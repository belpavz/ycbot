# app.py
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import config
import utils
import yclients
from flask_sqlalchemy import SQLAlchemy
import os
import bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
migrate = Migrate(app, db)


# Определение модели данных для связи с Yclients
class UsersYclients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    salon_id = db.Column(db.Integer)
    user_yclients_id = db.Column(db.Integer)

    def __repr__(self):
        return f'<UsersYclients {self.user_id} {self.salon_id} {self.user_yclients_id}>'


# Определение модели пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return f'<User {self.name} {self.email}>'

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


# Модель для хранения телефонов пользователей Telegram
class UserPhone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_id = db.Column(db.String(20), unique=True)
    phone = db.Column(db.String(20))

    def __repr__(self):
        return f'<UserPhone {self.telegram_id} {self.phone}>'


# Создание базы данных (если ее нет)
with app.app_context():
    db.create_all()


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    salon_id = request.args.get('salon_id')
    user_data_encoded = request.args.get('user_data')
    user_data_sign = request.args.get('user_data_sign')
    salon_ids = request.args.getlist('salon_ids[]')

    if request.method == 'POST':
        try:
            password = request.form.get('password')
            email = request.form.get('email')
            name = request.form.get('name')
            phone = request.form.get('phone')

        # Ищем пользователя в базе данных по email
            user = User.query.filter_by(email=email).first()
            if user:
                user_id = user.id
            else:
                # Создаем нового пользователя
                new_user = User(name=name, email=email, phone=phone)
                new_user.set_password(password)  # Хешируем пароль
                db.session.add(new_user)
                db.session.commit()
                user_id = new_user.id

        # После успешной регистрации перенаправляем на страницу активации
            return redirect(url_for('activate', salon_id=salon_id, user_id=user_id))
        except Exception as e:
            app.logger.error(f"Ошибка при регистрации: {e}")
            return "Произошла ошибка при обработке формы. Пожалуйста, попробуйте снова.", 500

    if user_data_encoded and user_data_sign:
        # Передача данных пользователя включена
        user_data = utils.decode_user_data(
            user_data_encoded, app.config['PARTNER_TOKEN'])
        if user_data and utils.verify_signature(user_data_encoded, user_data_sign, app.config['PARTNER_TOKEN']):
            # Подпись валидна, можно использовать данные
            return render_template('signup.html', salon_id=salon_id, user_data=user_data, salon_ids=salon_ids, user_id=None)
        else:
            # Ошибка подписи или декодирования
            return "Invalid signature or data!", 400
    else:
        # Данные пользователя не переданы, отображаем обычную форму
        return render_template('signup.html', salon_id=salon_id, user_data=None, salon_ids=salon_ids, )


@app.route('/')
def home():
    return "Ваше приложение работает!"  # или вернуть HTML-шаблон


@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    # Обработка различных типов событий
    resource = data.get('resource')

    if resource == 'record':
        # Обработка события записи
        pass
    elif resource == 'client':
        # Обработка события клиента
        pass

    return jsonify({"success": True})


@app.route('/callback', methods=['POST'])
def callback():
    data = request.json
    salon_id = data.get('salon_id')
    application_id = data.get('application_id')
    event = data.get('event')

    if event == 'integration_disabled':
        # Обработка отключения интеграции
        pass

    return jsonify({"success": True})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Аутентификация успешна
            session['user_id'] = user.id  # Сохраняем ID пользователя в сессии
            # Перенаправляем на страницу профиля
            return redirect(url_for('profile'))
        else:
            # Неверный email или пароль
            return render_template('login.html', error="Неверный email или пароль")

    return render_template('login.html')


@app.route('/profile')
def profile():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        # Получаем salon_id и form_id из базы данных
        user_yclients = UsersYclients.query.filter_by(user_id=user_id).first()
        salon_id = user_yclients.salon_id if user_yclients else None
        form_id = "1"  # Получите реальный form_id из конфигурации или базы данных
        return render_template('profile.html', user=user, salon_id=salon_id, form_id=form_id)
    else:
        return redirect(url_for('login'))


@app.route('/activate', methods=['GET', 'POST'])
def activate():
    if request.method == 'POST':
        salon_id = request.form.get('salon_id')
        salon_ids = request.form.getlist('salon_ids[]')
        user_id = request.form.get('user_id')

        api_key = app.config['API_KEY']
        # Получаем application_id из конфига
        application_id = app.config['APPLICATION_ID']
        # Получаем webhook_url из конфига
        webhook_urls = [app.config['WEBHOOK_URL']]
        # channels = ["sms", "whatsapp"]  # Укажите каналы, если необходимо

        if salon_ids:
            for salon_id_item in salon_ids:
                success, user_yclients_id, response = yclients.activate_integration(
                    salon_id_item, api_key)
                if success:
                    print(
                        f"Интеграция успешно активирована для филиала {salon_id_item}, USER_ID: {user_yclients_id}")
                    # Сохраняем данные в базе данных
                    entry = UsersYclients(
                        user_id=user_id, salon_id=salon_id_item, user_yclients_id=user_yclients_id)
                    db.session.add(entry)
                    db.session.commit()

                    # Отправляем настройки интеграции
                    success, message = yclients.send_integration_settings(
                        salon_id_item, application_id, api_key, webhook_urls)
                    if success:
                        print(
                            f"Настройки интеграции успешно отправлены для филиала {salon_id_item}")
                    else:
                        print(
                            f"Ошибка отправки настроек интеграции для филиала {salon_id_item}: {message}")

                else:
                    print(
                        f"Ошибка активации для филиала {salon_id_item}: {response}")
                    # TODO: Обработать ошибку
        else:
            success, user_yclients_id, response = yclients.activate_integration(
                salon_id, api_key)
            if success:
                print(
                    f"Интеграция успешно активирована, USER_ID: {user_yclients_id}")
                # Сохраняем данные в базе данных
                entry = UsersYclients(
                    user_id=user_id, salon_id=salon_id, user_yclients_id=user_yclients_id)
                db.session.add(entry)
                db.session.commit()

                # Отправляем настройки интеграции
                success, message = yclients.send_integration_settings(
                    salon_id, application_id, api_key, webhook_urls)
                if success:
                    print(
                        f"Настройки интеграции успешно отправлены для филиала {salon_id}")
                else:
                    print(
                        f"Ошибка отправки настроек интеграции для филиала {salon_id}: {message}")

            else:
                print(f"Ошибка активации: {response}")
                # TODO: Обработать ошибку

        return "Интеграция активирована! (проверьте логи)", 200
    else:  # GET запрос
        salon_id = request.args.get('salon_id')
        user_id = request.args.get('user_id')
        return render_template('activate.html', salon_id=salon_id, user_id=user_id)


@app.route('/get_bot_link', methods=['POST'])
def get_bot_link():
    company_id = request.form.get('company_id')
    form_id = request.form.get('form_id')

    if not company_id or not form_id:
        return jsonify({"success": False, "error": "Missing required parameters"}), 400

    # Формируем параметр для deep linking
    start_param = f"{company_id}-{form_id}"

    # Формируем ссылку на бота
    bot_username = "yclient_bbot"  # имя бота
    bot_link = f"https://t.me/{bot_username}?start={start_param}"

    return jsonify({"success": True, "bot_link": bot_link})


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)  # Включите debug mode для разработки
    # app.run(debug=True, host="0.0.0.0", port=8000)
    app.run(host="0.0.0.0", port=8000)
    pass
