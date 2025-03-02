# app.py
from flask import Flask, request, render_template, redirect, url_for, session
import config
import utils
import yclients
from flask_sqlalchemy import SQLAlchemy
import os
import bcrypt  # Импортируем bcrypt

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']
db = SQLAlchemy(app)  # Инициализация SQLAlchemy

# Определение модели данных для связи с Yclients


class UsersYclients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    salon_id = db.Column(db.Integer)
    user_yclients_id = db.Column(db.Integer)

    def __repr__(self):
        return f'<UsersYclients {self.user_id} {self.salon_id} {self.user_yclients_id}>'

# Определение модели пользователя


class YourUserModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))  # Переименовали поле

    def __repr__(self):
        return f'<User {self.name} {self.email}>'

    def set_password(self, password):
        """Хеширует пароль и сохраняет хеш."""
        self.password_hash = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Проверяет, соответствует ли пароль хешу."""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


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
        password = request.form.get('password')
        email = request.form.get('email')
        name = request.form.get('name')
        phone = request.form.get('phone')

        # Ищем пользователя в базе данных по email
        user = YourUserModel.query.filter_by(email=email).first()
        if user:
            user_id = user.id
        else:
            # Создаем нового пользователя
            new_user = YourUserModel(name=name, email=email, phone=phone)
            new_user.set_password(password)  # Хешируем пароль
            db.session.add(new_user)
            db.session.commit()
            user_id = new_user.id

        # После успешной регистрации перенаправляем на страницу активации
        return redirect(url_for('activate', salon_id=salon_id, user_id=user_id))

    if user_data_encoded and user_data_sign:
        # Передача данных пользователя включена
        user_data = utils.decode_user_data(
            user_data_encoded, app.config['PARTNER_TOKEN'])
        if user_data and utils.verify_signature(user_data_encoded, user_data_sign, app.config['PARTNER_TOKEN']):
            # Подпись валидна, можно использовать данные
            return render_template('signup.html', salon_id=salon_id, user_data=user_data, salon_ids=salon_ids)
        else:
            # Ошибка подписи или декодирования
            return "Invalid signature or data!", 400
    else:
        # Данные пользователя не переданы, отображаем обычную форму
        return render_template('signup.html', salon_id=salon_id, user_data=None, salon_ids=salon_ids)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = YourUserModel.query.filter_by(email=email).first()
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
        user = YourUserModel.query.get(user_id)
        return render_template('profile.html', user=user)
    else:
        return redirect(url_for('login'))


@app.route('/activate', methods=['POST'])
def activate():
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


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


# ... остальной код ...
if __name__ == '__main__':
    # app.run(debug=True)  # Включите debug mode для разработки
    # app.run(debug=True, host="0.0.0.0", port=8000)
    pass
