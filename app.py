# app.py
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import config
import utils
import yc as yclients
import json
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
import logging
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime


app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']
db = SQLAlchemy(app)
migrate = Migrate(app, db)
csrf = CSRFProtect()
csrf.init_app(app)


# Настройка логирования в файл для анализа
if not app.debug:
    file_handler = RotatingFileHandler('/home/belpav/ycbot/logs/webhook.log',
                                       maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Webhook service startup')


# Логирования для отслеживания вебхуков
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/ycbot.log',
                                       maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('YCBot startup')


# Определение модели данных для связи с Yclients
class UsersYclients(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    salon_id = db.Column(db.Integer)
    user_yclients_id = db.Column(db.Integer)
    is_active = db.Column(db.Boolean, default=True)

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


# Модель для хранения событий вебхуков
class WebhookEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # record, client, integration_disabled
    event_type = db.Column(db.String(50))
    resource = db.Column(db.String(50))
    salon_id = db.Column(db.Integer)
    data = db.Column(db.Text)  # JSON данные
    processed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<WebhookEvent {self.event_type} {self.salon_id}>'


# Модель для хранения ролей пользователей
class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    salon_id = db.Column(db.Integer)
    role = db.Column(db.String(20))  # 'admin', 'client', etc.

    def __repr__(self):
        return f'<UserRole {self.user_id} {self.salon_id} {self.role}>'


# Функция для сохранения событий вебхуков
def save_webhook_event(event_type, resource, salon_id, data):
    """Сохраняет событие вебхука в базу данных."""
    try:
        webhook_event = WebhookEvent(
            event_type=event_type,
            resource=resource,
            salon_id=salon_id,
            data=json.dumps(data)
        )
        db.session.add(webhook_event)
        db.session.commit()
        app.logger.info(
            f"Webhook event saved: ID={webhook_event.id}, Type={event_type}, Resource={resource}")
        return webhook_event.id
    except Exception as e:
        app.logger.error(f"Error saving webhook event: {str(e)}")
        db.session.rollback()
        return None


# функции для обработки различных типов вебхуков
def process_record_webhook(record_data):
    """Обрабатывает вебхук о записи."""
    record_id = record_data.get('id')
    salon_id = record_data.get('company_id')
    client_id = record_data.get('client', {}).get('id') if isinstance(
        record_data.get('client'), dict) else record_data.get('client')
    staff_id = record_data.get('staff_id')
    date_time = record_data.get('datetime')
    status = record_data.get('attendance')

    # Здесь можно добавить логику обработки записи
    # Например, отправка уведомления в Telegram
    app.logger.info(f"Record {record_id} processed. Status: {status}")


def process_client_webhook(client_data):
    """Обрабатывает вебхук о клиенте."""
    client_id = client_data.get('id')
    client_name = client_data.get('name')
    client_phone = client_data.get('phone')

    # Здесь можно добавить логику обработки клиента
    app.logger.info(f"Client {client_id} processed: {client_name}")


# Создание базы данных (если ее нет)
with app.app_context():
    db.create_all()


@app.route('/debug-params')
def debug_params():
    params = {key: value for key, value in request.args.items()}
    return jsonify(params)


@app.route('/signup', methods=['GET', 'POST'])
@csrf.exempt
def signup():
    app.logger.info(f"Получен запрос на /signup с параметрами: {request.args}")
    app.logger.info(f"Заголовки запроса: {request.headers}")

    salon_id = request.args.get('salon_id')
    user_data = request.args.get('user_data')
    user_data_sign = request.args.get('user_data_sign')
    salon_ids = request.args.getlist('salon_ids[]')

    # Обработка ситуации, когда salon_id отсутствует
    if not salon_id and not salon_ids:
        app.logger.error("Отсутствует идентификатор салона")
        return "Ошибка: отсутствует идентификатор салона", 400

    decoded_user_data = None

    # Проверка и декодирование данных пользователя
    if user_data and user_data_sign:
        app.logger.info(f"Получены данные пользователя: {user_data}")
        try:
            # Декодирование данных пользователя
            decoded_user_data = utils.decode_user_data(
                user_data, app.config['PARTNER_TOKEN'])
            app.logger.info(
                f"Декодированные данные пользователя: {decoded_user_data}")

            # Проверка подписи
            if utils.verify_signature(user_data, user_data_sign, app.config['PARTNER_TOKEN']):
                # Автоматическая регистрация пользователя
                if decoded_user_data:
                    email = decoded_user_data.get('email')
                    if email:
                        user = User.query.filter_by(email=email).first()
                        if not user:
                            # Создаем нового пользователя
                            new_user = User(
                                name=decoded_user_data.get('name', ''),
                                email=email,
                                phone=decoded_user_data.get('phone', '')
                            )
                            # Генерируем случайный пароль
                            temp_password = os.urandom(8).hex()
                            new_user.set_password(temp_password)
                            db.session.add(new_user)
                            db.session.commit()
                            user_id = new_user.id
                        else:
                            user_id = user.id

                        # Перенаправляем на активацию
                        return redirect(url_for('activate', salon_id=salon_id, user_id=user_id))
            else:
                app.logger.warning("Недействительная подпись данных")
                decoded_user_data = None
        except Exception as e:
            app.logger.error(
                f"Ошибка при обработке данных пользователя: {str(e)}")
            decoded_user_data = None

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

    # Отображаем форму регистрации с данными пользователя (если они есть)
    return render_template('signup.html',
                           salon_id=salon_id,
                           user_data=decoded_user_data,
                           salon_ids=salon_ids,
                           user_id=None)


@app.route('/')
def home():
    return "Ваше приложение работает!"  # или вернуть HTML-шаблон


@app.route('/webhook', methods=['POST'])
@csrf.exempt
def webhook():
    try:
        data = request.json
        app.logger.info(f"Webhook received: {data}")

        resource = data.get('resource')
        company_id = data.get('company_id')
        salon_id = data.get('data', {}).get('company_id')

        # Сохраняем событие в базу данных
        event_id = save_webhook_event(
            'webhook', resource, salon_id or company_id, data)

        if resource == 'record':
            app.logger.info(f"Processing record event: {data}")
            record_data = data.get('data', {})
            # Обработка события записи
            process_record_webhook(record_data)
        elif resource == 'client':
            app.logger.info(f"Processing client event: {data}")
            client_data = data.get('data', {})
            # Обработка события клиента
            process_client_webhook(client_data)
        else:
            app.logger.warning(f"Unknown resource type: {resource}")

        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error processing webhook: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/callback', methods=['POST'])
@csrf.exempt
def callback():
    try:
        data = request.json
        app.logger.info(f"Callback received: {data}")

        salon_id = data.get('salon_id')
        application_id = data.get('application_id')
        event = data.get('event')
        partner_token = data.get('partner_token')

        # Сохраняем событие в базу данных
        event_id = save_webhook_event('callback', event, salon_id, data)

        if event == 'integration_disabled' or event == 'uninstall':
            app.logger.info(
                f"Processing {event} event for salon_id: {salon_id}")
            # Деактивация записей вместо удаления
            entries = UsersYclients.query.filter_by(salon_id=salon_id).all()
            for entry in entries:
                entry.is_active = False
            db.session.commit()
            app.logger.info(
                f"Integration data deactivated for salon_id: {salon_id}")
        else:
            app.logger.warning(f"Unknown event type: {event}")

        return jsonify({"success": True})
    except Exception as e:
        app.logger.error(f"Error processing callback: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


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
        user_yclients = UsersYclients.query.filter_by(
            user_id=user_id, is_active=True).first()
        salon_id = user_yclients.salon_id if user_yclients else None
        form_id = "1"  # Получите реальный form_id из конфигурации или базы данных
        return render_template('profile.html', user=user, salon_id=salon_id, form_id=form_id)
    else:
        return redirect(url_for('login'))


@app.route('/activate', methods=['GET', 'POST'])
@csrf.exempt
def activate():
    if request.method == 'POST':
        salon_id = request.form.get('salon_id')
        user_id = request.form.get('user_id')

        api_key = app.config['PARTNER_TOKEN']
        application_id = app.config['APPLICATION_ID']

        base_url = request.host_url.rstrip('/')
        webhook_urls = [f"{base_url}/webhook"]
        callback_url = f"{base_url}/callback"

        app.logger.info(
            f"Configuring webhooks: {webhook_urls} and callback: {callback_url}")

        success, result_message = activate_salon_integration(
            salon_id=salon_id,
            user_id=user_id,
            api_key=api_key,
            application_id=application_id,
            webhook_urls=webhook_urls,
            callback_url=callback_url
        )

        if success:
            return render_template('activate.html', message="Интеграция успешно активирована.")
        else:
            return render_template('activate.html', error_message=result_message)
    else:
        salon_id = request.args.get('salon_id')
        user_id = request.args.get('user_id')
        return render_template('activate.html', salon_id=salon_id, user_id=user_id)


def activate_salon_integration(salon_id, user_id, api_key, application_id, webhook_urls, callback_url):
    """Активирует интеграцию для конкретного салона."""
    try:
        # Проверяем наличие записи в базе данных
        existing_entry = UsersYclients.query.filter_by(
            salon_id=salon_id,
            user_id=user_id
        ).first()

        if existing_entry:
            if existing_entry.is_active:
                app.logger.info(
                    f"Integration already active for salon {salon_id}, USER_ID: {user_id}")
                return True, "Интеграция уже активна."
            else:
                # Реактивируем запись
                app.logger.info(
                    f"Reactivating integration for salon {salon_id}, USER_ID: {user_id}")
                existing_entry.is_active = True
                db.session.commit()

                # Отправляем настройки интеграции
                success, message = yclients.send_integration_settings(
                    salon_id, application_id, api_key, webhook_urls, callback_url)
                if success:
                    app.logger.info(
                        f"Integration settings successfully sent for salon {salon_id}")
                    return True, "Интеграция успешно активирована."
                else:
                    app.logger.error(
                        f"Error sending integration settings for salon {salon_id}: {message}")
                    return False, f"Ошибка отправки настроек: {message}"

        # Если записи нет в базе данных
        success, user_yclients_id, response = yclients.activate_integration(
            salon_id, api_key, webhook_urls=webhook_urls)
        if success:
            app.logger.info(
                f"Integration successfully activated for salon {salon_id}, USER_ID: {user_yclients_id}")
            # Сохраняем данные в базе данных
            entry = UsersYclients(
                user_id=user_id,
                salon_id=salon_id,
                user_yclients_id=user_yclients_id,
                is_active=True
            )
            db.session.add(entry)
            db.session.commit()

            # Отправляем настройки интеграции
            success, message = yclients.send_integration_settings(
                salon_id, application_id, api_key, webhook_urls, callback_url)
            if success:
                app.logger.info(
                    f"Integration settings successfully sent for salon {salon_id}")
                return True, "Интеграция успешно активирована."
            else:
                app.logger.error(
                    f"Error sending integration settings for salon {salon_id}: {message}")
                return False, f"Ошибка отправки настроек: {message}"
        else:
            error_message = response.get("meta", {}).get(
                "message", "Неизвестная ошибка")
            app.logger.error(
                f"Error activating integration for salon {salon_id}: {error_message}")
            return False, error_message

    except Exception as e:
        app.logger.error(
            f"Exception during activation for salon {salon_id}: {str(e)}")
        return False, f"Исключение: {str(e)}"


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
    # app.run(debug=True)  # Включите debug mode для разработки
    # app.run(debug=True, host="0.0.0.0", port=8000)
    # app.run(host="0.0.0.0", port=8000)
    pass
