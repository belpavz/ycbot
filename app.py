from flask import Flask, request, render_template, redirect, url_for, session, jsonify, flash
import config
import utils
import yc as yclients
import json
import bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_mail import Mail, Message
import subprocess
import logging
from logging.handlers import RotatingFileHandler
import os
import dkim
from datetime import datetime, timedelta
from models import db, User, Salon, Role, UserRole, UserPhone, WebhookEvent, ActivityLog, ChangeHistory, CachedData

app = Flask(__name__)
app.config.from_object('config.Config')
app.secret_key = app.config['SECRET_KEY']
mail = Mail(app)

# Инициализация базы данных с приложением
db.init_app(app)
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


def send_email_via_php(recipient, subject, body):
    """
    Отправляет email через PHP-скрипт с поддержкой DKIM
    """
    try:
        logging.info(f"Отправка email через PHP на адрес {recipient}")

        # Путь к PHP-скрипту
        php_script = '/home/belpav/ycbot/mail_app/send_email.php'

        # Запуск PHP-скрипта с параметрами, используя полный путь к PHP
        cmd = ['/usr/bin/php', php_script, recipient, subject, body]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60)

        # Проверка результата
        if result.returncode == 0:
            logging.info(
                f"PHP-скрипт успешно отправил email: {result.stdout.strip()}")
            return True
        else:
            php_output = result.stdout.strip()
            php_error = result.stderr.strip()
            logging.error(
                f"Ошибка при отправке email через PHP (returncode={result.returncode}). PHP stdout: '{php_output}'. PHP stderr: '{php_error}'")
        return False
    except subprocess.TimeoutExpired:
        logging.error(
            f"Превышено время ожидания при отправке email на {recipient}")
        return False
    except Exception as e:
        logging.error(f"Непредвиденная ошибка при отправке email: {str(e)}")
        return False


def send_credentials_email(recipient_email, password):
    """Отправляет данные для входа пользователю."""
    try:
        app.logger.info(f"Начинаем отправку email на {recipient_email}")
        app.logger.info(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
        app.logger.info(f"MAIL_PORT: {app.config['MAIL_PORT']}")
        app.logger.info(f"MAIL_USE_SSL: {app.config['MAIL_USE_SSL']}")
        app.logger.info(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
        app.logger.info(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")

        subject = "Данные для входа в YCBot"
        login_url = url_for('login', _external=True)
        body = f"""
        <html>
        <body>
        <p>Приветствуем!</p>
        
        <p>Вы успешно активировали интеграцию YCBot.</p>
        <p>Данные для входа в ваш личный кабинет:</p>
        
        <p>Сайт: <a href="{login_url}">{login_url}</a><br>
        Логин: {recipient_email}<br>
        Пароль: {password}</p>
        
        <p>С уважением,<br>
        Команда YCBot</p>
        </body>
        </html>
        """

        # Вызов функции отправки через PHP
        result = send_email_via_php(recipient_email, subject, body)

        if result:
            app.logger.info(
                f"Учетные данные успешно отправлены на {recipient_email}")
            return True
        else:
            app.logger.error(
                f"Не удалось отправить учетные данные на {recipient_email}")
            return False
    except Exception as e:
        app.logger.error(
            f"Ошибка отправки email на {recipient_email}: {str(e)}")
        return False


# Функции для работы с базой данных
def log_activity(user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
    """Логирует действие пользователя в системе."""
    log = ActivityLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=json.dumps(details) if details else None,
        ip_address=ip_address
    )
    db.session.add(log)
    db.session.commit()
    return log


def record_change(user_id, entity_type, entity_id, field_name, old_value, new_value):
    """Записывает изменение поля в истории."""
    change = ChangeHistory(
        user_id=user_id,
        entity_type=entity_type,
        entity_id=entity_id,
        field_name=field_name,
        old_value=str(old_value) if old_value is not None else None,
        new_value=str(new_value) if new_value is not None else None
    )
    db.session.add(change)
    db.session.commit()
    return change


def cache_set(key, value, expires_in=3600):
    """Сохраняет данные в кэш."""
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    cache_item = CachedData.query.filter_by(key=key).first()

    if cache_item:
        cache_item.value = json.dumps(value)
        cache_item.expires_at = expires_at
        cache_item.updated_at = datetime.utcnow()
    else:
        cache_item = CachedData(
            key=key,
            value=json.dumps(value),
            expires_at=expires_at
        )
        db.session.add(cache_item)

    db.session.commit()
    return True


def cache_get(key):
    """Получает данные из кэша."""
    cache_item = CachedData.query.filter_by(key=key).first()

    if not cache_item:
        return None

    if cache_item.expires_at and cache_item.expires_at < datetime.utcnow():
        db.session.delete(cache_item)
        db.session.commit()
        return None

    try:
        return json.loads(cache_item.value)
    except:
        return None


# Получение всех активных салонов пользователя с ролями
def get_user_salons_with_roles(user_id):
    """Получает все активные салоны пользователя с ролями."""
    query = db.session.query(
        Salon, Role.name.label('role_name')
    ).join(
        UserRole, UserRole.salon_id == Salon.id
    ).join(
        Role, Role.id == UserRole.role_id
    ).filter(
        UserRole.user_id == user_id,
        UserRole.is_active == True,
        Salon.is_active == True
    ).all()

    result = {}
    for salon, role_name in query:
        if salon.id not in result:
            result[salon.id] = {
                'id': salon.id,
                'salon_id': salon.salon_id,
                'name': salon.name,
                'roles': []
            }
        result[salon.id]['roles'].append(role_name)

    return list(result.values())


# Получение всех пользователей салона с ролями
def get_salon_users_with_roles(salon_id):
    """Получает всех активных пользователей салона с ролями."""
    query = db.session.query(
        User, Role.name.label('role_name')
    ).join(
        UserRole, UserRole.user_id == User.id
    ).join(
        Role, Role.id == UserRole.role_id
    ).join(
        Salon, Salon.id == UserRole.salon_id
    ).filter(
        Salon.salon_id == salon_id,
        UserRole.is_active == True,
        User.is_active == True
    ).all()

    result = {}
    for user, role_name in query:
        if user.id not in result:
            result[user.id] = {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'phone': user.phone,
                'roles': []
            }
        result[user.id]['roles'].append(role_name)

    return list(result.values())


def check_user_permission(user_id, salon_id, required_role):
    """Проверяет, имеет ли пользователь указанную роль в салоне."""
    role = Role.query.filter_by(name=required_role).first()
    if not role:
        return False

    user_role = UserRole.query.filter_by(
        user_id=user_id,
        salon_id=salon_id,
        role_id=role.id,
        is_active=True
    ).first()

    return user_role is not None


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


# Настройка миграции под новый формат БД
def migrate_data():
    """Мигрирует данные из старой структуры в новую."""
    # 1. Создание ролей
    roles = {
        'admin': 'Администратор салона',
        'client': 'Клиент салона',
        'staff': 'Сотрудник салона'
    }

    for role_name, description in roles.items():
        if not Role.query.filter_by(name=role_name).first():
            role = Role(name=role_name, description=description)
            db.session.add(role)

    db.session.commit()

    # 2. Миграция салонов
    from models import UsersYclients  # Импортируем старую модель
    old_salons = db.session.query(db.distinct(UsersYclients.salon_id)).all()
    for (old_salon_id,) in old_salons:
        if not Salon.query.filter_by(salon_id=old_salon_id).first():
            salon = Salon(salon_id=old_salon_id)
            db.session.add(salon)

    db.session.commit()

    # 3. Миграция связей пользователей и салонов
    old_relations = UsersYclients.query.all()
    admin_role = Role.query.filter_by(name='admin').first()

    for relation in old_relations:
        user = User.query.get(relation.user_id)
        salon = Salon.query.filter_by(salon_id=relation.salon_id).first()

        if user and salon:
            # Проверяем, есть ли уже такая связь
            existing_role = UserRole.query.filter_by(
                user_id=user.id,
                salon_id=salon.id,
                role_id=admin_role.id
            ).first()

            if not existing_role:
                user_role = UserRole(
                    user_id=user.id,
                    salon_id=salon.id,
                    role_id=admin_role.id,
                    is_active=relation.is_active
                )
                db.session.add(user_role)

    db.session.commit()

    # 4. Миграция телефонов пользователей Telegram
    old_phones = UserPhone.query.all()
    for phone in old_phones:
        user = User.query.filter_by(telegram_id=phone.telegram_id).first()
        if not user:
            # Создаем нового пользователя
            user = User(
                telegram_id=phone.telegram_id,
                phone=phone.phone,
                name=f"Telegram User {phone.telegram_id}",
                email=f"telegram_{phone.telegram_id}@example.com"
            )
            db.session.add(user)

    db.session.commit()

    print("Миграция данных завершена успешно!")


# Создание базы данных (если ее нет)
with app.app_context():
    db.create_all()


@app.route('/debug-params')
def debug_params():
    params = {key: value for key, value in request.args.items()}
    return jsonify(params)
    pass


@app.route('/signup', methods=['GET', 'POST'])
@csrf.exempt
def signup():
    app.logger.info(f"Получен запрос на /signup с параметрами: {request.args}")
    app.logger.info(f"Заголовки запроса: {request.headers}")

    salon_id = request.args.get('salon_id')
    user_data = request.args.get('user_data')
    user_data_sign = request.args.get('user_data_sign')
    salon_ids = request.args.getlist('salon_ids[]')
    user_email_for_activation = None

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
                        user_email_for_activation = email
                        user = User.query.filter_by(email=email).first()
                        temp_password = None
                        if not user:
                            # Создаем нового пользователя
                            temp_password = os.urandom(8).hex()
                            new_user = User(
                                name=decoded_user_data.get('name', ''),
                                email=email,
                                phone=decoded_user_data.get('phone', ''),
                                is_active=True,
                                created_at=datetime.utcnow(),
                                updated_at=datetime.utcnow()
                            )
                            new_user.set_password(temp_password)
                            db.session.add(new_user)
                            db.session.commit()
                            user_id = new_user.id

                            # Логируем создание пользователя
                            log_activity(user_id, "user_created", "user", user_id,
                                         {"email": email, "name": new_user.name})
                            send_credentials_email(email, temp_password)
                        else:
                            user_id = user.id
                            # Проверяем, активен ли пользователь
                            if not user.is_active:
                                user.is_active = True
                                db.session.commit()
                                log_activity(user_id, "user_activated", "user", user_id,
                                             {"email": email})

                        # Перенаправляем на активацию
                        app.logger.info(
                            f"Перенаправление на activate с salon_id={salon_id}, user_id={user_id}, email={user_email_for_activation}")
                        return redirect(url_for('activate', salon_id=salon_id, user_id=user_id, email=user_email_for_activation))
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
                # Проверяем, активен ли пользователь
                if not user.is_active:
                    user.is_active = True
                    db.session.commit()
                    # Логируем активацию пользователя
                    log_activity(user_id, "user_activated", "user", user_id,
                                 {"email": email})
            else:
                # Создаем нового пользователя
                new_user = User(
                    name=name,
                    email=email,
                    phone=phone,
                    is_active=True,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )

                new_user.set_password(password)  # Хешируем пароль
                db.session.add(new_user)
                db.session.commit()
                user_id = new_user.id

                # Логируем создание пользователя
                log_activity(user_id, "user_created", "user", user_id,
                             {"email": email, "name": name})

            # После успешной регистрации перенаправляем на страницу активации
            app.logger.info(
                f"POST: Перенаправление на activate с salon_id={salon_id}, user_id={user_id}")
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
    pass


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
        salon_id = data.get('data', {}).get('company_id') or company_id

        # Получаем объект салона из базы данных
        salon = Salon.query.filter_by(salon_id=salon_id).first()
        if not salon:
            # Если салон не найден, создаем его
            salon = Salon(salon_id=salon_id, is_active=True)
            db.session.add(salon)
            db.session.commit()

        # Используем функцию для сохранения события
        webhook_id = save_webhook_event('webhook', resource, salon.id, data)

        if not webhook_id:
            app.logger.error("Failed to save webhook event")
            return jsonify({"success": False, "error": "Failed to save webhook event"}), 500

        # Кэшируем часто используемые данные
        if resource == 'staff' or resource == 'service':
            cache_key = f"{resource}_{salon_id}"
            cache_set(cache_key, data.get('data', {}),
                      3600)  # Кэшируем на 1 час

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

        # Получаем объект салона из базы данных
        salon = Salon.query.filter_by(salon_id=salon_id).first()
        if not salon:
            # Если салон не найден, создаем его
            salon = Salon(salon_id=salon_id, is_active=True)
            db.session.add(salon)
            db.session.commit()

        # Используем функцию для сохранения события
        webhook_id = save_webhook_event('callback', event, salon.id, data)

        if not webhook_id:
            app.logger.error("Failed to save callback event")
            return jsonify({"success": False, "error": "Failed to save callback event"}), 500

        if event == 'integration_disabled' or event == 'uninstall':
            app.logger.info(
                f"Processing {event} event for salon_id: {salon_id}")
            # Деактивируем салон
            salon.integration_active = False
            db.session.commit()
            # Логируем действие
            log_activity(None, f"integration_{event}", "salon", salon.id,
                         {"salon_id": salon_id, "application_id": application_id})
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
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        session.pop('user_id', None)
        return redirect(url_for('login'))

    # Проверяем, активен ли пользователь
    if not user.is_active:
        session.pop('user_id', None)
        return render_template('login.html', error="Ваш аккаунт деактивирован. Пожалуйста, свяжитесь с администратором.")

    # Получаем все активные салоны пользователя с ролями
    user_salons = get_user_salons_with_roles(user_id)

    # Получаем данные для Telegram-бота
    form_id = "1"  # Получите реальный form_id из конфигурации или базы данных

    return render_template('profile.html',
                           user=user,
                           salons=user_salons,
                           form_id=form_id)


@app.route('/activate', methods=['GET', 'POST'])
@csrf.exempt
def activate():
    app.logger.info(f"Вызвана функция activate с методом {request.method}")
    app.logger.info(f"Параметры запроса: {request.args}")
    app.logger.info(f"Заголовки запроса: {request.headers}")

    email_from_signup = request.args.get('email') or request.form.get('email')
    app.logger.info(f"Email из параметров: {email_from_signup}")

    if request.method == 'POST':
        app.logger.info("Обработка POST запроса")
        salon_id = request.form.get('salon_id')
        user_id = request.form.get('user_id')
        app.logger.info(f"POST данные: salon_id={salon_id}, user_id={user_id}")

        # Добавьте проверку на пустые значения
        if not salon_id or not user_id:
            app.logger.error(
                f"Пустые значения: salon_id={salon_id}, user_id={user_id}")
            return render_template('activate.html', error_message="Отсутствует информация о салоне или администраторе салона")

        # Убедитесь, что значения являются целыми числами
        try:
            salon_id = int(salon_id)
            user_id = int(user_id)
            app.logger.info(
                f"Преобразованные значения: salon_id={salon_id}, user_id={user_id}")
        except ValueError as e:
            app.logger.error(
                f"Некорректные значения: salon_id={salon_id}, user_id={user_id}, ошибка: {str(e)}")
            return render_template('activate.html', error_message="Некорректные параметры")

        if not email_from_signup:
            app.logger.error(
                "Отсутствует email пользователя при активации (POST)")
            # Пытаемся получить email из БД, если user_id есть
            user = User.query.get(user_id)
            if user:
                email_from_signup = user.email
                app.logger.info(f"Получен email из БД: {email_from_signup}")
            else:
                app.logger.error(f"Пользователь с ID={user_id} не найден в БД")
                return render_template('activate.html', error_message="Ошибка: Email пользователя не найден.")

        api_key = app.config['PARTNER_TOKEN']
        application_id = app.config['APPLICATION_ID']
        base_url = request.host_url.rstrip('/')
        webhook_urls = [f"{base_url}/webhook"]
        callback_url = f"{base_url}/callback"

        app.logger.info(
            f"Конфигурация для активации: api_key={api_key[:5]}..., application_id={application_id}")
        app.logger.info(
            f"Настройка вебхуков: {webhook_urls} и callback: {callback_url}")

        try:
            app.logger.info(
                f"Вызов функции activate_salon_integration с параметрами: salon_id={salon_id}, user_id={user_id}, email={email_from_signup}")
            status, message, result_user_id = activate_salon_integration(
                salon_id=salon_id,
                user_id=user_id,
                email=email_from_signup,  # Передаем email
                api_key=api_key,
                application_id=application_id,
                webhook_urls=webhook_urls,
                callback_url=callback_url
            )
            app.logger.info(
                f"Результат activate_salon_integration: status={status}, message={message}, result_user_id={result_user_id}")
        except Exception as e:
            app.logger.error(
                f"Исключение при вызове activate_salon_integration: {str(e)}", exc_info=True)
            return render_template('activate.html', error_message=f"Внутренняя ошибка сервера: {str(e)}", salon_id=salon_id, user_id=user_id, email=email_from_signup)

        if status == 'error':
            app.logger.error(f"Ошибка активации: {message}")
            return render_template('activate.html', error_message=message, salon_id=salon_id, user_id=user_id, email=email_from_signup)
        elif status == 'newly_activated':
            app.logger.info(f"Успешная новая активация: {message}")
            # В message уже отформатированное сообщение с email
            return render_template('activate.html', success_message=message, show_profile_button=True, user_id=result_user_id)
        elif status == 'already_active':
            app.logger.info(f"Интеграция уже была активна: {message}")
            return render_template('activate.html', already_active_message=message, show_profile_button=True, user_id=result_user_id)
        else:
            app.logger.warning(f"Неизвестный статус активации: {status}")
            return render_template('activate.html', error_message="Неизвестный статус активации", salon_id=salon_id, user_id=user_id, email=email_from_signup)
    else:
        app.logger.info("Обработка GET запроса")
        salon_id = request.args.get('salon_id')
        user_id = request.args.get('user_id')
        app.logger.info(
            f"GET параметры: salon_id={salon_id}, user_id={user_id}")

        # Добавьте проверку на пустые значения
        if not salon_id or not user_id:
            app.logger.error(
                f"Пустые значения при GET-запросе: salon_id={salon_id}, user_id={user_id}")
            return render_template('activate.html', error_message="Отсутствуют обязательные параметры")

        if not email_from_signup:
            app.logger.warning(
                "Отсутствует email пользователя при активации (GET)")
            # Пытаемся получить email из БД
            try:
                user = User.query.get(int(user_id))
                if user:
                    email_from_signup = user.email
                    app.logger.info(
                        f"Получен email из БД для GET запроса: {email_from_signup}")
            except Exception as e:
                app.logger.error(f"Ошибка при получении email из БД: {str(e)}")

        app.logger.info(
            f"GET: Отображение страницы активации с salon_id={salon_id}, user_id={user_id}, email={email_from_signup}")
        return render_template('activate.html', salon_id=salon_id, user_id=user_id, email=email_from_signup)


def activate_salon_integration(salon_id, user_id, email, api_key, application_id, webhook_urls, callback_url):
    """ Активирует интеграцию салона с YClients, связывает пользователя с салоном
    и возвращает статус операции. """
    try:
        # 1. Найти или создать салон в нашей БД по YClients salon_id
        salon = Salon.query.filter_by(salon_id=salon_id).first()
        if not salon:
            # Если салон не найден, создаем новую запись
            salon = Salon(salon_id=salon_id, is_active=False,
                          integration_active=False)
            db.session.add(salon)
            # Commit нужен здесь, чтобы получить salon.id для дальнейшего использования
            db.session.commit()
            app.logger.info(
                f"Создан новый салон в БД с ID={salon.id} для YClients salon_id={salon_id}")
        else:
            app.logger.info(
                f"Найден существующий салон в БД с ID={salon.id} для YClients salon_id={salon_id}")

        # 2. Получить роль 'admin'
        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            app.logger.error(
                "Критическая ошибка конфигурации: Роль 'admin' не найдена в базе данных!")
            # Возвращаем ошибку, так как это проблема настройки сервера.
            return 'error', "Ошибка конфигурации сервера: Роль 'admin' отсутствует.", None

        # 3. Проверить, была ли интеграция уже активна для этого салона
        if salon.integration_active:
            app.logger.info(
                f"Интеграция для салона {salon_id} (ID: {salon.id}) уже была активна.")

            # Проверяем/создаем/активируем связь пользователя с ролью администратора для этого салона
            user_role = UserRole.query.filter_by(
                user_id=user_id, salon_id=salon.id, role_id=admin_role.id).first()

            if not user_role:
                # Если связи не было (например, другой админ активировал ранее), создаем ее
                new_user_role = UserRole(
                    user_id=user_id,
                    salon_id=salon.id,
                    role_id=admin_role.id,
                    is_active=True
                )
                db.session.add(new_user_role)
                log_activity(user_id, "added_admin_role_on_reactivation", "salon", salon.id,
                             {"salon_id": salon_id})
                app.logger.info(
                    f"Добавлена роль 'admin' пользователю {user_id} для уже активного салона {salon.id}")
            elif not user_role.is_active:
                # Если связь была, но неактивна, активируем
                user_role.is_active = True
                log_activity(user_id, "reactivated_admin_role", "salon", salon.id,
                             {"salon_id": salon_id})
                app.logger.info(
                    f"Реактивирована роль 'admin' пользователю {user_id} для салона {salon.id}")

            db.session.commit()  # Сохраняем изменения UserRole, если они были

            # Можно на всякий случай переотправить настройки в YClients
            try:
                yclients.send_integration_settings(
                    salon_id, application_id, api_key, webhook_urls, callback_url
                )
                app.logger.info(
                    f"Настройки интеграции переотправлены для уже активного салона {salon_id}")
            except Exception as settings_err:
                app.logger.warning(
                    f"Не удалось переотправить настройки для уже активного салона {salon_id}: {settings_err}")

            return 'already_active', "Интеграция уже была активирована ранее для этого салона.", user_id

        # --- 4. Логика НОВОЙ активации (если salon.integration_active был False) ---
        app.logger.info(
            f"Начало процесса НОВОЙ активации интеграции для салона {salon_id} (ID: {salon.id}) пользователем {user_id}")
        log_activity(user_id, "start_new_activation", "salon", salon.id,
                     {"salon_id": salon_id, "application_id": application_id})

        # 5. Вызов API YClients для активации интеграции
        success, user_yclients_id_or_msg, response = yclients.activate_integration(
            salon_id=salon_id,
            api_key=api_key,
            webhook_urls=webhook_urls,
            application_id=application_id,
            callback_url=callback_url
        )

        # Обработка ответа, если YClients говорит, что приложение уже установлено
        is_already_installed = False
        # Убрана лишняя проверка на dict и str, так как activate_integration теперь возвращает стандартизированный ответ
        if success and response and isinstance(response, dict) and response.get("meta", {}).get("message") == "Приложение уже установлено":
            is_already_installed = True
            app.logger.info(
                f"YClients API сообщил, что приложение уже было установлено для салона {salon_id}")
            # Считаем это успехом, так как наша цель - активная интеграция

        # 6. Обработка результата вызова API YClients
        if success:
            app.logger.info(
                f"API YClients успешно активировал интеграцию (или она уже была активна) для салона {salon_id}")

            # Создаем или активируем связь UserRole
            user_role = UserRole.query.filter_by(
                user_id=user_id,
                salon_id=salon.id,
                role_id=admin_role.id
            ).first()

            if not user_role:
                user_role = UserRole(
                    user_id=user_id,
                    salon_id=salon.id,
                    role_id=admin_role.id,
                    is_active=True
                )
                db.session.add(user_role)
                log_activity(user_id, "created_admin_role_on_activation", "salon", salon.id,
                             {"salon_id": salon_id})
                app.logger.info(
                    f"Создана связь UserRole 'admin' для пользователя {user_id} и салона {salon.id}")
            elif not user_role.is_active:
                user_role.is_active = True
                log_activity(user_id, "reactivated_admin_role_on_activation", "salon", salon.id,
                             {"salon_id": salon_id})
                app.logger.info(
                    f"Реактивирована связь UserRole 'admin' для пользователя {user_id} и салона {salon.id}")

            # Обновляем статус салона в нашей БД
            salon.is_active = True          # Сам салон теперь активен в нашей системе
            salon.integration_active = True  # Интеграция с YClients активна
            db.session.commit()
            app.logger.info(
                f"Статус салона ID={salon.id} обновлен: is_active=True, integration_active=True")

            # 7. Отправляем настройки (вебхуки) в YClients ПОСЛЕ успешной активации и коммита
            app.logger.info(
                f"Отправка настроек интеграции в YClients для салона {salon_id}")
            settings_success, settings_message = yclients.send_integration_settings(
                salon_id, application_id, api_key, webhook_urls, callback_url
            )

            if settings_success:
                app.logger.info(
                    f"Настройки интеграции успешно отправлены для салона {salon_id}")
                # Интеграция полностью успешно активирована
                return 'newly_activated', f"Интеграция успешно активирована. Данные для входа отправлены на ваш почтовый адрес: {email}", user_id
            else:
                app.logger.error(
                    f"Ошибка отправки настроек интеграции для салона {salon_id}: {settings_message}")
                return 'error', f"Интеграция активирована, но произошла ошибка отправки настроек: {settings_message}", user_id
        else:
            # Ошибка при вызове API YClients activate_integration
            # (success был False)
            # Теперь activate_integration возвращает сообщение об ошибке здесь
            error_message = user_yclients_id_or_msg
            app.logger.error(
                f"Ошибка API YClients при активации интеграции для салона {salon_id}: {error_message}")
            # Откатывать ли создание салона, если он был новым? Нет, пусть остается неактивным.
            # Возвращаем ошибку
            return 'error', f"Ошибка активации интеграции в YClients: {error_message}", user_id

    except Exception as e:
        # Откат транзакции БД при любом неожиданном исключении
        db.session.rollback()
        app.logger.error(
            f"Неожиданное исключение при активации для салона {salon_id}: {str(e)}", exc_info=True)
        # Возвращаем общую ошибку сервера
        return 'error', f"Внутренняя ошибка сервера при активации: {str(e)}", None


@app.route('/get_bot_link', methods=['POST'])
def get_bot_link():
    company_id = request.form.get('company_id')
    form_id = request.form.get('form_id')
    user_id = session.get('user_id')

    if not company_id or not form_id:
        return jsonify({"success": False, "error": "Missing required parameters"}), 400

    # Проверяем, имеет ли пользователь доступ к этому салону
    if not check_user_permission(user_id, company_id, "admin") and not check_user_permission(user_id, company_id, "client"):
        return jsonify({"success": False, "error": "Нет доступа к этому салону"}), 403

    # Формируем параметр для deep linking
    start_param = f"{company_id}-{form_id}"

    # Формируем ссылку на бота
    bot_username = "yclient_bbot"  # имя бота
    bot_link = f"https://t.me/{bot_username}?start={start_param}"

    # Логируем действие
    log_activity(user_id, "get_bot_link", "salon", company_id,
                 {"company_id": company_id, "form_id": form_id})

    return jsonify({"success": True, "bot_link": bot_link})


@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        # Логируем выход пользователя
        log_activity(user_id, "logout", "user", user_id)

    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/manage_roles', methods=['GET', 'POST'])
def manage_roles():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    is_admin = False
    admin_salons = []

    user_roles = UserRole.query.filter_by(
        user_id=user_id, is_active=True).all()
    for user_role in user_roles:
        role = Role.query.get(user_role.role_id)
        if role and role.name == 'admin':
            is_admin = True
            admin_salons.append(user_role.salon_id)

    if not is_admin:
        return redirect(url_for('profile'))

    if request.method == 'POST':
        action = request.form.get('action')
        target_user_id = request.form.get('target_user_id')
        salon_id = request.form.get('salon_id')
        role_id = request.form.get('role_id')

        # Проверяем, имеет ли пользователь права администратора для этого салона
        if int(salon_id) not in admin_salons:
            return jsonify({"success": False, "error": "Нет прав администратора для этого салона"}), 403

        if action == 'add':
            # Добавление роли
            new_role = UserRole(
                user_id=target_user_id,
                salon_id=salon_id,
                role_id=role_id,
                is_active=True
            )
            db.session.add(new_role)
            db.session.commit()

            # Логируем действие
            role = Role.query.get(role_id)
            role_name = role.name if role else "unknown"
            log_activity(user_id, "add_role", "user", target_user_id,
                         {"salon_id": salon_id, "role": role_name})

            return jsonify({"success": True})

        elif action == 'remove':
            # Удаление роли
            user_role = UserRole.query.filter_by(
                user_id=target_user_id,
                salon_id=salon_id,
                role_id=role_id,
                is_active=True
            ).first()

            if user_role:
                user_role.is_active = False
                db.session.commit()

                # Логируем действие
                role = Role.query.get(role_id)
                role_name = role.name if role else "unknown"
                log_activity(user_id, "remove_role", "user", target_user_id,
                             {"salon_id": salon_id, "role": role_name})

                return jsonify({"success": True})
            else:
                return jsonify({"success": False, "error": "Роль не найдена"}), 404

    # Получаем список салонов, где пользователь является администратором
    salons = []
    for salon_id in admin_salons:
        salon = Salon.query.get(salon_id)
        if salon and salon.is_active:
            salons.append(salon)

    # Получаем список ролей
    roles = Role.query.all()

    return render_template('manage_roles.html',
                           salons=salons,
                           roles=roles)


@app.route('/activity_logs')
def activity_logs():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Проверяем, является ли пользователь администратором
    is_admin = False
    admin_salons = []

    user_roles = UserRole.query.filter_by(
        user_id=user_id, is_active=True).all()
    for user_role in user_roles:
        role = Role.query.get(user_role.role_id)
        if role and role.name == 'admin':
            is_admin = True
            admin_salons.append(user_role.salon_id)

    if not is_admin:
        return redirect(url_for('profile'))

    # Получаем параметры фильтрации
    entity_type = request.args.get('entity_type')
    entity_id = request.args.get('entity_id')
    action = request.args.get('action')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    # Формируем запрос с учетом фильтров
    query = ActivityLog.query

    if entity_type:
        query = query.filter(ActivityLog.entity_type == entity_type)

    if entity_id:
        query = query.filter(ActivityLog.entity_id == entity_id)

    if action:
        query = query.filter(ActivityLog.action == action)

    if date_from:
        date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
        query = query.filter(ActivityLog.created_at >= date_from_obj)

    if date_to:
        date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
        query = query.filter(ActivityLog.created_at <= date_to_obj)

    # Получаем логи с пагинацией
    page = request.args.get('page', 1, type=int)
    per_page = 20
    logs_pagination = query.order_by(
        ActivityLog.created_at.desc()).paginate(page=page, per_page=per_page)

    return render_template('activity_logs.html',
                           logs_pagination=logs_pagination,
                           entity_type=entity_type,
                           entity_id=entity_id,
                           action=action,
                           date_from=date_from,
                           date_to=date_to)


@app.route('/auto_login/<int:user_id>')
def auto_login(user_id):
    user = User.query.get(user_id)
    if user and user.is_active:
        session['user_id'] = user.id
        log_activity(user_id, "auto_login_success", "user", user_id)
        # Опциональное сообщение
        flash("Вы успешно вошли в систему.", "success")
        return redirect(url_for('profile'))
    else:
        log_activity(user_id, "auto_login_failed", "user", user_id, {
                     "reason": "User not found or inactive"})
        flash("Не удалось выполнить автоматический вход.", "error")
        # Перенаправить на обычную страницу входа
        return redirect(url_for('login'))


@app.route('/db-test')
def db_test():
    try:
        result = db.session.execute('SELECT 1').scalar()
        return f"Database connection test: {result}"
    except Exception as e:
        return f"Database connection error: {str(e)}"


@app.route('/config-test')
def config_test():
    return f"PARTNER_TOKEN exists: {'PARTNER_TOKEN' in app.config}"


@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.error(f"Unhandled exception: {str(e)}")
    return "Internal Server Error", 500


# Запуск миграции данных при запуске приложения
# Инициализация приложения
# if __name__ == '__main__':
#    with app.app_context():
    # Создаем все таблицы, если их нет
    # db.create_all()

    # Запускаем миграцию данных
    # try:
    #    migrate_data()
    #    app.logger.info("Миграция данных выполнена успешно")
    # except Exception as e:
    #    app.logger.error(f"Ошибка при миграции данных: {str(e)}")
#    pass


if __name__ == '__main__':
    # app.run(debug=True)  # Включите debug mode для разработки
    # app.run(debug=True, host="0.0.0.0", port=8000)
    # app.run(host="0.0.0.0", port=8000)
    pass
