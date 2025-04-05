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
from datetime import datetime, timedelta
from sqlalchemy.orm import relationship


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
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)  # Статус активности
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Интеграция с UserPhone
    telegram_id = db.Column(db.String(20), unique=True)

    # Отношения
    roles = db.relationship('UserRole', backref='user', lazy='dynamic')
    salons = db.relationship(
        'Salon', secondary='user_salon', backref='users', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.name} {self.email}>'

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


# Модель для хранении информации о салонах
class Salon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, unique=True,
                         nullable=False)  # ID салона в YClients
    name = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    integration_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Индекс для ускорения поиска по salon_id
    __table_args__ = (db.Index('idx_salon_id', 'salon_id'),)


# Таблица связи пользователей и салонов
user_salon = db.Table('user_salon',
                      db.Column('user_id', db.Integer, db.ForeignKey(
                          'user.id'), primary_key=True),
                      db.Column('salon_id', db.Integer, db.ForeignKey(
                          'salon.id'), primary_key=True),
                      db.Column('created_at', db.DateTime,
                                default=datetime.utcnow)
                      )


# Модель роли пользователя (администратор, клиент, сотрудник)
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # admin, client, staff, etc.
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))

    # Индекс для ускорения поиска по имени роли
    __table_args__ = (db.Index('idx_role_name', 'name'),)


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
    salon_id = db.Column(db.Integer, db.ForeignKey('salon.id'))
    data = db.Column(db.Text)  # JSON данные
    processed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)

    # Отношение к салону
    salon = db.relationship('Salon', backref='webhook_events')

    # Индексы для ускорения запросов
    __table_args__ = (
        db.Index('idx_webhook_salon', 'salon_id'),
        db.Index('idx_webhook_processed', 'processed'),
        db.Index('idx_webhook_type', 'event_type'),
    )


# Модель логирования действий пользователей в системе
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    # login, create_booking, etc.
    action = db.Column(db.String(100), nullable=False)
    entity_type = db.Column(db.String(50))  # user, salon, booking, etc.
    entity_id = db.Column(db.Integer)
    details = db.Column(db.Text)  # JSON с деталями действия
    ip_address = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Отношение к пользователю
    user = db.relationship('User', backref='activity_logs')

    # Индексы для ускорения запросов
    __table_args__ = (
        db.Index('idx_log_user', 'user_id'),
        db.Index('idx_log_entity', 'entity_type', 'entity_id'),
        db.Index('idx_log_created', 'created_at'),
    )


# Модель история изменения данных
class ChangeHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    entity_type = db.Column(db.String(50), nullable=False)  # user, salon, etc.
    entity_id = db.Column(db.Integer, nullable=False)
    field_name = db.Column(db.String(50), nullable=False)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Отношение к пользователю
    user = db.relationship('User', backref='changes')

    # Индексы для ускорения запросов
    __table_args__ = (
        db.Index('idx_history_entity', 'entity_type', 'entity_id'),
        db.Index('idx_history_user', 'user_id'),
        db.Index('idx_history_created', 'created_at'),
    )


# Кэширование данных
class CachedData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=False)  # JSON данные
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Индекс для ускорения поиска по ключу
    __table_args__ = (
        db.Index('idx_cache_key', 'key'),
        db.Index('idx_cache_expires', 'expires_at'),
    )


# Модель для хранения ролей пользователей
class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    salon_id = db.Column(db.Integer, db.ForeignKey('salon.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Определение отношений
    role = db.relationship('Role', backref='user_roles')
    salon = db.relationship('Salon', backref='user_roles')

    # Индексы для ускорения запросов
    __table_args__ = (
        db.Index('idx_user_salon_role', 'user_id', 'salon_id', 'role_id'),
        db.Index('idx_user_salon', 'user_id', 'salon_id'),
    )


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


# Настройка миграции под новый формат ЬД
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
                                phone=decoded_user_data.get('phone', ''),
                                is_active=True,
                                created_at=datetime.utcnow(),
                                updated_at=datetime.utcnow()
                            )
                            # Генерируем случайный пароль
                            temp_password = os.urandom(8).hex()
                            new_user.set_password(temp_password)
                            db.session.add(new_user)
                            db.session.commit()
                            user_id = new_user.id

                            # Логируем создание пользователя
                            log_activity(user_id, "user_created", "user", user_id,
                                         {"email": email, "name": new_user.name})
                        else:
                            user_id = user.id

                            # Проверяем, активен ли пользователь
                            if not user.is_active:
                                user.is_active = True
                                db.session.commit()

                                # Логируем активацию пользователя
                                log_activity(user_id, "user_activated", "user", user_id,
                                             {"email": email})

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
        salon_id = data.get('data', {}).get('company_id') or company_id

        # Получаем объект салона из базы данных
        salon = Salon.query.filter_by(salon_id=salon_id).first()
        if not salon:
            # Если салон не найден, создаем его
            salon = Salon(salon_id=salon_id, is_active=True)
            db.session.add(salon)
            db.session.commit()

        # Сохраняем событие в базу данных
        webhook_event = WebhookEvent(
            event_type='webhook',
            resource=resource,
            salon_id=salon.id,
            data=json.dumps(data)
        )
        db.session.add(webhook_event)
        db.session.commit()

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

        # Сохраняем событие в базу данных
        webhook_event = WebhookEvent(
            event_type='callback',
            resource=event,
            salon_id=salon.id,
            data=json.dumps(data)
        )
        db.session.add(webhook_event)
        db.session.commit()

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
    if request.method == 'POST':
        salon_id = request.form.get('salon_id')
        user_id = request.form.get('user_id')

        # Добавьте проверку на пустые значения
        if not salon_id or not user_id:
            app.logger.error(
                f"Пустые значения: salon_id={salon_id}, user_id={user_id}")
            return render_template('activate.html', error_message="Отсутствуют обязательные параметры")

        # Убедитесь, что значения являются целыми числами
        try:
            salon_id = int(salon_id)
            user_id = int(user_id)
        except ValueError:
            app.logger.error(
                f"Некорректные значения: salon_id={salon_id}, user_id={user_id}")
            return render_template('activate.html', error_message="Некорректные параметры")

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

        # Добавьте проверку на пустые значения
        if not salon_id or not user_id:
            app.logger.error(
                f"Пустые значения при GET-запросе: salon_id={salon_id}, user_id={user_id}")
            return render_template('activate.html', error_message="Отсутствуют обязательные параметры")

        return render_template('activate.html', salon_id=salon_id, user_id=user_id)


def activate_salon_integration(salon_id, user_id, api_key, application_id, webhook_urls, callback_url):
    """Активирует интеграцию для конкретного салона."""
    try:
        # Проверка типов данных
        if not salon_id or not user_id:
            app.logger.error(
                f"Пустые значения в activate_salon_integration: salon_id={salon_id}, user_id={user_id}")
            return False, "Отсутствуют обязательные параметры"

        # Убедитесь, что значения являются целыми числами
        salon_id = int(salon_id) if not isinstance(salon_id, int) else salon_id
        user_id = int(user_id) if not isinstance(user_id, int) else user_id

        # Получаем салон из базы данных или создаем новый
        salon = Salon.query.filter_by(salon_id=salon_id).first()
        if not salon:
            salon = Salon(salon_id=salon_id, is_active=True)
            db.session.add(salon)
            db.session.commit()

        # Логирование действия
        log_activity(user_id, "activate_integration", "salon", salon.id,
                     {"salon_id": salon_id, "application_id": application_id})

        # Проверяем наличие связи пользователя и салона
        user_role = UserRole.query.filter_by(
            user_id=user_id,
            salon_id=salon.id
        ).first()

        admin_role = Role.query.filter_by(name='admin').first()
        if not admin_role:
            admin_role = Role(name='admin', description='Администратор салона')
            db.session.add(admin_role)
            db.session.commit()

        if user_role:
            # Если связь уже существует, активируем ее
            if not user_role.is_active:
                user_role.is_active = True
                old_value = "неактивна"
                new_value = "активна"
                record_change(user_id, "user_role", user_role.id,
                              "is_active", old_value, new_value)
                db.session.commit()

            # Отправляем настройки интеграции
            success, message = yclients.send_integration_settings(
                salon_id, application_id, api_key, webhook_urls, callback_url)

            if success:
                app.logger.info(
                    f"Integration settings successfully sent for salon {salon_id}")
                # Активируем салон, если он был неактивен
                if not salon.is_active:
                    salon.is_active = True
                    salon.integration_active = True
                    db.session.commit()
                return True, "Интеграция успешно активирована."
            else:
                app.logger.error(
                    f"Error sending integration settings for salon {salon_id}: {message}")
                return False, f"Ошибка отправки настроек: {message}"

        # Если связи нет, создаем новую
        success, user_yclients_id, response = yclients.activate_integration(
            salon_id=salon_id,
            api_key=api_key,
            webhook_urls=webhook_urls,
            application_id=application_id,
            callback_url=callback_url
        )

        # Проверяем ответ на наличие сообщения о том, что приложение уже установлено
        if isinstance(response, dict) and response.get("meta", {}).get("message") == "Приложение уже установлено":
            app.logger.info(
                f"Application already installed for salon {salon_id}")

            # Создаем связь пользователя и салона с ролью администратора
            new_user_role = UserRole(
                user_id=user_id,
                salon_id=salon.id,
                role_id=admin_role.id,
                is_active=True
            )
            db.session.add(new_user_role)
            db.session.commit()

            # Обновляем настройки интеграции
            success, message = yclients.send_integration_settings(
                salon_id, application_id, api_key, webhook_urls, callback_url)

            salon.integration_active = True
            db.session.commit()

            return True, "Интеграция уже установлена и была активирована в системе."

        if success:
            app.logger.info(
                f"Integration successfully activated for salon {salon_id}, USER_ID: {user_yclients_id}")

            # Создаем связь пользователя и салона с ролью администратора
            new_user_role = UserRole(
                user_id=user_id,
                salon_id=salon.id,
                role_id=admin_role.id,
                is_active=True
            )
            db.session.add(new_user_role)

            # Активируем салон
            salon.is_active = True
            salon.integration_active = True
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
            # Обработка строки вместо словаря
            if isinstance(response, str):
                # Проверяем, содержит ли строка ответа информацию о том, что приложение уже установлено
                if "Пользователь уже установил это приложение" in response:
                    app.logger.info(
                        f"Application already installed for salon {salon_id} (from error message)")

                    # Создаем связь пользователя и салона с ролью администратора
                    new_user_role = UserRole(
                        user_id=user_id,
                        salon_id=salon.id,
                        role_id=admin_role.id,
                        is_active=True
                    )
                    db.session.add(new_user_role)

                    # Активируем салон
                    salon.is_active = True
                    salon.integration_active = True
                    db.session.commit()

                    return True, "Интеграция уже установлена и была активирована в системе."

                error_message = response  # Если response — строка (ошибка)
            else:
                error_message = response.get("meta", {}).get(
                    "message", "Неизвестная ошибка")

            app.logger.error(
                f"Error activating integration for salon {salon_id}: {error_message}")
            return False, error_message

    except Exception as e:
        app.logger.error(
            f"Exception during activation for salon {salon_id}: {str(e)}")
        # Добавляем логирование полного ответа при ошибке
        if hasattr(e, 'response') and e.response is not None:
            app.logger.error(f"Response content: {e.response.text}")
        return False, f"Исключение: {str(e)}"


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


# Запуск миграции данных при запуске приложения
# Инициализация приложения
if __name__ == '__main__':
    with app.app_context():
        # Создаем все таблицы, если их нет
        db.create_all()

        # Запускаем миграцию данных
        try:
            migrate_data()
            app.logger.info("Миграция данных выполнена успешно")
        except Exception as e:
            app.logger.error(f"Ошибка при миграции данных: {str(e)}")

    pass


# if __name__ == '__main__':
    # app.run(debug=True)  # Включите debug mode для разработки
    # app.run(debug=True, host="0.0.0.0", port=8000)
    # app.run(host="0.0.0.0", port=8000)
    # pass
