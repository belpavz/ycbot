from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt

db = SQLAlchemy()


# Таблица для хранения OAuth-токенов
class OAuthToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    salon_id = db.Column(db.Integer, db.ForeignKey('salon.id'), nullable=False)
    access_token = db.Column(db.String(255), nullable=False)
    refresh_token = db.Column(db.String(255), nullable=False)
    token_type = db.Column(db.String(50), default='Bearer')
    expires_at = db.Column(db.DateTime, nullable=False)
    scope = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Отношение к салону
    salon = db.relationship('Salon', backref='oauth_tokens')

    @property
    def is_expired(self):
        """Проверяет, истек ли срок действия токена"""
        return datetime.utcnow() > self.expires_at


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
