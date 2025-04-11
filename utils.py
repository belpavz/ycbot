# utils.py
import base64
import hashlib
import hmac
import json
from config import Config
import requests
from datetime import datetime, timedelta
from models import db, OAuthToken, Salon


def get_oauth_url(client_id, redirect_uri, state=None):
    """Формирует URL для OAuth-авторизации"""
    base_url = "https://yclients.com/oauth/authorize"
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code"
    }
    if state:
        params["state"] = state

    query_string = "&".join(
        [f"{key}={value}" for key, value in params.items()])
    return f"{base_url}?{query_string}"


def exchange_code_for_token(client_id, client_secret, code, redirect_uri):
    """Обменивает код авторизации на токены доступа"""
    url = "https://yclients.com/oauth/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri
    }

    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def refresh_oauth_token(client_id, client_secret, refresh_token):
    """Обновляет токен доступа с помощью refresh_token"""
    url = "https://yclients.com/oauth/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    response = requests.post(url, data=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None


def save_oauth_token(salon_id, token_data):
    """Сохраняет или обновляет токены OAuth в базе данных"""
    salon = Salon.query.filter_by(salon_id=salon_id).first()
    if not salon:
        return False

    # Вычисляем время истечения токена
    expires_in = token_data.get('expires_in', 3600)  # По умолчанию 1 час
    expires_at = datetime.utcnow() + timedelta(seconds=expires_in)

    # Проверяем, есть ли уже токен для этого салона
    token = OAuthToken.query.filter_by(salon_id=salon.id).first()

    if token:
        # Обновляем существующий токен
        token.access_token = token_data['access_token']
        token.refresh_token = token_data['refresh_token']
        token.token_type = token_data.get('token_type', 'Bearer')
        token.expires_at = expires_at
        token.scope = token_data.get('scope', '')
        token.updated_at = datetime.utcnow()
    else:
        # Создаем новый токен
        token = OAuthToken(
            salon_id=salon.id,
            access_token=token_data['access_token'],
            refresh_token=token_data['refresh_token'],
            token_type=token_data.get('token_type', 'Bearer'),
            expires_at=expires_at,
            scope=token_data.get('scope', '')
        )
        db.session.add(token)

    db.session.commit()
    return True


def get_valid_oauth_token(salon_id, client_id, client_secret):
    """Получает действительный токен OAuth, при необходимости обновляя его"""
    salon = Salon.query.filter_by(salon_id=salon_id).first()
    if not salon:
        return None

    token = OAuthToken.query.filter_by(salon_id=salon.id).first()
    if not token:
        return None

    # Если токен истек, обновляем его
    if token.is_expired:
        token_data = refresh_oauth_token(
            client_id, client_secret, token.refresh_token)
        if token_data:
            save_oauth_token(salon_id, token_data)
            return token_data['access_token']
        else:
            return None

    return token.access_token


def decode_user_data(user_data_encoded, partner_token):
    """Декодирует user_data из base64."""
    try:
        user_data_bytes = base64.b64decode(user_data_encoded)
        user_data_str = user_data_bytes.decode('utf-8')
        return json.loads(user_data_str)
    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Ошибка декодирования user_data: {e}")
        return None


def verify_signature(user_data_encoded, user_data_sign, partner_token):
    """Проверяет подпись user_data."""
    try:
        user_data_bytes = base64.b64decode(user_data_encoded)
        user_data_str = user_data_bytes.decode('utf-8')
        expected_signature = hmac.new(
            partner_token.encode('utf-8'),
            user_data_str.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Добавляем логирование для отладки
        import logging
        logger = logging.getLogger('utils')
        logger.info(f"Expected signature: {expected_signature[:10]}...")
        logger.info(f"Received signature: {user_data_sign[:10]}...")

        return hmac.compare_digest(user_data_sign, expected_signature)
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        import logging
        logger = logging.getLogger('utils')
        logger.error(f"Ошибка проверки подписи: {e}")
        return False
