# utils.py
import base64
import hashlib
import hmac
import json
from config import Config


def decode_user_data(user_data_encoded, partner_token):
    """Декодирует user_data из base64 и проверяет подпись."""
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
        return hmac.compare_digest(user_data_sign, expected_signature)
    except (base64.binascii.Error, UnicodeDecodeError) as e:
        print(f"Ошибка проверки подписи: {e}")
        return False


def verify_yclients_signature(user_data, signature):
    """Проверка подписи данных пользователя от YClients"""
    # Получаем секретный ключ из конфигурации
    secret_key = Config.YCLIENTS_SECRET_KEY

    # Создаем HMAC-SHA256 подпись
    calculated_signature = hmac.new(
        secret_key.encode('utf-8'),
        user_data.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Сравниваем вычисленную подпись с полученной
    return hmac.compare_digest(calculated_signature, signature)


def decode_yclients_user_data(user_data):
    """Декодирование данных пользователя от YClients"""
    try:
        # Декодируем base64 и преобразуем в JSON
        decoded_data = base64.b64decode(user_data).decode('utf-8')
        return json.loads(decoded_data)
    except Exception as e:
        raise Exception(f"Ошибка декодирования данных пользователя: {e}")
