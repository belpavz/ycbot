# utils.py
import base64
import hashlib
import hmac
import json
from config import Config


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
