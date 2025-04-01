# yclients.py
import requests
import json


def activate_integration(salon_id, api_key, webhook_urls, application_id, callback_url=None):
    """Активирует интеграцию для указанного salon_id."""
    url = "https://api.yclients.com/marketplace/partner/callback/"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.yclients.v2+json"
    }
    data = {
        "salon_id": salon_id,
        "application_id": application_id,
        "webhook_urls": webhook_urls
    }

    # Добавляем callback_url в запрос, если он передан
    if callback_url:
        data["callback_url"] = callback_url

    try:
        response = requests.post(url, headers=headers, json=data)
        response_json = response.json()

        # Проверяем на ошибку "Пользователь уже установил это приложение"
        if not response_json.get("success") and response_json.get("meta", {}).get("message") == "Пользователь уже установил это приложение.":
            return True, None, {"success": True, "meta": {"message": "Приложение уже установлено"}}

        response.raise_for_status()
        if response_json.get("success"):
            user_id = response_json["data"].get("user_id")
            return True, user_id, response_json
        else:
            return False, None, response_json
    except requests.exceptions.RequestException as e:
        # Добавляем логирование полного ответа при ошибке
        error_message = str(e)
        if hasattr(e, 'response') and e.response is not None:
            try:
                error_message += f" | Response: {e.response.text}"
            except:
                pass
        return False, None, error_message


def send_integration_settings(salon_id, application_id, api_key, webhook_urls, callback_url=None):
    url = "https://api.yclients.com/marketplace/partner/callback/"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.yclients.v2+json"  # Добавляем заголовок Accept
    }
    data = {
        "salon_id": salon_id,
        "application_id": application_id,
        "webhook_urls": webhook_urls,
    }
    if callback_url:
        data["callback_url"] = callback_url

    print(f"Sending integration settings: {data}")  # Для отладки
    try:
        response = requests.post(url, headers=headers, json=data)
        response_json = response.json()
        print(f"Response: {response_json}")  # Для отладки

        # Проверяем на ошибку "Пользователь уже установил это приложение"
        if not response_json.get("success") and response_json.get("meta", {}).get("message") == "Пользователь уже установил это приложение.":
            return True, "Приложение уже установлено"

        response.raise_for_status()
        return True, response_json
    except requests.exceptions.RequestException as e:
        error_message = f"Error sending integration settings: {e}"
        if hasattr(e, 'response') and e.response is not None:
            error_message += f" | Response: {e.response.text}"
        return False, error_message
