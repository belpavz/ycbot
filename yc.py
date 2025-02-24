# yclients.py
import requests
import json


def activate_integration(salon_id, api_key):
    """Активирует интеграцию для указанного salon_id и возвращает USER_ID."""
    url = f"https://api.yclients.com/api/v1/company/{salon_id}/integrations"  # Пример URL, уточните в документации YClients
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    #  В теле запроса больше не нужен user_id
    data = {}
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response.raise_for_status()
        response_json = response.json()
        if response_json.get("success"):
            # Получаем USER_ID из ответа
            user_id = response_json["data"]["user_id"]
            return True, user_id, response_json  # Возвращаем True, USER_ID и полный ответ
        else:
            return False, None, response_json  # Возвращаем False, None и полный ответ
    except requests.exceptions.RequestException as e:
        return False, None, str(e)


def send_integration_settings(salon_id, application_id, api_key, webhook_urls, channels=None):
    """Отправляет настройки интеграции в YCLIENTS."""
    url = "https://api.yclients.com/marketplace/partner/callback"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "salon_id": salon_id,
        "application_id": application_id,
        "api_key": api_key,
        "webhook_urls": webhook_urls
    }
    if channels:
        data["channels"] = channels

    try:
        response = requests.post(url, headers=headers, data=json.dumps(data))
        response.raise_for_status()
        return True, response.json()
    except requests.exceptions.RequestException as e:
        return False, str(e)
