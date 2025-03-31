# yclients.py
import requests
import json


def activate_integration(salon_id, api_key, webhook_urls):
    """Активирует интеграцию для указанного salon_id."""
    url = f"https://api.yclients.com/marketplace/partner/callback/"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    data = {
        "salon_id": salon_id,
        "webhook_urls": webhook_urls
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        response_json = response.json()
        if response_json.get("success"):
            user_id = response_json["data"].get("user_id")
            return True, user_id, response_json
        else:
            return False, None, response_json
    except requests.exceptions.RequestException as e:
        return False, None, str(e)


def send_integration_settings(salon_id, application_id, api_key, webhook_urls, callback_url=None):
    url = "https://api.yclients.com/marketplace/partner/callback/"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    data = {
        "salon_id": salon_id,
        "application_id": application_id,
        "webhook_urls": webhook_urls,
    }
    if callback_url:
        data["callback_url"] = callback_url

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        return True, response.json()
    except requests.exceptions.RequestException as e:
        error_message = f"Error sending integration settings: {e}"
        if e.response:
            error_message += f" | Response: {e.response.text}"
        return False, error_message
