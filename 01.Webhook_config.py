import base64
import hashlib
import hmac
import os
import time
import requests


API_BASE_URL = "https://api.switch-bot.com/v1.1"

ACCESS_TOKEN: str = os.getenv('ACCESS_TOKEN')
SECRET: str = os.getenv('SECRET')


def __generate_request_headers() -> dict:
    """SWITCH BOT APIのリクエストヘッダーを生成する"""

    nonce = ""
    t = str(round(time.time() * 1000))
    string_to_sign = "{}{}{}".format(ACCESS_TOKEN, t, nonce)
    string_to_sign_b = bytes(string_to_sign, "utf-8")
    secret_b = bytes(SECRET, "utf-8")
    sign = base64.b64encode(
        hmac.new(secret_b, msg=string_to_sign_b, digestmod=hashlib.sha256).digest()
    )

    return {
        "Content-Type": "application/json",
        "Authorization": ACCESS_TOKEN,
        "t": t,
        "sign": sign,
        "nonce": nonce,
    }


def post_webhook(path: str, body: dict) -> str:
    url = f"{API_BASE_URL}/webhook/{path}"
    response = requests.post(url, headers=__generate_request_headers(), json=body)

    return response.json()


def setup_webhook(webhook_url: str):
    """
    Configure webhook
    Configure the url that all the webhook events will be sent to
    """
    body = {
        "action": "setupWebhook",
        "url": webhook_url,
        "deviceList": "ALL",
    }
    return post_webhook("setupWebhook", body)


def query_webhook():
    """
    Get webhook configuration
    Get the current configuration info of the webhook
    """
    body = {"action": "queryUrl"}

    return post_webhook("queryWebhook", body)


def delete_webhook(webhook_url: str):
    """
    Delete webhook
    Delete the configuration of the webhook
    """
    body = {"action": "deleteWebhook", "url": webhook_url}

    return post_webhook("deleteWebhook", body)


def lambda_handler(event, context):
    print(event)
    target = event['target']
    if not target == "query":
        url = event['url']

    if target == "setup":
        response = setup_webhook(url)
    elif target == "query":
        response = query_webhook()
    elif target == "delete":
        response = delete_webhook(url)
    
    print(response)
    return response
