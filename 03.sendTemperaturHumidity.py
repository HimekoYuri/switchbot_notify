import os
import json
import hashlib
import hmac
import base64
import uuid
import time
import requests

def lambda_handler(event, context):
    deviceId= os.getenv('DEVICE_ID')
    token = os.getenv('TOKEN')
    secret = os.getenv('SECRET')
    switchBotUrl = os.getenv('SWITCHBOT')

    nonce = str(uuid.uuid4())
    t = int(round(time.time() * 1000))
    string_to_sign = "{}{}{}".format(token, t, nonce)
    string_to_sign = bytes(string_to_sign, "utf-8")
    secret = bytes(secret, "utf-8")
    sign = base64.b64encode(hmac.new(secret, msg=string_to_sign, digestmod=hashlib.sha256).digest())

    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "charset": "utf-8",
        "t": str(t),
        "sign": str(sign, "utf-8"),
        "nonce": nonce
    }

    switchBotUrl = switchBotUrl + deviceId + '/status'

    response = requests.get(switchBotUrl, headers=headers)
    devices = response.json()
    print(devices['body'])

    sendDiscord(devices['body'])

    return

def sendDiscord(devices):
    url = os.getenv('DISCORD')
    userId = os.getenv('USER_ID')
    temperature = devices['temperature']
    humidity = devices['humidity']
    
    # Header
    headers ={
        "Content-Type": "application/json"
    }

    # 送信内容
    payload = {
        "content": f"<@{userId}> 気温：{temperature} ℃, 湿度：{humidity}%"
    }
    print(payload)
    # POSTリクエストを送信
    response = requests.post(url, json=payload, headers=headers)

    print(response)

    return 
