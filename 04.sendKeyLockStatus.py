import json
import requests
import os
import boto3

def lambda_handler(event, context):
    topKey = "WoLockPro"
    bottomKey = "WoLock"
    switchhub = "WoHub2"
    url = os.getenv('URL')
    userId = os.getenv('USER_ID')
    body = json.loads(event["body"])
    
    deviceType = body["context"]["deviceType"]
    keyState = os.getenv('KEY_STATE')

    lambda_client = boto3.client('lambda')

    print(deviceType)

    if deviceType == topKey:
        keyType = "上の鍵"
    elif deviceType == bottomKey:
        keyType = "下の鍵"

        lambda_client.invoke(
            FunctionName = 'sendKeyLockStatusBottom',
            InvocationType='Event',
            Payload=json.dumps(body)
        )
        return
    else:
        return {
            'statusCode': 204
        }       
    
    # 電池残量と鍵の状態を取得。
    battery = body["context"]["battery"]
    lockState = body["context"]["lockState"]
   
    if keyState == lockState:
        print("状態が同じなので処理終了")
        return {
            'status': 204
        }

    # Header
    headers ={
        "Content-Type": "application/json"
    }

    # 送信内容
    payload = {
        "content": f"<@{userId}> {keyType}の状態：{lockState}, 電池残量：{battery}"
    }
    print(payload)
    # POSTリクエストを送信
    response = requests.post(url, json=payload, headers=headers)

    print(response)

    lambdaResponse = lambda_client.update_function_configuration(
        FunctionName=context.invoked_function_arn,
        Environment={
            'Variables': {
                'URL': url,
                'USER_ID': userId,
                'KEY_STATE': lockState
            }
        }
    )

    print(lambdaResponse)

    return {
        'statusCode': 200,
    }
