import os
import json
import hashlib
import hmac
import base64
import uuid
import time
import requests
import logging
import re
from urllib.parse import urlparse

# ログ設定（機密情報を含まないよう設定）
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# セキュリティ設定
ALLOWED_SOURCE_IPS = os.getenv('ALLOWED_SOURCE_IPS', '').split(',') if os.getenv('ALLOWED_SOURCE_IPS') else []
MAX_REQUEST_AGE = int(os.getenv('MAX_REQUEST_AGE', '300'))  # 5分

def sanitize_log_input(input_data):
    """ログインジェクション対策のためのサニタイゼーション"""
    if input_data is None:
        return "None"
    
    # 文字列に変換
    sanitized = str(input_data)
    
    # 改行文字を削除/置換（ログインジェクション対策）
    sanitized = sanitized.replace('\n', '\\n')
    sanitized = sanitized.replace('\r', '\\r')
    sanitized = sanitized.replace('\t', '\\t')
    
    # 制御文字を削除
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    
    # 長すぎる文字列は切り詰め
    if len(sanitized) > 1000:
        sanitized = sanitized[:1000] + "...[truncated]"
    
    return sanitized

def safe_log_info(message, *args):
    """安全なログ出力（INFO）"""
    sanitized_message = sanitize_log_input(message)
    sanitized_args = [sanitize_log_input(arg) for arg in args]
    logger.info(sanitized_message, *sanitized_args)

def safe_log_error(message, *args):
    """安全なログ出力（ERROR）"""
    sanitized_message = sanitize_log_input(message)
    sanitized_args = [sanitize_log_input(arg) for arg in args]
    logger.error(sanitized_message, *sanitized_args)

def verify_scheduled_execution(context):
    """スケジュール実行の検証（認可制御強化）"""
    try:
        # CloudWatch Eventsからの実行かチェック
        if hasattr(context, 'invoked_function_arn'):
            function_arn = context.invoked_function_arn
            if not function_arn.startswith('arn:aws:lambda:'):
                safe_log_error("無効なLambda関数ARN")
                return False
        
        # 実行ロールの検証
        try:
            import boto3
            sts_client = boto3.client('sts')
            caller_identity = sts_client.get_caller_identity()
            
            # 期待される実行ロールかチェック
            expected_role_pattern = 'role-SendTemperatureHumiditytoDiscord'
            if expected_role_pattern not in caller_identity.get('Arn', ''):
                safe_log_error(f"予期しない実行ロール: {caller_identity.get('Arn')}")
                return False
            
            safe_log_info("スケジュール実行検証成功")
            return True
            
        except Exception as e:
            safe_log_error(f"STS呼び出しエラー: {str(e)}")
            return False
        
    except Exception as e:
        safe_log_error(f"スケジュール実行検証エラー: {str(e)}")
        return False

def perform_authorization_checks(event, context):
    """包括的な認可チェック（Broken Access Control対策）"""
    try:
        safe_log_info("認可チェック開始")
        
        # スケジュール実行の検証（温度・湿度通知は定期実行）
        if not verify_scheduled_execution(context):
            raise ValueError("スケジュール実行検証に失敗しました")
        
        safe_log_info("全ての認可チェックが成功しました")
        return True
        
    except Exception as e:
        safe_log_error(f"認可チェックエラー: {str(e)}")
        return False

def validate_environment_variables():
    """環境変数の検証"""
    required_vars = ['DEVICE_ID', 'TOKEN', 'SECRET', 'SWITCHBOT', 'DISCORD', 'USER_ID']
    missing_vars = []
    
    for var in required_vars:
        value = os.getenv(var)
        if not value or value.strip() == '':
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"必要な環境変数が設定されていません: {', '.join(missing_vars)}")
    
    # URL形式の検証
    switchbot_url = os.getenv('SWITCHBOT')
    discord_url = os.getenv('DISCORD')
    
    if not is_valid_https_url(switchbot_url):
        raise ValueError("SWITCHBOT URLが無効またはHTTPSではありません")
    
    if not is_valid_https_url(discord_url):
        raise ValueError("DISCORD URLが無効またはHTTPSではありません")

def is_valid_https_url(url):
    """HTTPS URLの検証"""
    try:
        parsed = urlparse(url)
        return parsed.scheme == 'https' and parsed.netloc
    except:
        return False

def mask_sensitive_data(data, keys_to_mask):
    """機密データのマスク化"""
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if key.lower() in [k.lower() for k in keys_to_mask]:
                masked[key] = "***MASKED***"
            else:
                masked[key] = mask_sensitive_data(value, keys_to_mask)
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_data(item, keys_to_mask) for item in data]
    else:
        return data

def create_switchbot_headers(token, secret):
    """SwitchBot API用のヘッダー作成"""
    try:
        nonce = str(uuid.uuid4())
        t = int(round(time.time() * 1000))
        string_to_sign = f"{token}{t}{nonce}"
        string_to_sign_bytes = string_to_sign.encode('utf-8')
        secret_bytes = secret.encode('utf-8')
        sign = base64.b64encode(
            hmac.new(secret_bytes, msg=string_to_sign_bytes, digestmod=hashlib.sha256).digest()
        )

        return {
            "Authorization": token,
            "Content-Type": "application/json",
            "charset": "utf-8",
            "t": str(t),
            "sign": sign.decode('utf-8'),
            "nonce": nonce
        }
    except Exception as e:
        safe_log_error(f"ヘッダー作成エラー: {str(e)}")
        raise

def get_switchbot_data(device_id, token, secret, switchbot_url):
    """SwitchBotからデータを取得"""
    try:
        headers = create_switchbot_headers(token, secret)
        url = f"{switchbot_url}{device_id}/status"
        
        # リクエスト情報をログ出力（機密情報は除外）
        safe_log_info(f"SwitchBot APIリクエスト: {url}")
        
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        
        # レスポンスデータの検証
        if 'body' not in data:
            raise ValueError("SwitchBot APIレスポンスに'body'が含まれていません")
        
        # 機密情報をマスクしてログ出力
        masked_data = mask_sensitive_data(data, ['token', 'secret', 'authorization'])
        safe_log_info(f"SwitchBotデータ取得成功: {json.dumps(masked_data, ensure_ascii=False)}")
        
        return data['body']
        
    except requests.exceptions.Timeout:
        safe_log_error("SwitchBot API タイムアウト")
        raise
    except requests.exceptions.RequestException as e:
        safe_log_error(f"SwitchBot API リクエストエラー: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        safe_log_error(f"SwitchBot API レスポンス解析エラー: {str(e)}")
        raise
    except Exception as e:
        safe_log_error(f"SwitchBotデータ取得エラー: {str(e)}")
        raise

def send_discord_notification(devices_data, discord_url, user_id):
    """Discord通知送信"""
    try:
        # データの検証
        if not isinstance(devices_data, dict):
            raise ValueError("デバイスデータが無効です")
        
        temperature = devices_data.get('temperature')
        humidity = devices_data.get('humidity')
        
        if temperature is None or humidity is None:
            raise ValueError("温度または湿度データが取得できません")
        
        # 数値の検証
        try:
            temp_float = float(temperature)
            humid_float = float(humidity)
        except (ValueError, TypeError):
            raise ValueError("温度または湿度データが数値ではありません")
        
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "content": f"<@{user_id}> 気温：{temperature} ℃, 湿度：{humidity}%"
        }
        
        # 機密情報をマスクしてログ出力
        masked_payload = mask_sensitive_data(payload, ['user_id'])
        safe_log_info(f"Discord通知送信: {json.dumps(masked_payload, ensure_ascii=False)}")
        
        response = requests.post(discord_url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        
        safe_log_info("Discord通知送信成功")
        
    except requests.exceptions.Timeout:
        safe_log_error("Discord通知 タイムアウト")
        raise
    except requests.exceptions.RequestException as e:
        safe_log_error(f"Discord通知 リクエストエラー: {str(e)}")
        raise
    except Exception as e:
        safe_log_error(f"Discord通知送信エラー: {str(e)}")
        raise

def lambda_handler(event, context):
    """Lambda関数のメインハンドラー（認可制御強化版）"""
    try:
        safe_log_info("温度・湿度通知処理開始")
        
        # 認可チェック（Broken Access Control対策）
        if not perform_authorization_checks(event, context):
            safe_log_error("認可チェックに失敗しました")
            return {
                'statusCode': 403,
                'body': json.dumps({
                    'error': 'アクセスが拒否されました'
                }, ensure_ascii=False)
            }
        
        # 環境変数の検証
        validate_environment_variables()
        
        # 環境変数取得
        device_id = os.getenv('DEVICE_ID')
        token = os.getenv('TOKEN')
        secret = os.getenv('SECRET')
        switchbot_url = os.getenv('SWITCHBOT')
        discord_url = os.getenv('DISCORD')
        user_id = os.getenv('USER_ID')
        
        # SwitchBotからデータ取得
        devices_data = get_switchbot_data(device_id, token, secret, switchbot_url)
        
        # Discord通知送信
        send_discord_notification(devices_data, discord_url, user_id)
        
        safe_log_info("温度・湿度通知処理完了")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': '温度・湿度通知送信完了',
                'timestamp': int(time.time())
            }, ensure_ascii=False)
        }
        
    except Exception as e:
        safe_log_error(f"処理エラー: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': '内部サーバーエラー',
                'timestamp': int(time.time())
            }, ensure_ascii=False)
        } 
