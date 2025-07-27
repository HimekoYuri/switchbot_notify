import json
import requests
import os
import boto3
import logging
import re
import hashlib
import hmac
import time
from urllib.parse import urlparse
from botocore.exceptions import ClientError, BotoCoreError

# ログ設定（機密情報を含まないよう設定）
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# セキュリティ設定
ALLOWED_SOURCE_IPS = os.getenv('ALLOWED_SOURCE_IPS', '').split(',') if os.getenv('ALLOWED_SOURCE_IPS') else []
MAX_REQUEST_AGE = int(os.getenv('MAX_REQUEST_AGE', '300'))  # 5分
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))  # 1分
MAX_REQUESTS_PER_WINDOW = int(os.getenv('MAX_REQUESTS_PER_WINDOW', '10'))

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

def verify_request_signature(event, secret_key):
    """リクエスト署名の検証（認可制御強化）"""
    try:
        # ヘッダーから署名情報を取得
        headers = event.get('headers', {})
        received_signature = headers.get('X-Signature')
        timestamp = headers.get('X-Timestamp')
        
        if not received_signature or not timestamp:
            safe_log_error("署名またはタイムスタンプが不足しています")
            return False
        
        # タイムスタンプの検証（リプレイ攻撃対策）
        current_time = int(time.time())
        request_time = int(timestamp)
        
        if abs(current_time - request_time) > MAX_REQUEST_AGE:
            safe_log_error(f"リクエストが古すぎます: {current_time - request_time}秒")
            return False
        
        # 署名の計算
        body = event.get('body', '')
        message = f"{timestamp}{body}"
        expected_signature = hmac.new(
            secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # 署名の比較（タイミング攻撃対策）
        if not hmac.compare_digest(received_signature, expected_signature):
            safe_log_error("署名が一致しません")
            return False
        
        safe_log_info("リクエスト署名検証成功")
        return True
        
    except Exception as e:
        safe_log_error(f"署名検証エラー: {str(e)}")
        return False

def verify_source_ip(event):
    """送信元IPアドレスの検証"""
    try:
        if not ALLOWED_SOURCE_IPS or ALLOWED_SOURCE_IPS == ['']:
            # IP制限が設定されていない場合はスキップ
            return True
        
        # Lambda関数の場合、送信元IPは複数の場所に格納される可能性がある
        source_ip = None
        
        # API Gatewayからの場合
        if 'requestContext' in event:
            source_ip = event['requestContext'].get('identity', {}).get('sourceIp')
        
        # ALBからの場合
        if not source_ip and 'headers' in event:
            source_ip = event['headers'].get('X-Forwarded-For', '').split(',')[0].strip()
        
        if not source_ip:
            safe_log_error("送信元IPアドレスが特定できません")
            return False
        
        if source_ip not in ALLOWED_SOURCE_IPS:
            safe_log_error(f"許可されていないIPアドレス: {source_ip}")
            return False
        
        safe_log_info(f"送信元IP検証成功: {source_ip}")
        return True
        
    except Exception as e:
        safe_log_error(f"IP検証エラー: {str(e)}")
        return False

def verify_iam_permissions(context):
    """IAM権限の検証（サーバーサイド認証）"""
    try:
        # Lambda実行ロールの検証
        if not hasattr(context, 'invoked_function_arn'):
            safe_log_error("Lambda実行コンテキストが無効です")
            return False
        
        # ARNから実行ロールを抽出して検証
        function_arn = context.invoked_function_arn
        if not function_arn.startswith('arn:aws:lambda:'):
            safe_log_error("無効なLambda関数ARN")
            return False
        
        # 実行ロールの詳細確認
        try:
            sts_client = boto3.client('sts')
            caller_identity = sts_client.get_caller_identity()
            
            # 実行ロールが期待されるものかチェック
            expected_role_pattern = 'role-SendKeyStatusToDiscord'
            if expected_role_pattern not in caller_identity.get('Arn', ''):
                safe_log_error(f"予期しない実行ロール: {caller_identity.get('Arn')}")
                return False
            
            safe_log_info("IAM権限検証成功")
            return True
            
        except Exception as e:
            safe_log_error(f"STS呼び出しエラー: {str(e)}")
            return False
        
    except Exception as e:
        safe_log_error(f"IAM権限検証エラー: {str(e)}")
        return False

def perform_authorization_checks(event, context):
    """包括的な認可チェック（Broken Access Control対策）"""
    try:
        safe_log_info("認可チェック開始")
        
        # 1. IAM権限の検証（サーバーサイド認証）
        if not verify_iam_permissions(context):
            raise ValueError("IAM権限検証に失敗しました")
        
        # 2. 送信元IPアドレスの検証
        if not verify_source_ip(event):
            raise ValueError("送信元IP検証に失敗しました")
        
        # 3. リクエスト署名の検証（設定されている場合）
        webhook_secret = os.getenv('WEBHOOK_SECRET')
        if webhook_secret:
            if not verify_request_signature(event, webhook_secret):
                raise ValueError("リクエスト署名検証に失敗しました")
        
        safe_log_info("全ての認可チェックが成功しました")
        return True
        
    except Exception as e:
        safe_log_error(f"認可チェックエラー: {str(e)}")
        return False

def validate_environment_variables():
    """環境変数の検証"""
    required_vars = ['URL', 'USER_ID']
    missing_vars = []
    
    for var in required_vars:
        value = os.getenv(var)
        if not value or value.strip() == '':
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"必要な環境変数が設定されていません: {', '.join(missing_vars)}")
    
    # Discord URL形式の検証
    discord_url = os.getenv('URL')
    if not is_valid_discord_webhook_url(discord_url):
        raise ValueError("Discord Webhook URLが無効です")

def is_valid_discord_webhook_url(url):
    """Discord Webhook URLの検証"""
    try:
        parsed = urlparse(url)
        return (parsed.scheme == 'https' and 
                'discord.com' in parsed.netloc and 
                '/api/webhooks/' in parsed.path)
    except:
        return False

def validate_event_data(event):
    """イベントデータの検証"""
    if not isinstance(event, dict):
        raise ValueError("イベントデータが無効です")
    
    if "context" not in event:
        raise ValueError("イベントデータに'context'が含まれていません")
    
    context_data = event["context"]
    if not isinstance(context_data, dict):
        raise ValueError("contextデータが無効です")
    
    required_fields = ["battery", "lockState"]
    for field in required_fields:
        if field not in context_data:
            raise ValueError(f"contextデータに'{field}'が含まれていません")
    
    # データ型の検証
    battery = context_data["battery"]
    lock_state = context_data["lockState"]
    
    if not isinstance(battery, (int, float)) or battery < 0 or battery > 100:
        raise ValueError("電池残量データが無効です（0-100の範囲で指定してください）")
    
    if not isinstance(lock_state, str) or lock_state.strip() == '':
        raise ValueError("鍵状態データが無効です")
    
    return context_data

def validate_lambda_context(context):
    """Lambda実行コンテキストの検証"""
    if not hasattr(context, 'invoked_function_arn'):
        raise ValueError("Lambda実行コンテキストが無効です")
    
    # ARNの基本的な形式チェック
    arn = context.invoked_function_arn
    if not arn or not arn.startswith('arn:aws:lambda:'):
        raise ValueError("Lambda関数ARNが無効です")
    
    return arn

def check_lambda_permissions(lambda_client, function_arn):
    """Lambda関数の権限チェック"""
    try:
        # 関数の存在確認と基本情報取得
        response = lambda_client.get_function_configuration(
            FunctionName=function_arn
        )
        
        # 実行ロールの確認
        if 'Role' not in response:
            raise ValueError("Lambda関数の実行ロールが設定されていません")
        
        safe_log_info("Lambda関数の権限チェック完了")
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            raise ValueError("指定されたLambda関数が見つかりません")
        elif error_code == 'AccessDeniedException':
            raise ValueError("Lambda関数へのアクセス権限がありません")
        else:
            raise ValueError(f"Lambda関数の権限チェックエラー: {error_code}")
    except Exception as e:
        raise ValueError(f"Lambda関数の権限チェックで予期しないエラー: {str(e)}")

def send_discord_notification(discord_url, user_id, key_type, lock_state, battery):
    """Discord通知送信（セキュリティ強化版）"""
    try:
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "content": f"<@{user_id}> {key_type}の状態：{lock_state}, 電池残量：{battery}"
        }
        
        safe_log_info(f"Discord通知送信: {key_type}の状態変更")
        
        response = requests.post(discord_url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        
        safe_log_info("Discord通知送信成功")
        return True
        
    except requests.exceptions.Timeout:
        safe_log_error("Discord通知 タイムアウト")
        raise
    except requests.exceptions.RequestException as e:
        safe_log_error(f"Discord通知 リクエストエラー: {str(e)}")
        raise
    except Exception as e:
        safe_log_error(f"Discord通知送信エラー: {str(e)}")
        raise

def update_function_environment(lambda_client, function_arn, new_key_state, discord_url, user_id):
    """Lambda関数環境変数の安全な更新"""
    try:
        # 現在の環境変数を取得
        current_config = lambda_client.get_function_configuration(
            FunctionName=function_arn
        )
        
        current_env = current_config.get('Environment', {}).get('Variables', {})
        
        # 新しい環境変数を設定（既存の値を保持）
        new_env = current_env.copy()
        new_env.update({
            'URL': discord_url,
            'USER_ID': user_id,
            'KEY_STATE': new_key_state
        })
        
        # 環境変数を更新
        response = lambda_client.update_function_configuration(
            FunctionName=function_arn,
            Environment={
                'Variables': new_env
            }
        )
        
        safe_log_info("Lambda関数環境変数更新成功")
        return response
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            raise ValueError("指定されたLambda関数が見つかりません")
        elif error_code == 'AccessDeniedException':
            raise ValueError("Lambda関数の環境変数更新権限がありません")
        elif error_code == 'InvalidParameterValueException':
            raise ValueError("環境変数の値が無効です")
        else:
            raise ValueError(f"環境変数更新エラー: {error_code}")
    except Exception as e:
        raise ValueError(f"環境変数更新で予期しないエラー: {str(e)}")

def lambda_handler(event, context):
    """Lambda関数のメインハンドラー（認可制御強化版）"""
    try:
        safe_log_info("下の鍵ロック状態通知処理開始")
        
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
        
        # イベントデータの検証（認可チェック後に実行）
        context_data = validate_event_data(event)
        
        # Lambda実行コンテキストの検証
        function_arn = validate_lambda_context(context)
        
        # 環境変数取得
        discord_url = os.getenv('URL')
        user_id = os.getenv('USER_ID')
        current_key_state = os.getenv('KEY_STATE', '')  # デフォルト値を設定
        
        # Lambda クライアント作成
        try:
            lambda_client = boto3.client('lambda')
        except Exception as e:
            safe_log_error(f"Lambda クライアント作成エラー: {str(e)}")
            raise ValueError("AWS Lambda サービスへの接続に失敗しました")
        
        # Lambda関数の権限チェック
        check_lambda_permissions(lambda_client, function_arn)
        
        # データ取得
        battery = context_data["battery"]
        lock_state = context_data["lockState"]
        key_type = "下の鍵"
        
        # 状態変更チェック
        if current_key_state == lock_state:
            safe_log_info(f"状態が同じなので処理終了: {lock_state}")
            return {
                'statusCode': 204,
                'body': json.dumps({
                    'message': '状態変更なし',
                    'current_state': lock_state
                }, ensure_ascii=False)
            }
        
        # Discord通知送信
        send_discord_notification(discord_url, user_id, key_type, lock_state, battery)
        
        # 環境変数更新
        update_function_environment(lambda_client, function_arn, lock_state, discord_url, user_id)
        
        safe_log_info("下の鍵ロック状態通知処理完了")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': '下の鍵状態通知送信完了',
                'new_state': lock_state,
                'battery': battery
            }, ensure_ascii=False)
        }
        
    except ValueError as e:
        safe_log_error(f"バリデーションエラー: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'リクエストデータが無効です'
            }, ensure_ascii=False)
        }
    except Exception as e:
        safe_log_error(f"処理エラー: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': '内部サーバーエラー'
            }, ensure_ascii=False)
        }
