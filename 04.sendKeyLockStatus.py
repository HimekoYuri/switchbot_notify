import json
import requests
import os
import boto3
import logging
import re
from urllib.parse import urlparse
from botocore.exceptions import ClientError, BotoCoreError

# ログ設定（機密情報を含まないよう設定）
logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

# 定数定義
DEVICE_TYPES = {
    "WoLockPro": "上の鍵",
    "WoLock": "下の鍵",
    "WoHub2": "スイッチハブ"
}

ALLOWED_DEVICE_TYPES = ["WoLockPro", "WoLock"]

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
    
    if "body" not in event:
        raise ValueError("イベントデータに'body'が含まれていません")
    
    try:
        body = json.loads(event["body"])
    except json.JSONDecodeError:
        raise ValueError("イベントボディのJSON解析に失敗しました")
    
    if not isinstance(body, dict):
        raise ValueError("イベントボディが無効です")
    
    if "context" not in body:
        raise ValueError("イベントボディに'context'が含まれていません")
    
    context_data = body["context"]
    if not isinstance(context_data, dict):
        raise ValueError("contextデータが無効です")
    
    # デバイスタイプの検証
    if "deviceType" not in context_data:
        raise ValueError("contextデータに'deviceType'が含まれていません")
    
    device_type = context_data["deviceType"]
    if not isinstance(device_type, str) or device_type not in DEVICE_TYPES:
        raise ValueError(f"無効なデバイスタイプです: {device_type}")
    
    # 処理対象デバイスの場合の追加検証
    if device_type in ALLOWED_DEVICE_TYPES:
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
    
    return body

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

def invoke_bottom_key_function(lambda_client, body):
    """下の鍵処理用Lambda関数の安全な呼び出し"""
    try:
        # 呼び出し先関数の存在確認
        target_function = 'sendKeyLockStatusBottom'
        
        try:
            lambda_client.get_function_configuration(FunctionName=target_function)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise ValueError(f"呼び出し先Lambda関数が見つかりません: {target_function}")
            else:
                raise
        
        # 安全なペイロード作成
        safe_payload = {
            "context": body["context"]
        }
        
        response = lambda_client.invoke(
            FunctionName=target_function,
            InvocationType='Event',
            Payload=json.dumps(safe_payload)
        )
        
        safe_log_info(f"下の鍵処理Lambda関数呼び出し成功: {target_function}")
        return response
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDeniedException':
            raise ValueError("Lambda関数の呼び出し権限がありません")
        elif error_code == 'InvalidParameterValueException':
            raise ValueError("Lambda関数呼び出しパラメータが無効です")
        else:
            raise ValueError(f"Lambda関数呼び出しエラー: {error_code}")
    except Exception as e:
        raise ValueError(f"Lambda関数呼び出しで予期しないエラー: {str(e)}")

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
    """Lambda関数のメインハンドラー（セキュリティ強化版）"""
    try:
        safe_log_info("鍵ロック状態通知処理開始")
        
        # 環境変数の検証
        validate_environment_variables()
        
        # イベントデータの検証
        body = validate_event_data(event)
        
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
        
        # デバイスタイプ取得
        device_type = body["context"]["deviceType"]
        
        safe_log_info(f"デバイスタイプ: {device_type}")
        
        # デバイスタイプ別処理
        if device_type == "WoLockPro":
            key_type = DEVICE_TYPES[device_type]
            
            # データ取得
            battery = body["context"]["battery"]
            lock_state = body["context"]["lockState"]
            
            # 状態変更チェック
            if current_key_state == lock_state:
                safe_log_info("状態が同じなので処理終了")
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
            
            safe_log_info("上の鍵ロック状態通知処理完了")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': '上の鍵状態通知送信完了',
                    'new_state': lock_state,
                    'battery': battery
                }, ensure_ascii=False)
            }
            
        elif device_type == "WoLock":
            # 下の鍵処理用Lambda関数を呼び出し
            invoke_bottom_key_function(lambda_client, body)
            
            safe_log_info("下の鍵処理Lambda関数呼び出し完了")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': '下の鍵処理Lambda関数呼び出し完了'
                }, ensure_ascii=False)
            }
            
        else:
            # 処理対象外のデバイス
            safe_log_info(f"処理対象外のデバイスタイプ: {device_type}")
            return {
                'statusCode': 204,
                'body': json.dumps({
                    'message': '処理対象外のデバイスタイプ',
                    'device_type': device_type
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
