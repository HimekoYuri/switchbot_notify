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

# 認可レベル定義
AUTHORIZATION_LEVELS = {
    'ADMIN': 100,
    'OPERATOR': 50,
    'VIEWER': 10,
    'GUEST': 0
}

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

class ServerSideSessionManager:
    """サーバーサイドセッション管理クラス"""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.session_table_name = os.getenv('SESSION_TABLE_NAME', 'lambda-sessions')
        self.session_timeout = int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1時間
        
    def get_session_table(self):
        """セッションテーブルの取得/作成"""
        try:
            table = self.dynamodb.Table(self.session_table_name)
            # テーブルの存在確認
            table.load()
            return table
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                safe_log_info(f"セッションテーブル {self.session_table_name} が存在しません。IAM権限ベースの認証を使用します。")
                return None
            else:
                safe_log_error(f"セッションテーブルアクセスエラー: {str(e)}")
                return None
    
    def get_session_data(self, session_id):
        """サーバーサイドセッションデータの取得"""
        try:
            if not session_id:
                return None
                
            table = self.get_session_table()
            if not table:
                return None
            
            response = table.get_item(
                Key={'session_id': session_id}
            )
            
            if 'Item' not in response:
                safe_log_error(f"セッションが見つかりません: {session_id}")
                return None
            
            session_data = response['Item']
            
            # セッションの有効期限チェック
            current_time = int(time.time())
            if session_data.get('expires_at', 0) < current_time:
                safe_log_error(f"セッションが期限切れです: {session_id}")
                self.delete_session(session_id)
                return None
            
            safe_log_info(f"有効なセッションデータを取得: {session_id}")
            return session_data
            
        except Exception as e:
            safe_log_error(f"セッションデータ取得エラー: {str(e)}")
            return None
    
    def delete_session(self, session_id):
        """期限切れセッションの削除"""
        try:
            table = self.get_session_table()
            if table:
                table.delete_item(Key={'session_id': session_id})
        except Exception as e:
            safe_log_error(f"セッション削除エラー: {str(e)}")

def get_user_role_from_iam(context):
    """IAMロールからユーザー権限を取得（サーバーサイド認証）"""
    try:
        sts_client = boto3.client('sts')
        caller_identity = sts_client.get_caller_identity()
        
        # IAMロールから権限レベルを判定
        arn = caller_identity.get('Arn', '')
        
        # ロール名から権限レベルを判定
        if 'AdministratorAccess' in arn or 'Admin' in arn:
            return 'ADMIN', AUTHORIZATION_LEVELS['ADMIN']
        elif 'SendKeyStatusToDiscord' in arn:
            return 'OPERATOR', AUTHORIZATION_LEVELS['OPERATOR']
        elif 'ReadOnly' in arn:
            return 'VIEWER', AUTHORIZATION_LEVELS['VIEWER']
        else:
            return 'GUEST', AUTHORIZATION_LEVELS['GUEST']
            
    except Exception as e:
        safe_log_error(f"IAMロール取得エラー: {str(e)}")
        return 'GUEST', AUTHORIZATION_LEVELS['GUEST']

def get_user_role_from_session(event):
    """サーバーサイドセッションからユーザー権限を取得"""
    try:
        session_manager = ServerSideSessionManager()
        
        # セッションIDの取得（複数の方法を試行）
        session_id = None
        
        # 1. ヘッダーから取得
        headers = event.get('headers', {})
        session_id = headers.get('X-Session-ID') or headers.get('Authorization', '').replace('Bearer ', '')
        
        # 2. リクエストコンテキストから取得
        if not session_id and 'requestContext' in event:
            session_id = event['requestContext'].get('authorizer', {}).get('session_id')
        
        if not session_id:
            safe_log_error("セッションIDが見つかりません")
            return None, 0
        
        # サーバーサイドセッションデータの取得
        session_data = session_manager.get_session_data(session_id)
        if not session_data:
            return None, 0
        
        # セッションからロール情報を取得
        user_role = session_data.get('role', 'GUEST')
        user_permissions = session_data.get('permissions', [])
        authorization_level = AUTHORIZATION_LEVELS.get(user_role, 0)
        
        safe_log_info(f"セッションから取得した権限: {user_role} (レベル: {authorization_level})")
        return user_role, authorization_level
        
    except Exception as e:
        safe_log_error(f"セッション権限取得エラー: {str(e)}")
        return None, 0

def check_required_authorization_level(action):
    """アクションに必要な認可レベルを取得"""
    action_requirements = {
        'send_notification': AUTHORIZATION_LEVELS['OPERATOR'],
        'update_environment': AUTHORIZATION_LEVELS['ADMIN'],
        'read_status': AUTHORIZATION_LEVELS['VIEWER'],
        'invoke_function': AUTHORIZATION_LEVELS['OPERATOR']
    }
    
    return action_requirements.get(action, AUTHORIZATION_LEVELS['ADMIN'])

def perform_server_side_authorization(event, context, required_action):
    """サーバーサイド認可チェック（��良版）"""
    try:
        safe_log_info(f"サーバーサイド認可チェック開始: {required_action}")
        
        # 必要な認可レベルを取得
        required_level = check_required_authorization_level(required_action)
        
        # 1. サーバーサイドセッションからの権限取得を試行
        session_role, session_level = get_user_role_from_session(event)
        
        if session_role and session_level >= required_level:
            safe_log_info(f"セッション認証成功: {session_role} (レベル: {session_level})")
            return True, session_role
        
        # 2. IAMロールベースの認証にフォールバック
        iam_role, iam_level = get_user_role_from_iam(context)
        
        if iam_level >= required_level:
            safe_log_info(f"IAM認証成功: {iam_role} (レベル: {iam_level})")
            return True, iam_role
        
        safe_log_error(f"認可レベル不足: 必要={required_level}, セッション={session_level}, IAM={iam_level}")
        return False, None
        
    except Exception as e:
        safe_log_error(f"サーバーサイド認可チェックエラー: {str(e)}")
        return False, None

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

def perform_authorization_checks(event, context):
    """包括的な認可チェック（サーバーサイドセッション対応版）"""
    try:
        safe_log_info("認可チェック開始")
        
        # 1. サーバーサイド認可チェック（メイン）
        is_authorized, user_role = perform_server_side_authorization(event, context, 'send_notification')
        if not is_authorized:
            raise ValueError("サーバーサイド認可チェックに失敗しました")
        
        # 2. 送信元IPアドレスの検証
        if not verify_source_ip(event):
            raise ValueError("送信元IP検証に失敗しました")
        
        # 3. リクエスト署名の検証（設定されている場合）
        webhook_secret = os.getenv('WEBHOOK_SECRET')
        if webhook_secret:
            if not verify_request_signature(event, webhook_secret):
                raise ValueError("リクエスト署名検証に失敗しました")
        
        safe_log_info(f"全ての認可チェックが成功しました (ユーザー権限: {user_role})")
        return True
        
    except Exception as e:
        safe_log_error(f"認可チェックエラー: {str(e)}")
        return False

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
    """Lambda関数のメインハンドラー（認可制御強化版）"""
    try:
        safe_log_info("鍵ロック状態通知処理開始")
        
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
