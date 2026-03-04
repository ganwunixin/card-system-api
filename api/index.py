from flask import Flask, request, jsonify
import json
import hashlib
import os
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
import urllib.request
import urllib.error
import ssl

app = Flask(__name__)

API_SECRET = os.environ.get("API_SECRET", "your-secret-key-change-me")

TURSO_URL = "libsql://card-system-ganwunixin.aws-ap-south-1.turso.io"
TURSO_TOKEN = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3NzI2NTA5MTgsImlkIjoiMDE5Y2JhMzYtNjUwMS03NTY5LTgwODMtZGEwOTliYTQwZmJlIiwicmlkIjoiYWFhMjNmOWQtYjIyZS00Yzg0LTlkNTgtZDI4YzAxZTMxMmNlIn0.2o64nupMcudyS6GP2iJ3wjyrdWabkEsZQSfhF1UTGYHGAxFvud_g5UtFBHzZ9IqeXffziCR3rrvnIEj5Laa3BQ"

CARD_TYPES = {
    "1H": {"name": "1小时卡", "duration": timedelta(hours=1)},
    "1D": {"name": "天卡", "duration": timedelta(days=1)},
    "1M": {"name": "月卡", "duration": timedelta(days=30)},
    "3M": {"name": "季卡", "duration": timedelta(days=90)},
    "1Y": {"name": "年卡", "duration": timedelta(days=365)},
    "F0": {"name": "永久卡", "permanent": True}
}

PERMANENT_CARD_EXPIRE = "2099-12-31 23:59:59"

def execute_sql(sql: str, params: list = None):
    """执行SQL语句"""
    url = TURSO_URL.replace('libsql://', 'https://')
    headers = {
        'Authorization': f'Bearer {TURSO_TOKEN}',
        'Content-Type': 'application/json'
    }
    
    statements = []
    if params:
        statements.append({'q': sql, 'params': params})
    else:
        statements.append({'q': sql})
    
    data = {'statements': statements}
    
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode('utf-8'),
        headers=headers,
        method='POST'
    )
    
    with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
        result = json.loads(response.read().decode('utf-8'))
    
    if result and len(result) > 0:
        first_result = result[0]
        if 'error' in first_result:
            raise Exception(first_result['error']['message'])
        return first_result.get('results', {})
    return {}

def validate_card_format(card_number: str, software_prefix: str) -> Tuple[bool, str]:
    if len(card_number) != 22: return False, "卡密长度错误"
    parts = card_number.split('-')
    if len(parts) != 5: return False, "卡密格式错误"
    prefix, type_code, random_part, timestamp, checksum = parts
    if prefix != software_prefix: return False, "软件前缀不匹配"
    if type_code not in CARD_TYPES: return False, "未知卡类型"
    salt = f"card_system_v5_{prefix.lower()}"
    checksum_input = f"{prefix}{type_code}{random_part}{timestamp}{salt}"
    expected_checksum = hashlib.sha256(checksum_input.encode()).hexdigest()[:4].upper()
    if checksum != expected_checksum: return False, "卡密校验失败"
    return True, "格式验证通过"

def check_revocation(card_number: str) -> bool:
    result = execute_sql("SELECT COUNT(*) as cnt FROM card_revocation WHERE card_number = ?", [card_number])
    rows = result.get('rows', [])
    return rows[0][0] > 0 if rows else False

def get_card_info(card_number: str) -> Optional[Dict]:
    result = execute_sql("SELECT * FROM cards WHERE card_number = ?", [card_number])
    rows = result.get('rows', [])
    columns = result.get('columns', [])
    if not rows: return None
    return dict(zip(columns, rows[0]))

def activate_card(card_number: str, machine_fingerprint: str) -> Tuple[bool, str, Dict]:
    if check_revocation(card_number): return False, "卡密已被注销", {}
    card_info = get_card_info(card_number)
    if not card_info: return False, "卡密不存在", {}
    if card_info.get('status') == '已激活':
        stored_fingerprint = card_info.get('machine_fingerprint', '')
        if stored_fingerprint and stored_fingerprint != machine_fingerprint:
            return False, "卡密已绑定其他设备", card_info
        return True, "卡密已激活", card_info
    type_code = card_number.split('-')[1]
    card_type_info = CARD_TYPES.get(type_code, {})
    activate_time = datetime.now()
    if card_type_info.get("permanent"):
        expire_time = PERMANENT_CARD_EXPIRE
    else:
        duration = card_type_info.get("duration", timedelta(days=30))
        expire_time = (activate_time + duration).strftime("%Y-%m-%d %H:%M:%S")
    activate_time_str = activate_time.strftime("%Y-%m-%d %H:%M:%S")
    execute_sql("UPDATE cards SET status = '已激活', machine_fingerprint = ?, activate_time = ?, expire_time = ? WHERE card_number = ?", [machine_fingerprint, activate_time_str, expire_time, card_number])
    card_info['status'] = '已激活'
    card_info['machine_fingerprint'] = machine_fingerprint
    card_info['activate_time'] = activate_time_str
    card_info['expire_time'] = expire_time
    return True, "激活成功", card_info

def check_status(card_number: str, machine_fingerprint: str) -> Tuple[bool, str, Dict]:
    if check_revocation(card_number): return False, "卡密已被注销", {}
    card_info = get_card_info(card_number)
    if not card_info: return False, "卡密不存在", {}
    if card_info.get('status') != '已激活': return False, "卡密未激活", card_info
    stored_fingerprint = card_info.get('machine_fingerprint', '')
    if stored_fingerprint and stored_fingerprint != machine_fingerprint:
        return False, "设备绑定不匹配", card_info
    expire_time_str = card_info.get('expire_time', '')
    if expire_time_str and expire_time_str != PERMANENT_CARD_EXPIRE:
        try:
            expire_time = datetime.strptime(expire_time_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expire_time:
                execute_sql("UPDATE cards SET status = '已过期' WHERE card_number = ?", [card_number])
                return False, "卡密已过期", card_info
        except ValueError: pass
    execute_sql("UPDATE cards SET last_validate_time = ? WHERE card_number = ?", [datetime.now().strftime("%Y-%m-%d %H:%M:%S"), card_number])
    return True, "验证通过", card_info

def revoke_card(card_number: str, software_name: str, reason: str) -> Tuple[bool, str]:
    if check_revocation(card_number): return False, "卡密已注销"
    execute_sql("INSERT INTO card_revocation (card_number, software_name, revoke_time, revoke_reason) VALUES (?, ?, ?, ?)", [card_number, software_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), reason])
    execute_sql("UPDATE cards SET status = '已注销' WHERE card_number = ?", [card_number])
    return True, "注销成功"

@app.route('/')
def index():
    return jsonify({'status': 'ok', 'message': 'Card System API is running', 'version': '2.0'})

@app.route('/api', methods=['GET', 'POST'])
def api():
    if request.method == 'GET':
        return jsonify({'status': 'ok', 'message': 'Card System API is running', 'version': '2.0'})
    try:
        data = request.get_json() or {}
        action = data.get('action', '')
        if action == 'validate':
            valid, msg = validate_card_format(data.get('card_number', ''), data.get('software_prefix', ''))
            return jsonify({'success': valid, 'message': msg})
        elif action == 'activate':
            valid, msg = validate_card_format(data.get('card_number', ''), data.get('software_prefix', ''))
            if not valid: return jsonify({'success': False, 'message': msg})
            success, msg, info = activate_card(data.get('card_number', ''), data.get('machine_fingerprint', ''))
            return jsonify({'success': success, 'message': msg, 'data': info})
        elif action == 'check':
            valid, msg = validate_card_format(data.get('card_number', ''), data.get('software_prefix', ''))
            if not valid: return jsonify({'success': False, 'message': msg})
            success, msg, info = check_status(data.get('card_number', ''), data.get('machine_fingerprint', ''))
            return jsonify({'success': success, 'message': msg, 'data': info})
        elif action == 'revoke':
            if data.get('api_key', '') != API_SECRET: return jsonify({'success': False, 'message': '无权限'})
            success, msg = revoke_card(data.get('card_number', ''), data.get('software_name', ''), data.get('reason', '管理员注销'))
            return jsonify({'success': success, 'message': msg})
        else:
            return jsonify({'success': False, 'message': '未知操作，请使用: validate, activate, check, revoke'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'服务器错误: {str(e)}'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
