#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Card System API - Vercel Serverless Function
在线卡密验证API接口

部署到Vercel后，可通过以下接口调用：
- POST /api/validate - 验证卡密
- POST /api/activate - 激活卡密
- POST /api/check - 检查状态
- POST /api/revoke - 注销卡密（管理员）
"""

import json
import hashlib
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional, Any
import urllib.request
import urllib.parse

API_SECRET = os.environ.get("API_SECRET", "your-secret-key-change-me")

CARD_TYPES = {
    "1H": {"name": "1小时卡", "duration": timedelta(hours=1)},
    "1D": {"name": "天卡", "duration": timedelta(days=1)},
    "1M": {"name": "月卡", "duration": timedelta(days=30)},
    "3M": {"name": "季卡", "duration": timedelta(days=90)},
    "1Y": {"name": "年卡", "duration": timedelta(days=365)},
    "F0": {"name": "永久卡", "permanent": True}
}

PERMANENT_CARD_EXPIRE = "2099-12-31 23:59:59"

def get_db_connection():
    """获取数据库连接"""
    db_url = os.environ.get("DATABASE_URL")
    
    if db_url:
        import psycopg2
        conn = psycopg2.connect(db_url)
    else:
        db_path = "/tmp/card_system.db"
        conn = sqlite3.connect(db_path, check_same_thread=False)
        init_db(conn)
    
    return conn

def init_db(conn):
    """初始化数据库表"""
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cards (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_number TEXT UNIQUE NOT NULL,
            software_name TEXT NOT NULL,
            card_type TEXT NOT NULL,
            days REAL NOT NULL,
            price REAL NOT NULL,
            generate_time TEXT NOT NULL,
            status TEXT DEFAULT '未激活',
            machine_fingerprint TEXT DEFAULT '',
            activate_time TEXT,
            expire_time TEXT,
            last_validate_time TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS card_revocation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            card_number TEXT NOT NULL,
            software_name TEXT NOT NULL,
            revoke_time TEXT NOT NULL,
            revoke_reason TEXT,
            UNIQUE(card_number, software_name)
        )
    ''')
    
    conn.commit()

def validate_card_format(card_number: str, software_prefix: str) -> Tuple[bool, str]:
    """验证卡密格式"""
    if len(card_number) != 22:
        return False, "卡密长度错误"
    
    parts = card_number.split('-')
    if len(parts) != 5:
        return False, "卡密格式错误"
    
    prefix, type_code, random_part, timestamp, checksum = parts
    
    if prefix != software_prefix:
        return False, "软件前缀不匹配"
    
    if type_code not in CARD_TYPES:
        return False, "未知卡类型"
    
    salt = f"card_system_v5_{prefix.lower()}"
    checksum_input = f"{prefix}{type_code}{random_part}{timestamp}{salt}"
    expected_checksum = hashlib.sha256(checksum_input.encode()).hexdigest()[:4].upper()
    
    if checksum != expected_checksum:
        return False, "卡密校验失败"
    
    return True, "格式验证通过"

def check_revocation(conn, card_number: str) -> bool:
    """检查卡密是否被注销"""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM card_revocation WHERE card_number = ?",
        (card_number,)
    )
    return cursor.fetchone()[0] > 0

def get_card_info(conn, card_number: str) -> Optional[Dict]:
    """获取卡密信息"""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM cards WHERE card_number = ?",
        (card_number,)
    )
    row = cursor.fetchone()
    
    if not row:
        return None
    
    columns = [desc[0] for desc in cursor.description]
    return dict(zip(columns, row))

def activate_card(conn, card_number: str, machine_fingerprint: str) -> Tuple[bool, str, Dict]:
    """激活卡密"""
    cursor = conn.cursor()
    
    if check_revocation(conn, card_number):
        return False, "卡密已被注销", {}
    
    card_info = get_card_info(conn, card_number)
    if not card_info:
        return False, "卡密不存在", {}
    
    if card_info['status'] == '已激活':
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
    
    cursor.execute('''
        UPDATE cards SET 
            status = '已激活',
            machine_fingerprint = ?,
            activate_time = ?,
            expire_time = ?
        WHERE card_number = ?
    ''', (machine_fingerprint, activate_time_str, expire_time, card_number))
    
    conn.commit()
    
    card_info['status'] = '已激活'
    card_info['machine_fingerprint'] = machine_fingerprint
    card_info['activate_time'] = activate_time_str
    card_info['expire_time'] = expire_time
    
    return True, "激活成功", card_info

def check_status(conn, card_number: str, machine_fingerprint: str) -> Tuple[bool, str, Dict]:
    """检查卡密状态"""
    if check_revocation(conn, card_number):
        return False, "卡密已被注销", {}
    
    card_info = get_card_info(conn, card_number)
    if not card_info:
        return False, "卡密不存在", {}
    
    if card_info['status'] != '已激活':
        return False, "卡密未激活", card_info
    
    stored_fingerprint = card_info.get('machine_fingerprint', '')
    if stored_fingerprint and stored_fingerprint != machine_fingerprint:
        return False, "设备绑定不匹配", card_info
    
    expire_time_str = card_info.get('expire_time', '')
    if expire_time_str and expire_time_str != PERMANENT_CARD_EXPIRE:
        try:
            expire_time = datetime.strptime(expire_time_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > expire_time:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE cards SET status = '已过期' WHERE card_number = ?",
                    (card_number,)
                )
                conn.commit()
                return False, "卡密已过期", card_info
        except ValueError:
            pass
    
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE cards SET last_validate_time = ? WHERE card_number = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), card_number)
    )
    conn.commit()
    
    return True, "验证通过", card_info

def revoke_card(conn, card_number: str, software_name: str, reason: str) -> Tuple[bool, str]:
    """注销卡密"""
    cursor = conn.cursor()
    
    if check_revocation(conn, card_number):
        return False, "卡密已注销"
    
    cursor.execute('''
        INSERT INTO card_revocation (card_number, software_name, revoke_time, revoke_reason)
        VALUES (?, ?, ?, ?)
    ''', (card_number, software_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), reason))
    
    cursor.execute(
        "UPDATE cards SET status = '已注销' WHERE card_number = ?",
        (card_number,)
    )
    
    conn.commit()
    return True, "注销成功"

def handler(request):
    """Vercel Serverless Handler"""
    try:
        if isinstance(request, dict):
            body = request.get('body', '{}')
            if isinstance(body, str):
                data = json.loads(body) if body else {}
            else:
                data = body
            method = request.get('method', 'POST')
        else:
            body = request.body.decode('utf-8') if hasattr(request, 'body') else '{}'
            data = json.loads(body) if body else {}
            method = request.method if hasattr(request, 'method') else 'POST'
        
        action = data.get('action', '')
        
        conn = get_db_connection()
        
        try:
            if action == 'validate':
                card_number = data.get('card_number', '')
                software_prefix = data.get('software_prefix', '')
                
                valid, msg = validate_card_format(card_number, software_prefix)
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'success': valid,
                        'message': msg
                    }, ensure_ascii=False)
                }
            
            elif action == 'activate':
                card_number = data.get('card_number', '')
                software_prefix = data.get('software_prefix', '')
                machine_fingerprint = data.get('machine_fingerprint', '')
                
                valid, msg = validate_card_format(card_number, software_prefix)
                if not valid:
                    return {
                        'statusCode': 200,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({
                            'success': False,
                            'message': msg
                        }, ensure_ascii=False)
                    }
                
                success, msg, info = activate_card(conn, card_number, machine_fingerprint)
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'success': success,
                        'message': msg,
                        'data': info
                    }, ensure_ascii=False)
                }
            
            elif action == 'check':
                card_number = data.get('card_number', '')
                software_prefix = data.get('software_prefix', '')
                machine_fingerprint = data.get('machine_fingerprint', '')
                
                valid, msg = validate_card_format(card_number, software_prefix)
                if not valid:
                    return {
                        'statusCode': 200,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({
                            'success': False,
                            'message': msg
                        }, ensure_ascii=False)
                    }
                
                success, msg, info = check_status(conn, card_number, machine_fingerprint)
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'success': success,
                        'message': msg,
                        'data': info
                    }, ensure_ascii=False)
                }
            
            elif action == 'revoke':
                api_key = data.get('api_key', '')
                if api_key != API_SECRET:
                    return {
                        'statusCode': 403,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({
                            'success': False,
                            'message': '无权限'
                        }, ensure_ascii=False)
                    }
                
                card_number = data.get('card_number', '')
                software_name = data.get('software_name', '')
                reason = data.get('reason', '管理员注销')
                
                success, msg = revoke_card(conn, card_number, software_name, reason)
                return {
                    'statusCode': 200,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'success': success,
                        'message': msg
                    }, ensure_ascii=False)
                }
            
            else:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({
                        'success': False,
                        'message': '未知操作'
                    }, ensure_ascii=False)
                }
        
        finally:
            conn.close()
    
    except Exception as e:
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'success': False,
                'message': f'服务器错误: {str(e)}'
            }, ensure_ascii=False)
        }

def main(request):
    """入口函数"""
    return handler(request)
