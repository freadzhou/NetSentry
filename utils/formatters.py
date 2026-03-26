#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
格式化工具模块
"""

import time
import ipaddress
from datetime import datetime
from typing import Optional


def format_bytes(bytes_count: float, decimals: int = 2) -> str:
    """格式化字节数为人类可读格式"""
    if bytes_count == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    index = 0
    
    while bytes_count >= 1024 and index < len(units) - 1:
        bytes_count /= 1024
        index += 1
    
    return f"{bytes_count:.{decimals}f} {units[index]}"


def format_rate(bytes_per_sec: float, decimals: int = 2) -> str:
    """格式化速率"""
    return f"{format_bytes(bytes_per_sec, decimals)}/s"


def format_ip_port(ip: str, port: int) -> str:
    """格式化IP和端口"""
    if not ip:
        if port:
            return f":{port}"
        return ""
    return f"{ip}:{port}" if port else ip


def format_connection_status(status: str) -> str:
    """格式化连接状态"""
    status_map = {
        'ESTABLISHED': '已建立',
        'SYN_SENT': 'SYN发送',
        'SYN_RECV': 'SYN接收',
        'FIN_WAIT1': 'FIN等待1',
        'FIN_WAIT2': 'FIN等待2',
        'TIME_WAIT': '时间等待',
        'CLOSE': '已关闭',
        'CLOSE_WAIT': '关闭等待',
        'LAST_ACK': '最后确认',
        'LISTEN': '监听中',
        'CLOSING': '关闭中',
        '': '无'
    }
    return status_map.get(status.upper(), status)


def format_timestamp(timestamp: float, fmt: str = "%H:%M:%S") -> str:
    """格式化时间戳"""
    if timestamp <= 0:
        return ""
    return datetime.fromtimestamp(timestamp).strftime(fmt)


def format_duration(seconds: float) -> str:
    """格式化持续时间"""
    if seconds < 60:
        return f"{int(seconds)}秒"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        secs = int(seconds % 60)
        return f"{minutes}分{secs}秒"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return f"{hours}时{minutes}分"
    else:
        days = int(seconds / 86400)
        hours = int((seconds % 86400) / 3600)
        return f"{days}天{hours}时"


def is_private_ip(ip: str) -> bool:
    """判断是否为私有IP"""
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_local_ip(ip: str) -> bool:
    """判断是否为本机IP"""
    if not ip:
        return True
    local_ips = ['127.0.0.1', '::1', 'localhost', '0.0.0.0', '::']
    return ip in local_ips or is_private_ip(ip)


def get_ip_type(ip: str) -> str:
    """获取IP类型"""
    if not ip:
        return "本地"
    
    if ip in ['127.0.0.1', '::1', 'localhost']:
        return "回环"
    
    if ip in ['0.0.0.0', '::']:
        return "任意"
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "内网"
        elif ip_obj.is_global:
            return "外网"
        elif ip_obj.is_multicast:
            return "组播"
        elif ip_obj.is_link_local:
            return "链路本地"
        else:
            return "其他"
    except ValueError:
        return "未知"


def truncate_string(s: str, max_len: int = 30, suffix: str = "...") -> str:
    """截断字符串"""
    if len(s) <= max_len:
        return s
    return s[:max_len - len(suffix)] + suffix


def get_process_icon_name(process_name: str) -> str:
    """根据进程名获取图标名称"""
    name_lower = process_name.lower()
    
    # 浏览器
    browsers = ['chrome', 'firefox', 'edge', 'safari', 'opera', 'brave']
    if any(b in name_lower for b in browsers):
        return "browser"
    
    # 通讯软件
    messengers = ['wechat', 'qq', 'telegram', 'discord', 'slack', 'teams', 'zoom', 'skype']
    if any(m in name_lower for m in messengers):
        return "messenger"
    
    # 开发工具
    dev_tools = ['code', 'idea', 'pycharm', 'vscode', 'sublime', 'vim', 'git', 'node']
    if any(d in name_lower for d in dev_tools):
        return "developer"
    
    # 系统进程
    system = ['system', 'svchost', 'explorer', 'dwm', 'kernel', 'init']
    if any(s in name_lower for s in system):
        return "system"
    
    # 游戏
    games = ['steam', 'game', 'league', 'valorant', 'minecraft', 'epic']
    if any(g in name_lower for g in games):
        return "game"
    
    return "default"