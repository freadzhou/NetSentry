#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GeoIP工具模块 - 用于IP地理位置查询
"""

import socket
import struct
from typing import Optional, Dict, Tuple
from functools import lru_cache


# 常见端口服务映射
COMMON_PORTS = {
    20: 'FTP数据',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP服务端',
    68: 'DHCP客户端',
    69: 'TFTP',
    80: 'HTTP',
    110: 'POP3',
    119: 'NNTP',
    123: 'NTP',
    135: 'RPC',
    137: 'NetBIOS',
    138: 'NetBIOS',
    139: 'NetBIOS',
    143: 'IMAP',
    161: 'SNMP',
    162: 'SNMP Trap',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    514: 'Syslog',
    587: 'SMTP(TLS)',
    636: 'LDAPS',
    993: 'IMAPS',
    995: 'POP3S',
    1080: 'SOCKS',
    1433: 'MSSQL',
    1434: 'MSSQL',
    1521: 'Oracle',
    1723: 'PPTP',
    2049: 'NFS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5901: 'VNC',
    6379: 'Redis',
    6667: 'IRC',
    8000: 'HTTP代理',
    8080: 'HTTP代理',
    8443: 'HTTPS代理',
    9000: 'PHP-FPM',
    9090: '代理',
    27017: 'MongoDB',
}


def get_service_by_port(port: int) -> str:
    """根据端口号获取服务名称"""
    return COMMON_PORTS.get(port, '')


@lru_cache(maxsize=1024)
def get_hostname(ip: str, timeout: float = 0.5) -> str:
    """反向DNS查询（带缓存）"""
    if not ip or ip in ['127.0.0.1', '::1', '0.0.0.0', '::', 'localhost']:
        return ""
    
    try:
        hostname = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
        return hostname[0] if hostname else ""
    except (socket.herror, socket.gaierror, socket.timeout):
        return ""


def is_ipv4(ip: str) -> bool:
    """检查是否为IPv4地址"""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, OSError):
        return False


def is_ipv6(ip: str) -> bool:
    """检查是否为IPv6地址"""
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, OSError):
        return False


def ip_to_int(ip: str) -> int:
    """IP地址转整数"""
    try:
        if is_ipv4(ip):
            return struct.unpack("!I", socket.inet_pton(socket.AF_INET, ip))[0]
        elif is_ipv6(ip):
            return struct.unpack("!Q", socket.inet_pton(socket.AF_INET6, ip)[0:8])[0]
    except:
        pass
    return 0