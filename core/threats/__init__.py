#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
威胁检测模块 - 支持多源聚合拉取
配置文件位置：EXE同级目录的 config/threats/ 下
"""

import os
import sys
import json
import re
import ipaddress
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict, Set
from enum import IntEnum


class RiskLevel(IntEnum):
    """风险等级"""
    NORMAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# IP类型枚举
class IPType(IntEnum):
    """IP类型"""
    LOCAL = 0      # 127.0.0.1, ::1, localhost
    PRIVATE = 1    # 内网IP (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    PUBLIC = 2     # 公网IP


# 进程可信度枚举
class ProcessTrust(IntEnum):
    """进程可信度"""
    HIGH = 0    # 高信任 - 系统核心/知名软件
    MEDIUM = 1  # 中等信任 - 未知进程
    LOW = 2     # 低信任 - 风险进程


# 端口风险枚举
class PortRisk(IntEnum):
    """端口风险等级"""
    NORMAL = 0      # 正常端口
    SUSPICIOUS = 1  # 可疑端口（代理等）
    DANGEROUS = 2   # 危险端口（常见后门）


RISK_LABELS = {
    RiskLevel.NORMAL: ("正常", "#4ADE80"),
    RiskLevel.LOW: ("低风险", "#FBBF24"),
    RiskLevel.MEDIUM: ("中风险", "#FB923C"),
    RiskLevel.HIGH: ("高风险", "#F87171"),
    RiskLevel.CRITICAL: ("威胁", "#A855F7"),
}


@dataclass
class ThreatInfo:
    """威胁信息"""
    risk_level: RiskLevel
    risk_label: str
    risk_color: str
    description: str = ""
    threat_type: str = ""


def get_config_dir():
    """获取配置目录 - EXE同级目录下的config文件夹"""
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        return os.path.join(exe_dir, 'config')
    else:
        # 开发时：项目目录（需要往上跳3层：__init__.py -> threats -> core -> 项目根目录）
        current_file = os.path.abspath(__file__)      # core/threats/__init__.py
        threats_dir = os.path.dirname(current_file)   # core/threats
        core_dir = os.path.dirname(threats_dir)       # core
        project_dir = os.path.dirname(core_dir)       # NetSentry
        return os.path.join(project_dir, 'config')


class ThreatDatabase:
    """威胁数据库"""
    
    # 默认威胁库（内置基础数据）
    DEFAULT_THREATS = {
        "version": "2026-03-26",
        "source": "builtin",
        "malicious_ips": [],
        # 进程可信度分级
        "process_trust": {
            "high": [
                # Windows系统进程
                "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
                "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe", "dwm.exe",
                "taskmgr.exe", "runtimebroker.exe", "shellhost.exe", "fontdrvhost.exe",
                # 知名浏览器
                "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe", "brave.exe",
                # 知名通讯软件
                "wechat.exe", "qq.exe", "dingtalk.exe", "telegram.exe", "discord.exe",
                "skype.exe", "zoom.exe", "teams.exe",
                # 知名开发工具
                "code.exe", "idea64.exe", "pycharm64.exe", "node.exe", "python.exe",
                "git.exe", "bash.exe", "powershell.exe", "cmd.exe",
                # 办公软件
                "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                "notepad.exe", "calc.exe", "mspaint.exe",
                # 媒体播放
                "spotify.exe", "vlc.exe", "musicbee.exe",
            ],
            "low": [
                # 挖矿程序
                "xmrig.exe", "minerd.exe", "cpuminer.exe", "ethminer.exe", "phoenixminer.exe",
                # 后门/渗透工具
                "nc.exe", "ncat.exe", "netcat.exe", "mimikatz.exe", "metasploit.exe",
                "meterpreter.exe", "cobaltstrike.exe", "beacon.exe",
                # 远程控制
                "vnc.exe", "tightvnc.exe", "ultravnc.exe",
                # 匿名工具
                "tor.exe", "privoxy.exe",
            ]
        },
        # 端口风险分级
        "port_risk": {
            "dangerous": [
                4444, 5555, 6667, 1234, 31337, 4443, 5554, 9999, 6666,
                12345, 12346, 27374, 27375, 27376,
                1999, 2000, 2001, 2023, 2115, 2140, 2150, 2155,
                2283, 2300, 2301, 2500, 2567, 2583, 2600, 2601,
                1337, 7777, 8888,
            ],
            "suspicious": [
                1080, 7890, 7891, 7892, 7893, 7897, 10808, 10809,
                8080, 8118, 9090, 9050, 9051,
                5900, 5901, 5902, 5800, 5801,
                3306, 1433, 1434, 5432, 6379, 27017,
            ],
            "normal": [
                80, 443, 8080, 8443, 22, 2222, 21, 25, 587, 465,
                110, 995, 143, 993, 53, 3389,
            ]
        },
        # 可疑连接类型
        "suspicious_connections": {
            "tor_nodes": [9001, 9030, 9050, 9051],
            "miner_pools": [3333, 4444, 5555, 7777, 8888, 9999],
        }
    }
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance
    
    def _init(self):
        self.config_dir = get_config_dir()
        self.threats_dir = os.path.join(self.config_dir, 'threats')
        self.db_path = os.path.join(self.threats_dir, 'threat_db.json')
        self._threats = None
        self._ip_set = set()  # 用于O(1)快速查询恶意IP
        self._high_trust_set = set()  # 高信任进程集合
        self._low_trust_set = set()   # 低信任进程集合
        self._dangerous_ports = set()  # 危险端口集合
        self._suspicious_ports = set() # 可疑端口集合
        self._load_database()
    
    def _load_database(self):
        """加载威胁数据库"""
        os.makedirs(self.threats_dir, exist_ok=True)
        
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    self._threats = json.load(f)
                # 初始化各种集合用于快速查询
                self._ip_set = set(self._threats.get('malicious_ips', []))
                self._init_process_trust_sets()
                self._init_port_risk_sets()
                return
            except:
                pass
        
        self._threats = self.DEFAULT_THREATS.copy()
        self._ip_set = set(self._threats.get('malicious_ips', []))
        self._init_process_trust_sets()
        self._init_port_risk_sets()
        self._save_database()
    
    def _init_process_trust_sets(self):
        """初始化进程可信度集合"""
        process_trust = self._threats.get('process_trust', {})
        self._high_trust_set = set(p.lower() for p in process_trust.get('high', []))
        self._low_trust_set = set(p.lower() for p in process_trust.get('low', []))
    
    def _init_port_risk_sets(self):
        """初始化端口风险集合"""
        port_risk = self._threats.get('port_risk', {})
        self._dangerous_ports = set(port_risk.get('dangerous', []))
        self._suspicious_ports = set(port_risk.get('suspicious', []))
    
    def _save_database(self):
        """保存威胁数据库"""
        os.makedirs(self.threats_dir, exist_ok=True)
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self._threats, f, indent=2, ensure_ascii=False)
    
    def get_version(self) -> str:
        return self._threats.get('version', 'unknown')
    
    def get_source(self) -> str:
        return self._threats.get('source', 'unknown')
    
    def get_db_path(self) -> str:
        return self.db_path
    
    def get_ip_count(self) -> int:
        return len(self._threats.get('malicious_ips', []))
    
    def update_database(self, new_data: dict) -> bool:
        try:
            self._threats = new_data
            self._save_database()
            return True
        except Exception:
            return False
    
    def merge_ips(self, new_ips: list, source: str = "online") -> bool:
        """替换式更新恶意IP列表 - 与远程源保持一致，防止无限膨胀"""
        try:
            # 去重
            unique_ips = list(set(new_ips))
            
            # 替换而非合并，防止文件无限膨胀
            self._threats['malicious_ips'] = unique_ips
            self._threats['version'] = datetime.now().strftime("%Y-%m-%d")
            self._threats['source'] = source
            self._threats['ip_count'] = len(unique_ips)
            
            # 更新内存中的IP集合用于快速查询
            self._ip_set = set(unique_ips)
            
            self._save_database()
            return True
        except Exception:
            return False
    
    def analyze_process(self, process_name: str, pid: int = 0) -> ThreatInfo:
        """分析进程风险 - 基于可信度"""
        process_name_lower = process_name.lower()
        
        # 高信任进程
        if process_name_lower in self._high_trust_set:
            return ThreatInfo(
                risk_level=RiskLevel.NORMAL,
                risk_label=RISK_LABELS[RiskLevel.NORMAL][0],
                risk_color=RISK_LABELS[RiskLevel.NORMAL][1],
                description="已知安全进程"
            )
        
        # 低信任进程
        if process_name_lower in self._low_trust_set:
            return ThreatInfo(
                risk_level=RiskLevel.HIGH,
                risk_label=RISK_LABELS[RiskLevel.HIGH][0],
                risk_color=RISK_LABELS[RiskLevel.HIGH][1],
                description="检测到风险进程",
                threat_type="risk_process"
            )
        
        # 未知进程
        return ThreatInfo(
            risk_level=RiskLevel.LOW,
            risk_label=RISK_LABELS[RiskLevel.LOW][0],
            risk_color=RISK_LABELS[RiskLevel.LOW][1],
            description="未知进程"
        )
    
    def analyze_process_with_connections(self, process_name: str, connections: list, pid: int = 0) -> ThreatInfo:
        """
        分析进程综合风险 - 进程本身风险 + 所有连接的最高风险
        返回最高风险作为进程的整体风险等级
        """
        # 1. 获取进程本身的风险
        process_risk = self.analyze_process(process_name, pid)
        max_risk = process_risk.risk_level
        max_threat = process_risk
        
        # 2. 遍历所有连接，找出最高风险
        for conn in connections:
            remote_ip = getattr(conn, 'remote_addr', '') or ''
            remote_port = getattr(conn, 'remote_port', 0) or 0
            
            if remote_ip:  # 只分析有远程地址的连接
                conn_threat = self.analyze_connection(remote_ip, remote_port, process_name)
                if conn_threat.risk_level > max_risk:
                    max_risk = conn_threat.risk_level
                    max_threat = conn_threat
        
        return max_threat
    
    def _get_ip_type(self, ip: str) -> IPType:
        """判断IP类型"""
        if not ip:
            return IPType.LOCAL
        
        # 本地回环
        if ip in ('127.0.0.1', '::1', 'localhost', '0.0.0.0', '::'):
            return IPType.LOCAL
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # 本地回环
            if ip_obj.is_loopback:
                return IPType.LOCAL
            
            # 私有/内网IP
            if ip_obj.is_private:
                return IPType.PRIVATE
            
            # 链路本地也算内网
            if ip_obj.is_link_local:
                return IPType.PRIVATE
            
            # 公网IP
            return IPType.PUBLIC
            
        except ValueError:
            return IPType.PUBLIC  # 解析失败按公网处理
    
    def _get_process_trust(self, process_name: str) -> ProcessTrust:
        """获取进程可信度"""
        process_name_lower = process_name.lower()
        
        if process_name_lower in self._high_trust_set:
            return ProcessTrust.HIGH
        
        if process_name_lower in self._low_trust_set:
            return ProcessTrust.LOW
        
        return ProcessTrust.MEDIUM
    
    def _get_port_risk(self, port: int) -> PortRisk:
        """获取端口风险等级"""
        if port in self._dangerous_ports:
            return PortRisk.DANGEROUS
        
        if port in self._suspicious_ports:
            return PortRisk.SUSPICIOUS
        
        return PortRisk.NORMAL
    
    def analyze_connection(self, remote_ip: str, remote_port: int, 
                          process_name: str = "") -> ThreatInfo:
        """分析连接风险 - 基于矩阵判断"""
        
        # 1. 恶意IP直接判定（最高优先级）
        if remote_ip in self._ip_set:
            return ThreatInfo(
                risk_level=RiskLevel.CRITICAL,
                risk_label=RISK_LABELS[RiskLevel.CRITICAL][0],
                risk_color=RISK_LABELS[RiskLevel.CRITICAL][1],
                description=f"连接到已知恶意IP: {remote_ip}",
                threat_type="malicious_ip"
            )
        
        # 2. 获取各维度评估结果
        ip_type = self._get_ip_type(remote_ip)
        trust = self._get_process_trust(process_name)
        port_risk = self._get_port_risk(remote_port)
        
        # 3. 矩阵判断逻辑
        # 本地IP (127.0.0.1, ::1)
        if ip_type == IPType.LOCAL:
            if trust == ProcessTrust.LOW:
                return ThreatInfo(
                    risk_level=RiskLevel.MEDIUM,
                    risk_label=RISK_LABELS[RiskLevel.MEDIUM][0],
                    risk_color=RISK_LABELS[RiskLevel.MEDIUM][1],
                    description="风险进程本地通信",
                    threat_type="local_suspicious"
                )
            return ThreatInfo(
                risk_level=RiskLevel.NORMAL,
                risk_label=RISK_LABELS[RiskLevel.NORMAL][0],
                risk_color=RISK_LABELS[RiskLevel.NORMAL][1],
                description="本地通信"
            )
        
        # 内网IP
        elif ip_type == IPType.PRIVATE:
            if trust == ProcessTrust.HIGH:
                # 高信任进程连内网，正常
                return ThreatInfo(
                    risk_level=RiskLevel.NORMAL,
                    risk_label=RISK_LABELS[RiskLevel.NORMAL][0],
                    risk_color=RISK_LABELS[RiskLevel.NORMAL][1],
                    description="内网通信"
                )
            elif trust == ProcessTrust.MEDIUM:
                # 未知进程连内网
                if port_risk == PortRisk.DANGEROUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.MEDIUM,
                        risk_label=RISK_LABELS[RiskLevel.MEDIUM][0],
                        risk_color=RISK_LABELS[RiskLevel.MEDIUM][1],
                        description=f"未知进程连接内网危险端口: {remote_port}",
                        threat_type="internal_suspicious"
                    )
                return ThreatInfo(
                    risk_level=RiskLevel.LOW,
                    risk_label=RISK_LABELS[RiskLevel.LOW][0],
                    risk_color=RISK_LABELS[RiskLevel.LOW][1],
                    description="内网通信"
                )
            else:  # LOW trust
                # 低信任进程连内网，需要关注
                if port_risk == PortRisk.DANGEROUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.HIGH,
                        risk_label=RISK_LABELS[RiskLevel.HIGH][0],
                        risk_color=RISK_LABELS[RiskLevel.HIGH][1],
                        description="风险进程内网异常端口通信，可能横向移动",
                        threat_type="lateral_movement"
                    )
                elif port_risk == PortRisk.SUSPICIOUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.MEDIUM,
                        risk_label=RISK_LABELS[RiskLevel.MEDIUM][0],
                        risk_color=RISK_LABELS[RiskLevel.MEDIUM][1],
                        description="风险进程内网可疑端口通信",
                        threat_type="internal_suspicious"
                    )
                return ThreatInfo(
                    risk_level=RiskLevel.LOW,
                    risk_label=RISK_LABELS[RiskLevel.LOW][0],
                    risk_color=RISK_LABELS[RiskLevel.LOW][1],
                    description="风险进程内网通信"
                )
        
        # 公网IP
        else:  # PUBLIC
            if trust == ProcessTrust.HIGH:
                if port_risk == PortRisk.DANGEROUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.MEDIUM,
                        risk_label=RISK_LABELS[RiskLevel.MEDIUM][0],
                        risk_color=RISK_LABELS[RiskLevel.MEDIUM][1],
                        description=f"知名进程连接公网危险端口: {remote_port}",
                        threat_type="unusual_port"
                    )
                return ThreatInfo(
                    risk_level=RiskLevel.LOW,
                    risk_label=RISK_LABELS[RiskLevel.LOW][0],
                    risk_color=RISK_LABELS[RiskLevel.LOW][1],
                    description="公网通信"
                )
            elif trust == ProcessTrust.MEDIUM:
                if port_risk == PortRisk.DANGEROUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.HIGH,
                        risk_label=RISK_LABELS[RiskLevel.HIGH][0],
                        risk_color=RISK_LABELS[RiskLevel.HIGH][1],
                        description=f"未知进程连接公网危险端口: {remote_port}",
                        threat_type="suspicious_connection"
                    )
                elif port_risk == PortRisk.SUSPICIOUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.MEDIUM,
                        risk_label=RISK_LABELS[RiskLevel.MEDIUM][0],
                        risk_color=RISK_LABELS[RiskLevel.MEDIUM][1],
                        description=f"未知进程连接公网可疑端口: {remote_port}",
                        threat_type="suspicious_port"
                    )
                return ThreatInfo(
                    risk_level=RiskLevel.LOW,
                    risk_label=RISK_LABELS[RiskLevel.LOW][0],
                    risk_color=RISK_LABELS[RiskLevel.LOW][1],
                    description="公网通信"
                )
            else:  # LOW trust
                if port_risk == PortRisk.DANGEROUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.CRITICAL,
                        risk_label=RISK_LABELS[RiskLevel.CRITICAL][0],
                        risk_color=RISK_LABELS[RiskLevel.CRITICAL][1],
                        description="风险进程连接公网危险端口，疑似C2通信",
                        threat_type="c2_suspected"
                    )
                elif port_risk == PortRisk.SUSPICIOUS:
                    return ThreatInfo(
                        risk_level=RiskLevel.HIGH,
                        risk_label=RISK_LABELS[RiskLevel.HIGH][0],
                        risk_color=RISK_LABELS[RiskLevel.HIGH][1],
                        description="风险进程连接公网可疑端口",
                        threat_type="suspicious_connection"
                    )
                return ThreatInfo(
                    risk_level=RiskLevel.HIGH,
                    risk_label=RISK_LABELS[RiskLevel.HIGH][0],
                    risk_color=RISK_LABELS[RiskLevel.HIGH][1],
                    description="风险进程公网通信",
                    threat_type="risk_process_network"
                )


class ThreatUpdater:
    """威胁库更新器 - 支持多源聚合"""
    
    # IP列表源（按优先级排序）
    IP_LIST_SOURCES = [
        {
            "name": "Emerging Threats",
            "url": "https://rules.emergingthreats.net/blocklists/emerging-Block-IPs.txt",
            "format": "plain_ip",
            "priority": 1,
            "description": "Emerging Threats恶意IP列表"
        },
        {
            "name": "FireHol Level1",
            "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
            "format": "mixed",  # 可能包含CIDR
            "priority": 2,
            "description": "FireHol聚合列表（严格）"
        },
        {
            "name": "FireHol Level1 (CDN)",
            "url": "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level1.netset",
            "format": "mixed",
            "priority": 3,
            "description": "FireHol CDN镜像"
        },
        {
            "name": "Blocklist.de",
            "url": "https://lists.blocklist.de/lists/all.txt",
            "format": "plain_ip",
            "priority": 4,
            "description": "Blocklist.de攻击IP列表"
        },
    ]
    
    def __init__(self, database: ThreatDatabase):
        self.database = database
        self._last_update_status = None
    
    def check_update(self) -> tuple:
        """检查是否有可用更新源"""
        try:
            import urllib.request
            import ssl
            
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # 尝试连接第一个可用源
            for source in self.IP_LIST_SOURCES:
                try:
                    req = urllib.request.Request(source["url"], headers={'User-Agent': 'NetSentry/1.0'})
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as response:
                        # 只要能连接就返回有更新
                        return (True, source["name"], None)
                except:
                    continue
            
            return (False, None, "无法连接到任何威胁情报源")
            
        except Exception as e:
            return (False, None, str(e))
    
    def _download_ip_list(self, url: str) -> list:
        """下载IP列表"""
        import urllib.request
        import ssl
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'NetSentry/1.0'})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                content = response.read().decode('utf-8')
                return self._parse_ip_list(content)
        except Exception as e:
            print(f"下载失败 {url}: {e}")
            return []
    
    def _parse_ip_list(self, content: str) -> list:
        """解析IP列表"""
        ips = []
        
        # IP地址正则
        ip_pattern = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        
        for line in content.split('\n'):
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#') or line.startswith('//'):
                continue
            
            # 提取IP地址
            match = ip_pattern.match(line)
            if match:
                ip = match.group(1)
                # 简单验证IP格式
                parts = ip.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    ips.append(ip)
        
        return ips
    
    def download_update(self) -> tuple:
        """下载并合并威胁库更新"""
        all_ips = set()
        successful_sources = []
        
        # 按优先级尝试每个源
        for source in self.IP_LIST_SOURCES:
            print(f"正在从 {source['name']} 获取威胁列表...")
            
            ips = self._download_ip_list(source["url"])
            
            if ips:
                all_ips.update(ips)
                successful_sources.append(source["name"])
                print(f"  ✓ 获取 {len(ips)} 个IP")
                
                # 如果已经获取到足够的数据，可以提前结束
                # 但为了更全面，我们继续尝试其他源
            else:
                print(f"  ✗ 获取失败")
        
        if not all_ips:
            return (False, "无法从任何源获取威胁数据，请检查网络连接")
        
        # 合并到本地数据库
        if self.database.merge_ips(list(all_ips), ", ".join(successful_sources)):
            self._last_update_status = {
                "time": datetime.now().isoformat(),
                "sources": successful_sources,
                "ip_count": len(all_ips)
            }
            return (True, f"更新成功！从 {len(successful_sources)} 个源获取了 {len(all_ips)} 个恶意IP")
        else:
            return (False, "保存更新失败")
    
    def get_update_sources_info(self) -> list:
        """获取更新源信息"""
        return self.IP_LIST_SOURCES


def get_threat_database() -> ThreatDatabase:
    return ThreatDatabase()


def get_threat_updater() -> ThreatUpdater:
    return ThreatUpdater(get_threat_database())