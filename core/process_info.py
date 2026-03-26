#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
进程信息模块
获取进程详细信息
"""

import psutil
from typing import Optional, Dict, List
from dataclasses import dataclass


@dataclass
class ProcessDetail:
    """进程详细信息"""
    pid: int
    name: str
    path: str
    username: str
    cpu_percent: float
    memory_percent: float
    memory_mb: float
    create_time: float
    status: str
    num_threads: int
    num_handles: int = 0  # Windows only
    connections_count: int = 0


def get_process_detail(pid: int) -> Optional[ProcessDetail]:
    """获取进程详细信息"""
    try:
        if pid == 0:
            return ProcessDetail(
                pid=0,
                name="System",
                path="",
                username="SYSTEM",
                cpu_percent=0.0,
                memory_percent=0.0,
                memory_mb=0.0,
                create_time=0.0,
                status="running",
                num_threads=0,
                num_handles=0
            )
        
        proc = psutil.Process(pid)
        
        try:
            username = proc.username()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            username = "N/A"
        
        try:
            num_handles = proc.num_handles() if hasattr(proc, 'num_handles') else 0
        except (psutil.AccessDenied, AttributeError):
            num_handles = 0
        
        return ProcessDetail(
            pid=pid,
            name=proc.name(),
            path=proc.exe() if hasattr(proc, 'exe') else "",
            username=username,
            cpu_percent=proc.cpu_percent(interval=0.05),
            memory_percent=proc.memory_percent(),
            memory_mb=proc.memory_info().rss / (1024 * 1024),
            create_time=proc.create_time(),
            status=proc.status(),
            num_threads=proc.num_threads(),
            num_handles=num_handles
        )
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombiesProcess):
        return None


def get_all_processes() -> List[Dict]:
    """获取所有进程列表（简要信息）"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'],
                'cpu': proc.info['cpu_percent'] or 0.0,
                'memory': proc.info['memory_percent'] or 0.0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes


def get_processes_with_network() -> List[Dict]:
    """获取有网络活动的进程列表"""
    processes = []
    seen_pids = set()
    
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            pid = conn.pid if conn.pid else 0
            if pid not in seen_pids:
                seen_pids.add(pid)
                try:
                    if pid == 0:
                        processes.append({
                            'pid': 0,
                            'name': 'System',
                            'path': '',
                            'username': 'SYSTEM'
                        })
                    else:
                        proc = psutil.Process(pid)
                        processes.append({
                            'pid': pid,
                            'name': proc.name(),
                            'path': proc.exe() if hasattr(proc, 'exe') else '',
                            'username': proc.username() if hasattr(proc, 'username') else 'N/A'
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    processes.append({
                        'pid': pid,
                        'name': 'Unknown',
                        'path': '',
                        'username': 'N/A'
                    })
    except psutil.AccessDenied:
        pass
    
    return processes


def is_system_process(pid: int) -> bool:
    """判断是否为系统进程"""
    try:
        if pid == 0:
            return True
        proc = psutil.Process(pid)
        name = proc.name().lower()
        # Windows系统进程
        system_processes = [
            'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 
            'services.exe', 'lsass.exe', 'winlogon.exe', 'svchost.exe',
            'explorer.exe', 'dwm.exe', 'taskmgr.exe', 'powershell.exe',
            'kernel', 'init', 'kthreadd'  # Linux
        ]
        return name in system_processes or pid <= 10
    except:
        return False