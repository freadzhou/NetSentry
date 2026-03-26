#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络监控核心模块
负责采集网络连接、流量统计等数据
"""

import psutil
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from threading import Lock


@dataclass
class ConnectionInfo:
    """网络连接信息"""
    pid: int
    process_name: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    protocol: str  # 'TCP' or 'UDP'
    family: str  # 'IPv4' or 'IPv6'
    timestamp: float = field(default_factory=time.time)
    
    @property
    def connection_key(self) -> str:
        """生成唯一连接标识"""
        if self.remote_addr:
            return f"{self.protocol}:{self.local_addr}:{self.local_port}->{self.remote_addr}:{self.remote_port}"
        return f"{self.protocol}:{self.local_addr}:{self.local_port}"


@dataclass
class ProcessStats:
    """进程网络统计"""
    pid: int
    process_name: str
    process_path: str = ""
    connections: List[ConnectionInfo] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_recv: int = 0
    bytes_sent_rate: float = 0.0  # bytes/sec
    bytes_recv_rate: float = 0.0  # bytes/sec
    last_update: float = 0.0
    connection_count: int = 0


class NetworkMonitor:
    """网络监控器"""
    
    def __init__(self, refresh_interval: float = 1.5):
        self.refresh_interval = refresh_interval
        self._lock = Lock()
        
        # 进程统计缓存
        self._process_stats: Dict[int, ProcessStats] = {}
        
        # 上次采样时间
        self._last_sample_time: float = 0
        
        # 上次网络IO计数
        self._last_net_io: Dict[int, tuple] = {}  # pid -> (bytes_sent, bytes_recv, timestamp)
        
        # 系统级网络IO
        self._last_system_net_io: tuple = (0, 0, 0)  # (bytes_sent, bytes_recv, timestamp)
        
    def get_connections(self) -> Dict[int, ProcessStats]:
        """获取所有网络连接，按进程分组"""
        with self._lock:
            current_time = time.time()
            
            # 获取所有网络连接
            connections = psutil.net_connections(kind='inet')
            
            # 按PID分组
            pid_connections: Dict[int, List[ConnectionInfo]] = defaultdict(list)
            
            for conn in connections:
                pid = conn.pid if conn.pid else 0
                
                # 解析本地地址
                if conn.laddr:
                    local_addr = conn.laddr.ip
                    local_port = conn.laddr.port
                else:
                    local_addr = ""
                    local_port = 0
                
                # 解析远程地址
                if conn.raddr:
                    remote_addr = conn.raddr.ip
                    remote_port = conn.raddr.port
                else:
                    remote_addr = ""
                    remote_port = 0
                
                # 确定协议
                if conn.family == 2:  # AF_INET
                    family = "IPv4"
                elif conn.family == 10:  # AF_INET6
                    family = "IPv6"
                else:
                    family = "Unknown"
                
                protocol = "TCP" if conn.type == 1 else "UDP"
                
                conn_info = ConnectionInfo(
                    pid=pid,
                    process_name=self._get_process_name(pid),
                    local_addr=local_addr,
                    local_port=local_port,
                    remote_addr=remote_addr,
                    remote_port=remote_port,
                    status=conn.status if conn.status else "",
                    protocol=protocol,
                    family=family
                )
                
                pid_connections[pid].append(conn_info)
            
            # 构建进程统计
            result: Dict[int, ProcessStats] = {}
            
            for pid, conn_list in pid_connections.items():
                process_name = self._get_process_name(pid)
                process_path = self._get_process_path(pid)
                
                stats = ProcessStats(
                    pid=pid,
                    process_name=process_name,
                    process_path=process_path,
                    connections=conn_list,
                    connection_count=len(conn_list)
                )
                
                # 计算流量速率
                self._update_traffic_rate(stats, pid, current_time)
                
                result[pid] = stats
            
            return result
    
    def _get_process_name(self, pid: int) -> str:
        """获取进程名称"""
        if pid == 0:
            return "System"
        try:
            proc = psutil.Process(pid)
            return proc.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
    
    def _get_process_path(self, pid: int) -> str:
        """获取进程路径"""
        if pid == 0:
            return ""
        try:
            proc = psutil.Process(pid)
            return proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return ""
    
    def _update_traffic_rate(self, stats: ProcessStats, pid: int, current_time: float):
        """更新流量速率"""
        try:
            if pid == 0:
                return
            
            proc = psutil.Process(pid)
            io_counters = proc.io_counters()
            
            # 进程IO计数器不直接提供网络IO，我们使用系统级统计
            # 这是一个估算方法，后续可以改进
            
            # 使用上次采样数据计算速率
            if pid in self._last_net_io:
                last_sent, last_recv, last_time = self._last_net_io[pid]
                time_delta = current_time - last_time
                
                if time_delta > 0:
                    # 注意：这里使用的是总IO，不是网络IO
                    # 实际网络流量需要通过其他方式获取
                    pass
            
            # 更新缓存
            # self._last_net_io[pid] = (current_sent, current_recv, current_time)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
    
    def get_system_network_io(self) -> tuple:
        """获取系统级网络IO统计"""
        net_io = psutil.net_io_counters()
        return net_io.bytes_sent, net_io.bytes_recv
    
    def get_system_network_io_rate(self) -> tuple:
        """获取系统级网络IO速率"""
        current_time = time.time()
        current_sent, current_recv = self.get_system_network_io()
        
        last_sent, last_recv, last_time = self._last_system_net_io
        
        if last_time > 0:
            time_delta = current_time - last_time
            if time_delta > 0:
                sent_rate = (current_sent - last_sent) / time_delta
                recv_rate = (current_recv - last_recv) / time_delta
                self._last_system_net_io = (current_sent, current_recv, current_time)
                return sent_rate, recv_rate
        
        self._last_system_net_io = (current_sent, current_recv, current_time)
        return 0.0, 0.0
    
    def get_process_cpu_memory(self, pid: int) -> tuple:
        """获取进程CPU和内存使用率"""
        try:
            if pid == 0:
                return 0.0, 0.0
            proc = psutil.Process(pid)
            cpu_percent = proc.cpu_percent(interval=0.1)
            memory_percent = proc.memory_percent()
            return cpu_percent, memory_percent
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 0.0, 0.0


# 全局监控实例
_monitor_instance: Optional[NetworkMonitor] = None


def get_monitor(refresh_interval: float = 1.5) -> NetworkMonitor:
    """获取全局监控实例"""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = NetworkMonitor(refresh_interval)
    return _monitor_instance