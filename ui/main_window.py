#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主窗口模块 - 优化性能，避免卡顿
"""

import sys
import platform
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QScrollArea, QFrame, QSizePolicy, QApplication, QGraphicsDropShadowEffect,
    QMenu, QLineEdit
)
from PyQt6.QtCore import (
    Qt, QTimer, QPoint, QRect, QSize, QPropertyAnimation, 
    QEasingCurve, pyqtSignal, QThread
)
from PyQt6.QtGui import QColor, QCursor, QAction

from .styles import (
    Colors, Fonts, StyleSheets, Dimensions, RiskColors,
    ThemeColors, get_settings
)
from core.monitor import get_monitor, ProcessStats, ConnectionInfo
from core.threats import (
    get_threat_database, get_threat_updater, ThreatInfo, RiskLevel
)
from utils.formatters import (
    format_rate, format_connection_status,
    get_ip_type, truncate_string, get_process_icon_name
)

# 平台检测
IS_LINUX = platform.system() == 'Linux'
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'
from utils.geoip import get_service_by_port


SORT_BY_CONNECTIONS = 1
SORT_BY_PROCESS_NAME = 2
SORT_BY_PID = 3

IS_LINUX = platform.system() == 'Linux'
IS_WINDOWS = platform.system() == 'Windows'
IS_MACOS = platform.system() == 'Darwin'


class UpdateWorker(QThread):
    """后台更新威胁库的工作线程"""
    
    # 信号：更新完成 (success: bool, message: str)
    finished = pyqtSignal(bool, str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
    
    def run(self):
        """在后台线程执行更新"""
        try:
            updater = get_threat_updater()
            success, message = updater.download_update()
            self.finished.emit(success, message)
        except Exception as e:
            self.finished.emit(False, f"更新失败: {str(e)}")


class HeaderBar(QWidget):
    """顶部标题栏"""
    
    quit_requested = pyqtSignal()
    sort_changed = pyqtSignal(int)
    refresh_interval_changed = pyqtSignal(float)
    theme_changed = pyqtSignal(str)
    update_requested = pyqtSignal()
    drag_requested = pyqtSignal(QPoint)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._sort_mode = SORT_BY_CONNECTIONS
        self._refresh_interval = 2.0
        self._has_update = False
        self._is_updating = False
        self._init_ui()
        
    def _init_ui(self):
        self.setFixedHeight(Dimensions.scale(52))
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(10)
        
        self.icon_label = QLabel("📡")
        self.icon_label.setFont(Fonts.get_font(20))
        self.icon_label.setFixedWidth(Dimensions.scale(28))
        layout.addWidget(self.icon_label)
        
        self.title_label = QLabel("NetSentry")
        self.title_label.setFont(Fonts.SUBTITLE())
        layout.addWidget(self.title_label)
        
        self.author_label = QLabel("- Designed by Fread.Z")
        self.author_label.setFont(Fonts.CAPTION())
        layout.addWidget(self.author_label)
        
        layout.addStretch()
        
        # 更新按钮 - 字体加大
        self.update_btn = QLabel("🛡 更新")
        self.update_btn.setFont(Fonts.BODY())  # 加大字体
        self.update_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.update_btn)
        
        # 刷新间隔按钮 - 字体加大
        self.refresh_btn = QLabel("⏱ 2s")
        self.refresh_btn.setFont(Fonts.BODY())  # 加大字体
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.refresh_btn)
        
        # 排序按钮 - 字体加大
        self.sort_btn = QLabel("排序")
        self.sort_btn.setFont(Fonts.BODY())  # 加大字体
        self.sort_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        layout.addWidget(self.sort_btn)
        
        # 主题切换按钮 - Linux 使用文字，Windows/Mac 使用 emoji
        if IS_LINUX:
            self._use_emoji_theme = False
            self.theme_btn = QLabel("Dark")
            self.theme_btn.setFont(Fonts.CAPTION())
        else:
            self._use_emoji_theme = True
            self.theme_btn = QLabel("🌙")
            self.theme_btn.setFont(Fonts.get_font(14))
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.setToolTip("切换主题")
        layout.addWidget(self.theme_btn)
        
        self._apply_theme_style()
    
    def _apply_theme_style(self):
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        self.title_label.setStyleSheet(f"color: {colors['TEXT_PRIMARY']}; font-weight: bold;")
        self.author_label.setStyleSheet(f"color: {colors['TEXT_DIM']};")
        
        # 按钮样式 - 加大padding
        btn_style = f"color: {colors['TEXT_SECONDARY']}; background: {colors['BG_CARD']}; padding: 6px 12px; border-radius: 8px;"
        self.refresh_btn.setStyleSheet(btn_style)
        self.sort_btn.setStyleSheet(btn_style)
        
        if not self._has_update:
            self.update_btn.setStyleSheet(btn_style)
        
        # 主题按钮文字
        if self._use_emoji_theme:
            self.theme_btn.setText("☀️" if theme == 'light' else "🌙")
        else:
            self.theme_btn.setText("Light" if theme == 'light' else "Dark")
            self.theme_btn.setStyleSheet(btn_style)
        
        if self._has_update:
            self.update_btn.setText("🛡 更新 ●")
            self.update_btn.setStyleSheet(f"""
                color: #F87171;
                background: {colors['BG_CARD']};
                padding: 6px 12px;
                border-radius: 8px;
                font-weight: bold;
            """)
    
    def set_has_update(self, has_update: bool):
        self._has_update = has_update
        self._apply_theme_style()
    
    def set_updating(self, updating: bool):
        """设置更新中状态"""
        self._is_updating = updating
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        if updating:
            self.update_btn.setText("⏳ 更新中...")
            self.update_btn.setStyleSheet(f"""
                color: #60A5FA;
                background: {colors['BG_CARD']};
                padding: 6px 12px;
                border-radius: 8px;
                font-weight: bold;
            """)
            self.update_btn.setCursor(Qt.CursorShape.BusyCursor)
        else:
            self.update_btn.setText("🛡 更新")
            self.update_btn.setStyleSheet(f"color: {colors['TEXT_SECONDARY']}; background: {colors['BG_CARD']}; padding: 6px 12px; border-radius: 8px;")
            self.update_btn.setCursor(Qt.CursorShape.PointingHandCursor)
    
    def on_theme_changed(self):
        self._apply_theme_style()
    
    def contextMenuEvent(self, event):
        menu = QMenu(self)
        menu.setStyleSheet(StyleSheets.get_menu_style(Colors.get_theme()))
        
        refresh_action = QAction("🔄 刷新", self)
        refresh_action.triggered.connect(self._on_refresh)
        menu.addAction(refresh_action)
        
        menu.addSeparator()
        
        quit_action = QAction("❌ 退出 NetSentry", self)
        quit_action.triggered.connect(self.quit_requested.emit)
        menu.addAction(quit_action)
        
        menu.exec(event.globalPos())
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            
            if self.refresh_btn.geometry().contains(pos):
                self._show_refresh_menu()
                return
            elif self.sort_btn.geometry().contains(pos):
                self._show_sort_menu()
                return
            elif self.theme_btn.geometry().contains(pos):
                self._toggle_theme()
                return
            elif self.update_btn.geometry().contains(pos):
                self.update_requested.emit()
                return
            
            self.drag_requested.emit(event.globalPosition().toPoint())
            return
        
        super().mousePressEvent(event)
    
    def _toggle_theme(self):
        new_theme = Colors.toggle_theme()
        self.theme_changed.emit(new_theme)
        self._apply_theme_style()
        get_settings().set('theme', new_theme)
    
    def _show_refresh_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(StyleSheets.get_menu_style(Colors.get_theme()))
        
        for interval in [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0]:
            action = QAction(f"{interval} 秒", self)
            action.setCheckable(True)
            action.setChecked(abs(self._refresh_interval - interval) < 0.01)
            action.triggered.connect(lambda checked, i=interval: self._set_refresh_interval(i))
            menu.addAction(action)
        
        menu.exec(self.refresh_btn.mapToGlobal(QPoint(0, self.refresh_btn.height())))
    
    def _set_refresh_interval(self, interval: float):
        self._refresh_interval = interval
        self.refresh_btn.setText(f"⏱ {interval}s")
        self.refresh_interval_changed.emit(interval)
    
    def _show_sort_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(StyleSheets.get_menu_style(Colors.get_theme()))
        
        for mode, label in [(SORT_BY_CONNECTIONS, "按连接数排序"),
                           (SORT_BY_PROCESS_NAME, "按进程名排序"),
                           (SORT_BY_PID, "按PID排序")]:
            action = QAction(label, self)
            action.setCheckable(True)
            action.setChecked(self._sort_mode == mode)
            action.triggered.connect(lambda checked, m=mode: self._set_sort(m))
            menu.addAction(action)
        
        menu.exec(self.sort_btn.mapToGlobal(QPoint(0, self.sort_btn.height())))
    
    def _set_sort(self, mode: int):
        self._sort_mode = mode
        self.sort_changed.emit(mode)
    
    def _on_refresh(self):
        parent = self.parent()
        while parent:
            if hasattr(parent, '_force_refresh'):
                parent._force_refresh()
                break
            parent = parent.parent()


class SearchBar(QWidget):
    """搜索栏"""
    
    search_changed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()
    
    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        
        self.search_icon = QLabel("🔍")
        self.search_icon.setFont(Fonts.BODY())
        self.search_icon.setFixedWidth(Dimensions.scale(24))
        layout.addWidget(self.search_icon)
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索进程名或PID...")
        self.search_input.setFont(Fonts.BODY())
        self.search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_input, 1)
        
        self.clear_btn = QLabel("✕")
        self.clear_btn.setFont(Fonts.SMALL())
        self.clear_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_btn.setVisible(False)
        self.clear_btn.mousePressEvent = lambda e: self.search_input.clear()
        layout.addWidget(self.clear_btn)
        
        self._apply_theme()
    
    def _apply_theme(self):
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        self.setStyleSheet("background: transparent;")
        self.search_icon.setStyleSheet(f"color: {colors['TEXT_DIM']};")
        self.search_input.setStyleSheet(StyleSheets.get_input_style(theme))
        self.clear_btn.setStyleSheet(f"color: {colors['TEXT_DIM']}; padding: 4px;")
    
    def on_theme_changed(self):
        self._apply_theme()
    
    def _on_search_changed(self, text: str):
        self.clear_btn.setVisible(bool(text))
        self.search_changed.emit(text)
    
    def clear(self):
        self.search_input.clear()


class ConnectionItemWidget(QFrame):
    """连接项组件"""
    
    def __init__(self, conn: ConnectionInfo, threat_info: ThreatInfo = None, parent=None):
        super().__init__(parent)
        self.conn = conn
        self.threat_info = threat_info
        self.setObjectName("listItem")
        self.setFixedHeight(Dimensions.scale(64))
        self._init_ui()
    
    def _init_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(10)
        
        self._labels = {}
        
        left_widget = QWidget()
        left_widget.setStyleSheet("background: transparent;")
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(2)
        
        self._labels['protocol'] = QLabel(f"{self.conn.protocol}")
        self._labels['protocol'].setFont(Fonts.BODY())
        left_layout.addWidget(self._labels['protocol'])
        
        self._labels['status'] = QLabel(format_connection_status(self.conn.status))
        self._labels['status'].setFont(Fonts.SMALL())
        left_layout.addWidget(self._labels['status'])
        
        layout.addWidget(left_widget)
        
        mid_widget = QWidget()
        mid_widget.setStyleSheet("background: transparent;")
        mid_layout = QVBoxLayout(mid_widget)
        mid_layout.setContentsMargins(0, 0, 0, 0)
        mid_layout.setSpacing(4)
        
        self._labels['local'] = QLabel(f"本地: {self.conn.local_port}")
        self._labels['local'].setFont(Fonts.BODY())
        mid_layout.addWidget(self._labels['local'])
        
        if self.conn.remote_addr:
            ip_type = get_ip_type(self.conn.remote_addr)
            service = get_service_by_port(self.conn.remote_port)
            remote_text = f"{self.conn.remote_addr}:{self.conn.remote_port}"
            if service:
                remote_text += f" ({service})"
            self._labels['remote'] = QLabel(remote_text)
        else:
            self._labels['remote'] = QLabel("监听中...")
        self._labels['remote'].setFont(Fonts.SMALL())
        mid_layout.addWidget(self._labels['remote'])
        
        layout.addWidget(mid_widget, 1)
        
        self._labels['type'] = QLabel("")
        self._labels['type'].setFont(Fonts.SMALL())
        layout.addWidget(self._labels['type'])
        
        self._apply_theme()
    
    def _apply_theme(self):
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        self.setStyleSheet(StyleSheets.get_list_item_style(theme))
        
        protocol_color = colors['ACCENT_CYAN'] if self.conn.protocol == "TCP" else colors['ACCENT_PURPLE']
        self._labels['protocol'].setStyleSheet(f"color: {protocol_color}; font-weight: bold;")
        
        status_color = RiskColors.NORMAL if self.conn.status == "ESTABLISHED" else "#6B7280"
        self._labels['status'].setStyleSheet(f"color: {status_color};")
        
        self._labels['local'].setStyleSheet(f"color: {colors['TEXT_PRIMARY']};")
        
        if self.conn.remote_addr:
            ip_type = get_ip_type(self.conn.remote_addr)
            remote_color = colors['IP_LOCAL'] if ip_type in ["内网", "本地"] else colors['IP_REMOTE']
            self._labels['remote'].setStyleSheet(f"color: {remote_color};")
        else:
            self._labels['remote'].setStyleSheet(f"color: {colors['TEXT_DIM']};")
        
        if self.threat_info and self.threat_info.risk_level >= RiskLevel.MEDIUM:
            self._labels['type'].setText(self.threat_info.risk_label)
            self._labels['type'].setStyleSheet(f"color: white; background: {self.threat_info.risk_color}; padding: 4px 10px; border-radius: 6px; font-weight: bold;")
        elif self.conn.remote_addr:
            ip_type = get_ip_type(self.conn.remote_addr)
            self._labels['type'].setText(ip_type)
            bg_color = colors['ACCENT_BLUE'] if ip_type in ["内网", "本地"] else colors['ACCENT_PINK']
            self._labels['type'].setStyleSheet(f"color: white; background: {bg_color}; padding: 4px 10px; border-radius: 6px; font-weight: bold;")
        else:
            self._labels['type'].setVisible(False)
    
    def on_theme_changed(self):
        self._apply_theme()


class ProcessCardWidget(QFrame):
    """进程卡片组件"""
    
    def __init__(self, stats: ProcessStats, threat_info: ThreatInfo = None, parent=None):
        super().__init__(parent)
        self.stats = stats
        self.pid = stats.pid
        self.threat_info = threat_info
        self.setObjectName("listItem")
        self._is_expanded = False
        self._show_all = False  # 是否展开显示全部连接
        self._connection_widgets = []  # 缓存连接Widget
        self._init_ui()
    
    def _init_ui(self):
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(12, 10, 12, 10)
        self.main_layout.setSpacing(8)
        
        self._labels = {}
        
        header_widget = QWidget()
        header_widget.setStyleSheet("background: transparent;")
        header_layout = QHBoxLayout(header_widget)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        
        icon_map = {"browser": "🌐", "messenger": "💬", "developer": "💻", "system": "⚙️", "game": "🎮", "default": "📦"}
        icon = icon_map.get(get_process_icon_name(self.stats.process_name), "📦")
        self.icon_label = QLabel(icon)
        self.icon_label.setFont(Fonts.get_font(18))
        self.icon_label.setFixedWidth(Dimensions.scale(26))
        header_layout.addWidget(self.icon_label)
        
        info_widget = QWidget()
        info_widget.setStyleSheet("background: transparent;")
        info_layout = QVBoxLayout(info_widget)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(2)
        
        self._labels['name'] = QLabel(truncate_string(self.stats.process_name, 30))
        self._labels['name'].setFont(Fonts.BODY())
        info_layout.addWidget(self._labels['name'])
        
        self._labels['detail'] = QLabel(f"PID: {self.stats.pid}  |  {self.stats.connection_count} 个连接")
        self._labels['detail'].setFont(Fonts.SMALL())
        info_layout.addWidget(self._labels['detail'])
        
        header_layout.addWidget(info_widget, 1)
        
        self._labels['risk'] = QLabel("")
        self._labels['risk'].setFont(Fonts.SMALL())
        header_layout.addWidget(self._labels['risk'])
        
        self._labels['count'] = QLabel(str(self.stats.connection_count))
        self._labels['count'].setFont(Fonts.BODY())
        header_layout.addWidget(self._labels['count'])
        
        self._labels['expand'] = QLabel("▼")
        self._labels['expand'].setFont(Fonts.SMALL())
        header_layout.addWidget(self._labels['expand'])
        
        self.main_layout.addWidget(header_widget)
        
        self.connections_widget = QWidget()
        self.connections_widget.setStyleSheet("background: transparent;")
        self.connections_layout = QVBoxLayout(self.connections_widget)
        self.connections_layout.setContentsMargins(24, 0, 0, 0)
        self.connections_layout.setSpacing(4)
        
        self.connections_widget.setVisible(False)
        self.main_layout.addWidget(self.connections_widget)
        
        header_widget.setCursor(Qt.CursorShape.PointingHandCursor)
        header_widget.mousePressEvent = self._toggle_expand
        
        # 启用右键菜单
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        
        self._apply_theme()
    
    def _apply_theme(self):
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        self.setStyleSheet(StyleSheets.get_list_item_style(theme))
        
        self._labels['name'].setStyleSheet(f"color: {colors['TEXT_PRIMARY']}; font-weight: bold;")
        self._labels['detail'].setStyleSheet(f"color: {colors['TEXT_SECONDARY']};")
        
        if self.threat_info:
            self._labels['risk'].setText(self.threat_info.risk_label)
            self._labels['risk'].setStyleSheet(f"color: white; background: {self.threat_info.risk_color}; padding: 4px 12px; border-radius: 12px; font-weight: bold;")
        else:
            self._labels['risk'].setVisible(False)
        
        self._labels['count'].setStyleSheet(f"color: white; background: {colors['ACCENT_BLUE']}; padding: 4px 12px; border-radius: 12px; font-weight: bold;")
        self._labels['expand'].setStyleSheet(f"color: {colors['TEXT_DIM']};")
    
    def on_theme_changed(self):
        self._apply_theme()
        for widget in self._connection_widgets:
            if hasattr(widget, 'on_theme_changed'):
                widget.on_theme_changed()
        self._apply_more_label_style()
    
    def _show_context_menu(self, pos):
        """显示右键菜单"""
        menu = QMenu(self)
        menu.setStyleSheet(StyleSheets.get_menu_style(Colors.get_theme()))
        
        # 打开文件所在位置
        open_folder_action = QAction("📂 打开文件所在位置", self)
        open_folder_action.triggered.connect(self._open_file_location)
        menu.addAction(open_folder_action)
        
        # 复制进程名
        copy_name_action = QAction("📋 复制进程名", self)
        copy_name_action.triggered.connect(self._copy_process_name)
        menu.addAction(copy_name_action)
        
        menu.addSeparator()
        
        # 查看进程详情
        info_action = QAction(f"ℹ️ PID: {self.stats.pid}", self)
        info_action.setEnabled(False)
        menu.addAction(info_action)
        
        # 路径信息
        if self.stats.process_path:
            path_action = QAction(f"📁 {truncate_string(self.stats.process_path, 50)}", self)
            path_action.setEnabled(False)
            menu.addAction(path_action)
        
        menu.exec(self.mapToGlobal(pos))
    
    def _open_file_location(self):
        """打开文件所在位置并选中文件"""
        if not self.stats.process_path:
            return
        
        import subprocess
        import os
        
        path = self.stats.process_path
        if os.path.exists(path):
            # 使用 explorer /select 打开并选中文件
            subprocess.run(['explorer', '/select,', path])
    
    def _copy_process_name(self):
        """复制进程名到剪贴板"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.stats.process_name)
    
    def _toggle_expand(self, event):
        # 只响应左键点击，右键交给 contextMenu 处理
        if event.button() != Qt.MouseButton.LeftButton:
            return
        
        self._is_expanded = not self._is_expanded
        self.connections_widget.setVisible(self._is_expanded)
        self._labels['expand'].setText("▲" if self._is_expanded else "▼")
        
        if self._is_expanded:
            # 展开时立即更新连接列表
            if self.stats:
                self.update_connections(self.stats)
        else:
            # 收起时重置展开全部状态
            self._show_all = False
    
    def set_expanded(self, expanded: bool):
        self._is_expanded = expanded
        self.connections_widget.setVisible(expanded)
        self._labels['expand'].setText("▲" if expanded else "▼")
        
        if expanded:
            if self.stats:
                self.update_connections(self.stats)
        else:
            # 收起时重置展开全部状态
            self._show_all = False
    
    def update_data(self, stats: ProcessStats, threat_info: ThreatInfo = None):
        """更新数据 - 只更新文字，不重建Widget"""
        self.stats = stats
        self.threat_info = threat_info
        
        # 更新标签文字
        self._labels['name'].setText(truncate_string(self.stats.process_name, 30))
        self._labels['detail'].setText(f"PID: {self.stats.pid}  |  {self.stats.connection_count} 个连接")
        self._labels['count'].setText(str(self.stats.connection_count))
        
        # 更新风险标签
        if self.threat_info:
            self._labels['risk'].setText(self.threat_info.risk_label)
            self._labels['risk'].setStyleSheet(f"color: white; background: {self.threat_info.risk_color}; padding: 4px 12px; border-radius: 12px; font-weight: bold;")
            self._labels['risk'].setVisible(True)
        else:
            self._labels['risk'].setVisible(False)
    
    def update_connections(self, stats: ProcessStats):
        """更新连接列表 - 增量更新"""
        self.stats = stats
        threat_db = get_threat_database()
        
        # 只在展开状态下才更新连接详情
        if not self._is_expanded:
            return
        
        # 根据展开状态决定显示数量
        if self._show_all:
            display_conns = stats.connections  # 显示全部
        else:
            display_conns = stats.connections[:20]  # 最多显示20个
        
        # 复用现有Widget或创建新的
        while len(self._connection_widgets) > len(display_conns):
            widget = self._connection_widgets.pop()
            widget.setVisible(False)
        
        for i, conn in enumerate(display_conns):
            conn_threat = None
            if threat_db and conn.remote_addr:
                conn_threat = threat_db.analyze_connection(conn.remote_addr, conn.remote_port, self.stats.process_name)
            
            if i < len(self._connection_widgets):
                # 复用现有Widget
                widget = self._connection_widgets[i]
                widget.conn = conn
                widget.threat_info = conn_threat
                widget._apply_theme()
                widget.setVisible(True)
            else:
                # 创建新Widget
                widget = ConnectionItemWidget(conn, conn_threat)
                self._connection_widgets.append(widget)
                self.connections_layout.addWidget(widget)
        
        # 处理"更多"标签 - 只在未展开全部时显示
        if not self._show_all and len(stats.connections) > 20:
            if not hasattr(self, '_more_label'):
                self._more_label = QLabel(f"... 还有 {len(stats.connections) - 20} 个连接 ▼")
                self._more_label.setFont(Fonts.SMALL())
                self._more_label.setCursor(Qt.CursorShape.PointingHandCursor)
                # 绑定点击事件
                self._more_label.mousePressEvent = lambda e: self._expand_all_connections()
                self.connections_layout.addWidget(self._more_label)
                self._apply_more_label_style()
            self._more_label.setText(f"... 还有 {len(stats.connections) - 20} 个连接 ▼")
            self._more_label.setVisible(True)
        elif hasattr(self, '_more_label'):
            self._more_label.setVisible(False)
    
    def _apply_more_label_style(self):
        """应用'更多'标签样式"""
        if not hasattr(self, '_more_label'):
            return
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        # 白色主题用深色文字，暗色主题用浅色文字
        text_color = colors['TEXT_SECONDARY'] if theme == 'light' else '#FFFFFF'
        self._more_label.setStyleSheet(f"color: {text_color}; padding: 4px;")
    
    def _expand_all_connections(self):
        """展开显示所有连接 - 设置状态后刷新会保持"""
        self._show_all = True
        # 重新调用更新方法显示全部
        if self.stats:
            self.update_connections(self.stats)


class MainContent(QWidget):
    """主内容区域"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("content")
        self._sort_mode = SORT_BY_CONNECTIONS
        self._refresh_interval = 2000
        self._search_text = ""
        
        self.monitor = get_monitor()
        self.threat_db = get_threat_database()
        self._card_cache = {}
        self._all_process_stats = {}
        
        self._init_ui()
        
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._refresh_data)
        self.refresh_timer.start(self._refresh_interval)
        
        self._apply_theme()
    
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 12)
        layout.setSpacing(10)
        
        self.search_bar = SearchBar()
        self.search_bar.search_changed.connect(self._on_search_changed)
        layout.addWidget(self.search_bar)
        
        self._create_stats_bar(layout)
        
        self.separator = QFrame()
        self.separator.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(self.separator)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.scroll_area = scroll
        layout.addWidget(scroll, 1)
        
        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background: transparent;")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 6, 0)
        self.scroll_layout.setSpacing(6)
        self.scroll_layout.addStretch()
        
        scroll.setWidget(self.scroll_content)
        
        self._create_bottom(layout)
    
    def _apply_theme(self):
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        self.separator.setStyleSheet(f"background: {colors['BORDER']}; max-height: 1px;")
        self.scroll_area.setStyleSheet(f"QScrollArea {{ background: transparent; border: none; }}{StyleSheets.get_scrollbar_style(theme)}")
        
        if hasattr(self, '_stats_labels'):
            self._stats_labels['upload_title'].setStyleSheet(f"color: {colors['TEXT_SECONDARY']};")
            self._stats_labels['upload_value'].setStyleSheet(f"color: {colors['ACCENT_CYAN']}; font-weight: bold;")
            self._stats_labels['download_title'].setStyleSheet(f"color: {colors['TEXT_SECONDARY']};")
            self._stats_labels['download_value'].setStyleSheet(f"color: {colors['ACCENT_PINK']}; font-weight: bold;")
            self._stats_labels['process_title'].setStyleSheet(f"color: {colors['TEXT_SECONDARY']};")
            self._stats_labels['process_value'].setStyleSheet(f"color: {colors['TEXT_ACCENT']}; font-weight: bold;")
            self._stats_labels['version_title'].setStyleSheet(f"color: {colors['TEXT_SECONDARY']};")
            self._stats_labels['version_value'].setStyleSheet(f"color: {colors['TEXT_DIM']};")
    
    def on_theme_changed(self):
        self._apply_theme()
        self.search_bar.on_theme_changed()
        for card in self._card_cache.values():
            card.on_theme_changed()
    
    def _create_stats_bar(self, parent_layout):
        self._stats_labels = {}
        
        stats_widget = QWidget()
        stats_widget.setStyleSheet("background: transparent;")
        stats_layout = QHBoxLayout(stats_widget)
        stats_layout.setContentsMargins(4, 4, 4, 4)
        stats_layout.setSpacing(20)
        
        # 上传
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(2)
        self._stats_labels['upload_title'] = QLabel("↑ 上传")
        self._stats_labels['upload_title'].setFont(Fonts.CAPTION())
        l.addWidget(self._stats_labels['upload_title'])
        self._stats_labels['upload_value'] = QLabel("0 B/s")
        self._stats_labels['upload_value'].setFont(Fonts.SUBTITLE())
        l.addWidget(self._stats_labels['upload_value'])
        stats_layout.addWidget(w)
        
        # 下载
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(2)
        self._stats_labels['download_title'] = QLabel("↓ 下载")
        self._stats_labels['download_title'].setFont(Fonts.CAPTION())
        l.addWidget(self._stats_labels['download_title'])
        self._stats_labels['download_value'] = QLabel("0 B/s")
        self._stats_labels['download_value'].setFont(Fonts.SUBTITLE())
        l.addWidget(self._stats_labels['download_value'])
        stats_layout.addWidget(w)
        
        # 进程数
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(2)
        self._stats_labels['process_title'] = QLabel("活动进程")
        self._stats_labels['process_title'].setFont(Fonts.CAPTION())
        l.addWidget(self._stats_labels['process_title'])
        self._stats_labels['process_value'] = QLabel("0")
        self._stats_labels['process_value'].setFont(Fonts.SUBTITLE())
        l.addWidget(self._stats_labels['process_value'])
        stats_layout.addWidget(w)
        stats_layout.addStretch()
        
        # 威胁库版本
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        l = QVBoxLayout(w)
        l.setContentsMargins(0, 0, 0, 0)
        l.setSpacing(2)
        self._stats_labels['version_title'] = QLabel("威胁库")
        self._stats_labels['version_title'].setFont(Fonts.CAPTION())
        l.addWidget(self._stats_labels['version_title'])
        self._stats_labels['version_value'] = QLabel(self.threat_db.get_version())
        self._stats_labels['version_value'].setFont(Fonts.SMALL())
        l.addWidget(self._stats_labels['version_value'])
        stats_layout.addWidget(w)
        
        parent_layout.addWidget(stats_widget)
    
    def _create_bottom(self, parent_layout):
        bottom_widget = QWidget()
        bottom_widget.setStyleSheet("background: transparent;")
        bottom_layout = QHBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(8, 8, 8, 4)
        
        self.refresh_btn = QLabel("🔄 刷新")
        self.refresh_btn.setFont(Fonts.CAPTION())
        self.refresh_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.refresh_btn.mousePressEvent = lambda e: self._refresh_data()
        bottom_layout.addWidget(self.refresh_btn)
        
        bottom_layout.addStretch()
        
        # 作者标签 - 带渐变色呼吸效果
        self.bottom_author_label = QLabel("Designed by Fread.Z")
        self.bottom_author_label.setFont(Fonts.BODY())
        self.bottom_author_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bottom_layout.addWidget(self.bottom_author_label)
        
        bottom_layout.addStretch()
        
        self.version_label = QLabel("NetSentry v1.7.1")
        self.version_label.setFont(Fonts.SMALL())
        bottom_layout.addWidget(self.version_label)
        
        parent_layout.addWidget(bottom_widget)
        
        # 作者标签呼吸动画
        self._anim_step = 0
        self._author_timer = QTimer(self)
        self._author_timer.timeout.connect(self._animate_author_label)
        self._author_timer.start(50)  # 50ms 更新一次
    
    def _animate_author_label(self):
        """作者标签呼吸动画效果 - 颜色渐变"""
        import math
        
        # 在 0 到 2π 之间循环
        self._anim_step += 0.05
        t = (math.sin(self._anim_step) + 1) / 2  # 0 到 1
        
        # 渐变色：从青色(#06B6D4)到紫色(#8B5CF6)
        r = int(6 + t * (139 - 6))
        g = int(182 - t * (182 - 92))
        b = int(212 - t * (212 - 246))
        
        color = f"#{r:02X}{g:02X}{b:02X}"
        
        self.bottom_author_label.setStyleSheet(f"""
            QLabel {{
                color: {color};
                padding: 2px 8px;
                font-weight: bold;
            }}
        """)
    
    def set_sort_mode(self, mode: int):
        self._sort_mode = mode
        self._needs_resort = True
        self._refresh_data()
    
    def set_refresh_interval(self, seconds: float):
        self._refresh_interval = int(seconds * 1000)
        self.refresh_timer.setInterval(self._refresh_interval)
    
    def _on_search_changed(self, text: str):
        self._search_text = text.lower().strip()
        self._needs_resort = True
        self._refresh_data()
    
    def _matches_search(self, stats: ProcessStats) -> bool:
        if not self._search_text:
            return True
        return self._search_text in stats.process_name.lower() or self._search_text == str(stats.pid)
    
    def _refresh_data(self):
        """刷新数据 - 优化性能，避免重建UI"""
        # 获取数据
        process_stats = self.monitor.get_connections()
        self._all_process_stats = {p.pid: p for p in process_stats.values()}
        
        # 更新统计数字
        total_connections = sum(p.connection_count for p in process_stats.values())
        sent_rate, recv_rate = self.monitor.get_system_network_io_rate()
        
        self._stats_labels['upload_value'].setText(format_rate(sent_rate))
        self._stats_labels['download_value'].setText(format_rate(recv_rate))
        
        if self._search_text:
            matched_count = sum(1 for s in process_stats.values() if self._matches_search(s))
            self._stats_labels['process_value'].setText(f"{matched_count}/{len(process_stats)}")
        else:
            self._stats_labels['process_value'].setText(str(len(process_stats)))
        
        self._stats_labels['version_value'].setText(self.threat_db.get_version())
        
        # 保存展开状态
        expanded_pids = {pid for pid, card in self._card_cache.items() if card._is_expanded}
        
        # 删除已消失的进程卡片
        for pid in list(self._card_cache.keys()):
            if pid not in process_stats:
                card = self._card_cache.pop(pid)
                card.setVisible(False)
                card.deleteLater()
        
        # 更新或创建卡片
        for pid, stats in process_stats.items():
            # 使用综合风险分析：进程风险 + 连接风险
            threat_info = self.threat_db.analyze_process_with_connections(
                stats.process_name, stats.connections, pid
            )
            
            if pid in self._card_cache:
                # 更新现有卡片
                card = self._card_cache[pid]
                card.update_data(stats, threat_info)
                if pid in expanded_pids:
                    card.update_connections(stats)
                card.setVisible(self._matches_search(stats))
            else:
                # 创建新卡片
                card = ProcessCardWidget(stats, threat_info)
                self._card_cache[pid] = card
        
        # 排序并重新排列
        filtered_stats = [s for s in process_stats.values() if self._matches_search(s)]
        
        if self._sort_mode == SORT_BY_CONNECTIONS:
            filtered_stats.sort(key=lambda p: p.connection_count, reverse=True)
        elif self._sort_mode == SORT_BY_PROCESS_NAME:
            filtered_stats.sort(key=lambda p: p.process_name.lower())
        else:
            filtered_stats.sort(key=lambda p: p.pid)
        
        # 按顺序重新插入布局（只移动位置，不重建）
        for idx, stats in enumerate(filtered_stats[:50]):
            card = self._card_cache.get(stats.pid)
            if card:
                self.scroll_layout.insertWidget(idx, card)
        
        # 更新底部样式
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        self.refresh_btn.setStyleSheet(f"color: {colors['TEXT_SECONDARY']}; padding: 6px 14px; border-radius: 6px; background: {colors['BG_CARD']};")
        self.version_label.setStyleSheet(f"color: {colors['TEXT_DIM']};")


class NetSentryWindow(QMainWindow):
    """主窗口"""
    
    SNAP_NONE, SNAP_LEFT, SNAP_RIGHT, SNAP_TOP, SNAP_BOTTOM = 0, 1, 2, 3, 4
    RESIZE_MARGIN = 10
    
    def __init__(self):
        super().__init__()
        
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool)
        
        self._is_hidden = False
        self._snap_direction = self.SNAP_NONE
        self._drag_position = None
        self._is_resizing = False
        self._resize_edge = None
        self._resize_start_pos = None
        self._resize_start_geometry = None
        
        Fonts.init()
        Colors.set_theme(get_settings().get('theme', 'dark'))
        
        self._min_size = QSize(Dimensions.scale(Dimensions.WINDOW_MIN_WIDTH), Dimensions.scale(Dimensions.WINDOW_MIN_HEIGHT))
        self.setMinimumSize(self._min_size)
        
        self._init_ui()
        self._setup_position()
        self._check_for_updates()
    
    def _init_ui(self):
        self.container = QWidget()
        self.container.setObjectName("floatContainer")
        self.setCentralWidget(self.container)
        
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(25)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 5)
        self.container.setGraphicsEffect(shadow)
        
        self.main_layout = QVBoxLayout(self.container)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        
        self.header_bar = HeaderBar()
        self.header_bar.quit_requested.connect(self._quit_app)
        self.header_bar.sort_changed.connect(self._on_sort_changed)
        self.header_bar.refresh_interval_changed.connect(self._on_refresh_interval_changed)
        self.header_bar.theme_changed.connect(self._on_theme_changed)
        self.header_bar.update_requested.connect(self._on_update_requested)
        self.header_bar.drag_requested.connect(self._start_window_drag)
        self.main_layout.addWidget(self.header_bar)
        
        self.main_content = MainContent()
        self.main_layout.addWidget(self.main_content, 1)
        
        self.resize(Dimensions.scale(Dimensions.WINDOW_WIDTH), Dimensions.scale(Dimensions.WINDOW_HEIGHT))
        self._apply_theme()
    
    def _apply_theme(self):
        self.container.setStyleSheet(StyleSheets.get_container_style(Dimensions.scale(Dimensions.BORDER_RADIUS), Colors.get_theme()))
        self.header_bar.on_theme_changed()
        self.main_content.on_theme_changed()
    
    def _on_theme_changed(self, theme: str):
        self._apply_theme()
    
    def _on_update_requested(self):
        """异步更新威胁库"""
        # 防止重复点击
        if hasattr(self, '_update_worker') and self._update_worker is not None and self._update_worker.isRunning():
            return
        
        # 显示更新中状态
        self.header_bar.set_updating(True)
        
        # 创建并启动工作线程
        self._update_worker = UpdateWorker()
        self._update_worker.finished.connect(self._on_update_finished)
        self._update_worker.start()
    
    def _on_update_finished(self, success: bool, message: str):
        """更新完成回调"""
        self.header_bar.set_updating(False)
        
        if success:
            self.header_bar.set_has_update(False)
            self.main_content._refresh_data()
            self._show_toast("✅ " + message, success=True)
        else:
            self._show_toast("❌ " + message, success=False)
        
        print(f"更新结果: {message}")
    
    def _show_toast(self, message: str, success: bool = True):
        """显示提示消息"""
        toast = QLabel(message, self)
        toast.setObjectName("toast")
        
        theme = Colors.get_theme()
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        
        toast.setStyleSheet(f"""
            QLabel#toast {{
                color: white;
                background: {'#22C55E' if success else '#EF4444'};
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: bold;
            }}
        """)
        toast.setFont(Fonts.BODY())
        toast.adjustSize()
        
        # 定位在窗口顶部中央
        x = (self.width() - toast.width()) // 2
        y = self.header_bar.height() + 10
        toast.move(x, y)
        toast.show()
        toast.raise_()
        
        # 3秒后自动消失
        QTimer.singleShot(3000, toast.deleteLater)
    
    def _check_for_updates(self):
        def check():
            has_update, version, error = get_threat_updater().check_update()
            if has_update:
                self.header_bar.set_has_update(True)
        QTimer.singleShot(2000, check)
    
    def _setup_position(self):
        screen = QApplication.primaryScreen().availableGeometry()
        self.move(screen.width() - self.width() - 30, 30)
    
    def _on_sort_changed(self, mode: int): self.main_content.set_sort_mode(mode)
    def _on_refresh_interval_changed(self, seconds: float): self.main_content.set_refresh_interval(seconds)
    def _force_refresh(self): self.main_content._refresh_data()
    def _quit_app(self): QApplication.quit()
    
    def _start_window_drag(self, global_pos: QPoint):
        self._unhide()
        handle = self.windowHandle()
        
        # Linux/Wayland handles frameless window dragging more reliably through
        # Qt's native move request than by manually calling move() on mouse move.
        if IS_LINUX and handle and handle.startSystemMove():
            self._drag_position = None
            return
        
        self._drag_position = global_pos - self.frameGeometry().topLeft()
    
    def _get_resize_edge(self, pos: QPoint) -> str:
        m, r = self.RESIZE_MARGIN, self.rect()
        edges = (['left'] if pos.x() <= m else (['right'] if pos.x() >= r.width() - m else [])) + \
                (['top'] if pos.y() <= m else (['bottom'] if pos.y() >= r.height() - m else []))
        return '-'.join(edges)
    
    def _get_cursor_for_edge(self, edge: str) -> Qt.CursorShape:
        return {'left': Qt.CursorShape.SizeHorCursor, 'right': Qt.CursorShape.SizeHorCursor,
                'top': Qt.CursorShape.SizeVerCursor, 'bottom': Qt.CursorShape.SizeVerCursor,
                'top-left': Qt.CursorShape.SizeFDiagCursor, 'top-right': Qt.CursorShape.SizeBDiagCursor,
                'bottom-left': Qt.CursorShape.SizeBDiagCursor, 'bottom-right': Qt.CursorShape.SizeFDiagCursor}.get(edge, Qt.CursorShape.ArrowCursor)
    
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            pos = event.position().toPoint()
            edge = self._get_resize_edge(pos)
            
            # Linux 特殊处理：使用系统级窗口操作
            if IS_LINUX and edge:
                wh = self.windowHandle()
                if wh:
                    edge_flags = Qt.Edge(0)
                    if 'left' in edge:
                        edge_flags |= Qt.Edge.LeftEdge
                    if 'right' in edge:
                        edge_flags |= Qt.Edge.RightEdge
                    if 'top' in edge:
                        edge_flags |= Qt.Edge.TopEdge
                    if 'bottom' in edge:
                        edge_flags |= Qt.Edge.BottomEdge
                    if edge_flags:
                        wh.startSystemResize(edge_flags)
                        return
            
            if IS_LINUX and pos.y() <= self.header_bar.height():
                wh = self.windowHandle()
                if wh:
                    wh.startSystemMove()
                    self._unhide()
                    return
            
            # Windows/macOS 原有逻辑
            if edge:
                self._is_resizing = True
                self._resize_edge = edge
                self._resize_start_pos = event.globalPosition().toPoint()
                self._resize_start_geometry = self.geometry()
                return
            if pos.y() <= self.header_bar.height():
                self._drag_position = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
                self._unhide()
                return
        super().mousePressEvent(event)
    
    def mouseMoveEvent(self, event):
        pos = event.position().toPoint()
        
        # Linux 上系统处理移动和调整大小，只需要设置光标
        if IS_LINUX:
            edge = self._get_resize_edge(pos)
            if edge:
                self.setCursor(self._get_cursor_for_edge(edge))
            else:
                self.setCursor(Qt.CursorShape.ArrowCursor)
            return
        
        # Windows/macOS 使用原有逻辑
        if self._is_resizing:
            delta = event.globalPosition().toPoint() - self._resize_start_pos
            geo = self._resize_start_geometry
            new = {'left': geo.left() + delta.x() if 'left' in self._resize_edge else geo.left(),
                   'top': geo.top() + delta.y() if 'top' in self._resize_edge else geo.top(),
                   'right': geo.right() + delta.x() if 'right' in self._resize_edge else geo.right(),
                   'bottom': geo.bottom() + delta.y() if 'bottom' in self._resize_edge else geo.bottom()}
            w, h = new['right'] - new['left'], new['bottom'] - new['top']
            if w >= self._min_size.width() and h >= self._min_size.height():
                self.setGeometry(new['left'], new['top'], w, h)
            return
        self.setCursor(self._get_cursor_for_edge(self._get_resize_edge(pos)) if self._get_resize_edge(pos) else Qt.CursorShape.ArrowCursor)
        if self._drag_position:
            self.move(event.globalPosition().toPoint() - self._drag_position)
            return
        super().mouseMoveEvent(event)
    
    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            if self._is_resizing:
                self._is_resizing, self._resize_edge, self._resize_start_pos, self._resize_start_geometry = False, None, None, None
            elif self._drag_position:
                self._snap_direction = self._check_snap(self.pos())
                if self._snap_direction != self.SNAP_NONE:
                    self._apply_snap_hide(self._snap_direction)
            self._drag_position = None
        super().mouseReleaseEvent(event)
    
    def leaveEvent(self, event):
        self.setCursor(Qt.CursorShape.ArrowCursor)
        if self._snap_direction != self.SNAP_NONE and not self._is_hidden:
            QTimer.singleShot(500, self._check_auto_hide)
        super().leaveEvent(event)
    
    def enterEvent(self, event):
        self._unhide()
        super().enterEvent(event)
    
    def _check_snap(self, pos: QPoint) -> int:
        screen = QApplication.primaryScreen().availableGeometry()
        t = Dimensions.scale(Dimensions.SNAP_THRESHOLD)
        return self.SNAP_LEFT if pos.x() <= t else self.SNAP_RIGHT if pos.x() + self.width() >= screen.width() - t else self.SNAP_TOP if pos.y() <= t else self.SNAP_BOTTOM if pos.y() + self.height() >= screen.height() - t else self.SNAP_NONE
    
    def _apply_snap_hide(self, direction: int):
        screen = QApplication.primaryScreen().availableGeometry()
        peek = Dimensions.scale(Dimensions.HIDE_PEEK_SIZE)
        moves = {self.SNAP_LEFT: (-self.width() + peek, self.y()), self.SNAP_RIGHT: (screen.width() - peek, self.y()),
                 self.SNAP_TOP: (self.x(), -self.height() + peek), self.SNAP_BOTTOM: (self.x(), screen.height() - peek)}
        self.move(*moves.get(direction, (self.x(), self.y())))
        self._is_hidden = True
    
    def _unhide(self):
        if not self._is_hidden: return
        screen = QApplication.primaryScreen().availableGeometry()
        moves = {self.SNAP_LEFT: (0, self.y()), self.SNAP_RIGHT: (screen.width() - self.width(), self.y()),
                 self.SNAP_TOP: (self.x(), 0), self.SNAP_BOTTOM: (self.x(), screen.height() - self.height())}
        self.move(*moves.get(self._snap_direction, (self.x(), self.y())))
        self._is_hidden = False
    
    def _check_auto_hide(self):
        if self._snap_direction != self.SNAP_NONE and not self.underMouse():
            self._apply_snap_hide(self._snap_direction)
