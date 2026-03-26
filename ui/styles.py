#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
样式定义模块 - 支持暗色/亮色主题
"""

from PyQt6.QtGui import QColor, QFont
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtWidgets import QApplication
import sys
import os
import json


class ThemeColors:
    """主题颜色"""
    
    # 暗色主题
    DARK = {
        'BG_PRIMARY': '#2A2A3E',
        'BG_SECONDARY': '#23233A',
        'BG_CARD': '#3A3A5C',
        'BG_HOVER': '#4A4A6C',
        'BG_SELECTED': '#5A5A7C',
        'BG_INPUT': '#3A3A5C',
        
        'TEXT_PRIMARY': '#F0F0F0',
        'TEXT_SECONDARY': '#B8B8C8',
        'TEXT_ACCENT': '#00D4FF',
        'TEXT_DIM': '#8888A8',
        
        'BORDER': '#4A4A6C',
        'BORDER_LIGHT': '#6A6A8C',
        
        'ACCENT_BLUE': '#3B82F6',
        'ACCENT_CYAN': '#06B6D4',
        'ACCENT_PURPLE': '#8B5CF6',
        'ACCENT_PINK': '#EC4899',
        'ACCENT_GREEN': '#22C55E',
        'ACCENT_ORANGE': '#F97316',
        
        'IP_LOCAL': '#3B82F6',
        'IP_REMOTE': '#EC4899',
    }
    
    # 亮色主题 - 字体颜色加深以提高对比度
    LIGHT = {
        'BG_PRIMARY': '#F5F7FA',
        'BG_SECONDARY': '#FFFFFF',
        'BG_CARD': '#FFFFFF',
        'BG_HOVER': '#E8F0FE',
        'BG_SELECTED': '#D2E3FC',
        'BG_INPUT': '#F0F4F8',
        
        'TEXT_PRIMARY': '#1A1A2E',      # 深色主文字
        'TEXT_SECONDARY': '#4A4A5A',    # 深灰色次要文字
        'TEXT_ACCENT': '#0066CC',       # 蓝色强调
        'TEXT_DIM': '#6A6A7A',          # 中灰色
        
        'BORDER': '#E0E4E8',
        'BORDER_LIGHT': '#D0D4D8',
        
        'ACCENT_BLUE': '#2563EB',
        'ACCENT_CYAN': '#0891B2',
        'ACCENT_PURPLE': '#7C3AED',
        'ACCENT_PINK': '#DB2777',
        'ACCENT_GREEN': '#16A34A',
        'ACCENT_ORANGE': '#EA580C',
        
        'IP_LOCAL': '#2563EB',
        'IP_REMOTE': '#DB2777',
    }


# 风险等级颜色（不随主题变化）
class RiskColors:
    NORMAL = "#4ADE80"
    LOW = "#FBBF24"
    MEDIUM = "#FB923C"
    HIGH = "#F87171"
    CRITICAL = "#A855F7"


def get_colors():
    """获取当前主题的颜色字典"""
    from .styles import Colors
    if Colors._current_theme == 'light':
        return ThemeColors.LIGHT.copy()
    return ThemeColors.DARK.copy()


class Colors:
    """当前主题颜色"""
    
    _current_theme = 'dark'
    _colors = ThemeColors.DARK.copy()
    
    @classmethod
    def set_theme(cls, theme: str):
        """设置主题"""
        cls._current_theme = theme
        if theme == 'light':
            cls._colors = ThemeColors.LIGHT.copy()
        else:
            cls._colors = ThemeColors.DARK.copy()
    
    @classmethod
    def get_theme(cls) -> str:
        return cls._current_theme
    
    @classmethod
    def toggle_theme(cls) -> str:
        new_theme = 'light' if cls._current_theme == 'dark' else 'dark'
        cls.set_theme(new_theme)
        return new_theme
    
    # 直接属性访问
    @classmethod
    @property
    def BG_PRIMARY(cls): return cls._colors['BG_PRIMARY']
    
    @classmethod
    @property
    def BG_SECONDARY(cls): return cls._colors['BG_SECONDARY']
    
    @classmethod
    @property
    def BG_CARD(cls): return cls._colors['BG_CARD']
    
    @classmethod
    @property
    def BG_HOVER(cls): return cls._colors['BG_HOVER']
    
    @classmethod
    @property
    def BG_SELECTED(cls): return cls._colors['BG_SELECTED']
    
    @classmethod
    @property
    def BG_INPUT(cls): return cls._colors['BG_INPUT']
    
    @classmethod
    @property
    def TEXT_PRIMARY(cls): return cls._colors['TEXT_PRIMARY']
    
    @classmethod
    @property
    def TEXT_SECONDARY(cls): return cls._colors['TEXT_SECONDARY']
    
    @classmethod
    @property
    def TEXT_ACCENT(cls): return cls._colors['TEXT_ACCENT']
    
    @classmethod
    @property
    def TEXT_DIM(cls): return cls._colors['TEXT_DIM']
    
    @classmethod
    @property
    def BORDER(cls): return cls._colors['BORDER']
    
    @classmethod
    @property
    def BORDER_LIGHT(cls): return cls._colors['BORDER_LIGHT']
    
    @classmethod
    @property
    def ACCENT_BLUE(cls): return cls._colors['ACCENT_BLUE']
    
    @classmethod
    @property
    def ACCENT_CYAN(cls): return cls._colors['ACCENT_CYAN']
    
    @classmethod
    @property
    def ACCENT_PURPLE(cls): return cls._colors['ACCENT_PURPLE']
    
    @classmethod
    @property
    def ACCENT_PINK(cls): return cls._colors['ACCENT_PINK']
    
    @classmethod
    @property
    def ACCENT_GREEN(cls): return cls._colors['ACCENT_GREEN']
    
    @classmethod
    @property
    def ACCENT_ORANGE(cls): return cls._colors['ACCENT_ORANGE']
    
    @classmethod
    @property
    def IP_LOCAL(cls): return cls._colors['IP_LOCAL']
    
    @classmethod
    @property
    def IP_REMOTE(cls): return cls._colors['IP_REMOTE']


class Dimensions:
    """尺寸定义"""
    
    _scale_factor = 1.0
    
    @classmethod
    def init_dpi(cls):
        from PyQt6.QtWidgets import QApplication
        screen = QApplication.primaryScreen()
        if screen:
            logical_dpi = screen.logicalDotsPerInch()
            cls._scale_factor = logical_dpi / 96.0
            cls._scale_factor = max(1.0, min(cls._scale_factor, 2.5))
    
    @classmethod
    def scale(cls, value: int) -> int:
        return int(value * cls._scale_factor)
    
    WINDOW_WIDTH = 480
    WINDOW_HEIGHT = 650
    WINDOW_MIN_WIDTH = 400
    WINDOW_MIN_HEIGHT = 400
    
    MARGIN_SMALL = 4
    MARGIN_NORMAL = 8
    MARGIN_LARGE = 12
    
    BORDER_RADIUS = 14
    BORDER_RADIUS_SMALL = 10
    BORDER_RADIUS_TINY = 6
    
    SNAP_THRESHOLD = 25
    HIDE_PEEK_SIZE = 12
    
    FONT_TITLE = 18
    FONT_SUBTITLE = 14
    FONT_BODY = 12
    FONT_CAPTION = 11
    FONT_SMALL = 10


class Fonts:
    """字体定义"""
    
    _scale_factor = 1.0
    _font_family = "Microsoft YaHei UI"
    
    @classmethod
    def init(cls):
        Dimensions.init_dpi()
        cls._scale_factor = Dimensions._scale_factor
        
        if sys.platform == "darwin":
            cls._font_family = "PingFang SC"
        elif sys.platform == "linux":
            cls._font_family = "Noto Sans CJK SC"
        else:
            cls._font_family = "Microsoft YaHei UI"
    
    @classmethod
    def get_font(cls, size: int, bold: bool = False) -> QFont:
        font = QFont()
        font.setFamily(cls._font_family)
        font.setPixelSize(int(size * cls._scale_factor))
        font.setBold(bold)
        font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
        return font
    
    @classmethod
    def TITLE(cls) -> QFont:
        return cls.get_font(Dimensions.FONT_TITLE, bold=True)
    
    @classmethod
    def SUBTITLE(cls) -> QFont:
        return cls.get_font(Dimensions.FONT_SUBTITLE, bold=True)
    
    @classmethod
    def BODY(cls) -> QFont:
        return cls.get_font(Dimensions.FONT_BODY)
    
    @classmethod
    def CAPTION(cls) -> QFont:
        return cls.get_font(Dimensions.FONT_CAPTION)
    
    @classmethod
    def SMALL(cls) -> QFont:
        return cls.get_font(Dimensions.FONT_SMALL)


class StyleSheets:
    """样式表"""
    
    @staticmethod
    def get_container_style(radius: int = 14, theme: str = 'dark') -> str:
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        return f"""
            QWidget#floatContainer {{
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 {colors['BG_PRIMARY']}, stop:1 {colors['BG_SECONDARY']});
                border-radius: {radius}px;
                border: 1px solid {colors['BORDER']};
            }}
        """
    
    @staticmethod
    def get_list_item_style(theme: str = 'dark') -> str:
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        return f"""
            QFrame#listItem {{
                background: {colors['BG_CARD']};
                border-radius: 10px;
                border: 1px solid {colors['BORDER']};
            }}
            QFrame#listItem:hover {{
                background: {colors['BG_HOVER']};
                border: 1px solid {colors['BORDER_LIGHT']};
            }}
        """
    
    @staticmethod
    def get_scrollbar_style(theme: str = 'dark') -> str:
        handle_color = '#C0C4C8' if theme == 'light' else '#5A5A7C'
        handle_hover = '#A0A4A8' if theme == 'light' else '#6A6A8C'
        return f"""
            QScrollBar:vertical {{
                background: transparent;
                width: 10px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {handle_color};
                border-radius: 5px;
                min-height: 30px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {handle_hover};
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0;
            }}
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{
                background: transparent;
            }}
        """
    
    @staticmethod
    def get_menu_style(theme: str = 'dark') -> str:
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        return f"""
            QMenu {{
                background: {colors['BG_SECONDARY']};
                color: {colors['TEXT_PRIMARY']};
                border: 1px solid {colors['BORDER']};
                border-radius: 8px;
                padding: 4px;
                font-size: 11px;
            }}
            QMenu::item {{
                padding: 8px 20px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background: {colors['BG_HOVER']};
            }}
        """
    
    @staticmethod
    def get_input_style(theme: str = 'dark') -> str:
        colors = ThemeColors.LIGHT if theme == 'light' else ThemeColors.DARK
        return f"""
            QLineEdit {{
                background: {colors['BG_INPUT']};
                color: {colors['TEXT_PRIMARY']};
                border: 1px solid {colors['BORDER']};
                border-radius: 8px;
                padding: 8px 12px;
                selection-background-color: {colors['ACCENT_BLUE']};
            }}
            QLineEdit::placeholder {{
                color: {colors['TEXT_DIM']};
            }}
            QLineEdit:focus {{
                border: 1px solid {colors['ACCENT_BLUE']};
            }}
        """


def get_config_dir():
    """获取配置文件目录 - EXE同级目录下的config文件夹"""
    # 判断是否打包
    if getattr(sys, 'frozen', False):
        # 打包后：EXE同级目录
        exe_dir = os.path.dirname(sys.executable)
        return os.path.join(exe_dir, 'config')
    else:
        # 开发时：项目目录
        project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(project_dir, 'config')


class Settings:
    """用户设置管理"""
    
    DEFAULT_SETTINGS = {
        'theme': 'dark',
        'refresh_interval': 2.0,
        'sort_mode': 1,
    }
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._init()
        return cls._instance
    
    def _init(self):
        self.config_dir = get_config_dir()
        self.settings_path = os.path.join(self.config_dir, 'settings.json')
        self._settings = self.DEFAULT_SETTINGS.copy()
        self._load()
    
    def _load(self):
        os.makedirs(self.config_dir, exist_ok=True)
        if os.path.exists(self.settings_path):
            try:
                with open(self.settings_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self._settings.update(loaded)
            except:
                pass
    
    def save(self):
        os.makedirs(self.config_dir, exist_ok=True)
        with open(self.settings_path, 'w', encoding='utf-8') as f:
            json.dump(self._settings, f, indent=2)
    
    def get(self, key: str, default=None):
        return self._settings.get(key, default)
    
    def set(self, key: str, value):
        self._settings[key] = value
        self.save()


def get_settings() -> Settings:
    return Settings()