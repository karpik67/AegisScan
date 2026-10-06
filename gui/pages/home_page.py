"""Главная страница."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QCheckBox
)
from PyQt6.QtCore import Qt, pyqtSignal


CARD_QSS = """
QFrame#statCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
    border-radius: 12px;
}
QFrame#statCard:hover {
    border: 1px solid #89b4fa;
}
"""

INFO_CARD_QSS = """
QFrame#infoCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
    border-radius: 12px;
}
"""

# Стиль для активной защиты (зелёный)
PROTECT_ON_QSS = """
QFrame#protectCard {
    background-color: #1e3a2f;
    border: 2px solid #28a745;
    border-radius: 12px;
}
"""

# Стиль для выключенной защиты (красный)
PROTECT_OFF_QSS = """
QFrame#protectCard {
    background-color: #3a1e1e;
    border: 2px solid #dc3545;
    border-radius: 12px;
}
"""

CARD_TITLE_QSS = "color: #a6adc8; font-size: 12px; font-weight: 600;"
CARD_VALUE_QSS = "color: #89b4fa; font-size: 34px; font-weight: bold;"
CARD_SUBTITLE_QSS = "color: #7f849c; font-size: 12px;"


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", subtitle: str = ""):
        super().__init__()
        self.setObjectName("statCard")
        self.setStyleSheet(CARD_QSS)
        self.setMinimumHeight(120)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(6)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(CARD_TITLE_QSS)
        layout.addWidget(lbl_title)

        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet(CARD_VALUE_QSS)
        layout.addWidget(self.lbl_value)

        self.lbl_subtitle = QLabel(subtitle)
        self.lbl_subtitle.setStyleSheet(CARD_SUBTITLE_QSS)
        layout.addWidget(self.lbl_subtitle)

        layout.addStretch()

    def set_value(self, value: str):
        self.lbl_value.setText(value)


class ProtectionStatusCard(QFrame):
    """Карточка статуса резидентной защиты."""
    toggled = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setObjectName("protectCard")
        self.setMinimumHeight(100)
        self._enabled = True

        layout = QHBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(20)

        self.icon = QLabel("🛡")
        self.icon.setStyleSheet("font-size: 44px; background: transparent;")
        self.icon.setFixedWidth(60)
        layout.addWidget(self.icon)

        info = QVBoxLayout()
        info.setSpacing(4)

        self.title = QLabel("ЗАЩИТА В РЕАЛЬНОМ ВРЕМЕНИ")
        self.title.setStyleSheet(
            "color: white; font-size: 13px; font-weight: 600; "
            "background: transparent;"
        )
        info.addWidget(self.title)

        self.subtitle = QLabel("Активна — файлы проверяются автоматически")
        self.subtitle.setStyleSheet(
            "color: rgba(255,255,255,0.8); font-size: 13px; "
            "background: transparent;"
        )
        info.addWidget(self.subtitle)

        layout.addLayout(info, 1)

        self.toggle = QCheckBox()
        self.toggle.setChecked(True)
        self.toggle.setCursor(Qt.CursorShape.PointingHandCursor)
        self.toggle.setStyleSheet("""
            QCheckBox {
                background: transparent;
                spacing: 0;
            }
            QCheckBox::indicator {
                width: 46px;
                height: 24px;
                border-radius: 12px;
                background-color: rgba(255,255,255,0.25);
                border: 2px solid rgba(255,255,255,0.4);
            }
            QCheckBox::indicator:checked {
                background-color: #89b4fa;
                border: 2px solid #89b4fa;
            }
        """)
        self.toggle.toggled.connect(self._on_toggle)
        layout.addWidget(self.toggle)

        # Изначально — включено, зелёный стиль
        self.setStyleSheet(PROTECT_ON_QSS)

    def _on_toggle(self, checked: bool):
        self._enabled = checked
        if checked:
            self.setStyleSheet(PROTECT_ON_QSS)
            self.icon.setText("🛡")
            self.subtitle.setText("Активна — файлы проверяются автоматически")
        else:
            self.setStyleSheet(PROTECT_OFF_QSS)
            self.icon.setText("⚠️")
            self.subtitle.setText("Отключена — файлы не проверяются автоматически")
        self.toggled.emit(checked)

    def set_state(self, enabled: bool):
        """Программная установка состояния (без сигнала toggled)."""
        self.toggle.blockSignals(True)
        self.toggle.setChecked(enabled)
        self.toggle.blockSignals(False)
        self._enabled = enabled
        if enabled:
            self.setStyleSheet(PROTECT_ON_QSS)
            self.icon.setText("🛡")
            self.subtitle.setText("Активна — файлы проверяются автоматически")
        else:
            self.setStyleSheet(PROTECT_OFF_QSS)
            self.icon.setText("⚠️")
            self.subtitle.setText("Отключена — файлы не проверяются автоматически")


class HomePage(QWidget):
    scan_requested = pyqtSignal()
    protection_toggled = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Заголовок
        title = QLabel("Добро пожаловать в AegisScan")
        title.setStyleSheet(
            "font-size: 26px; font-weight: bold; color: #cdd6f4;"
        )
        layout.addWidget(title)

        subtitle = QLabel("Ваш персональный антивирус с искусственным интеллектом")
        subtitle.setStyleSheet("color: #7f849c; font-size: 13px;")
        layout.addWidget(subtitle)

        # Резидентная защита
        self.protect_card = ProtectionStatusCard()
        self.protect_card.toggled.connect(self.protection_toggled.emit)
        layout.addWidget(self.protect_card)

        # Кнопка проверки
        self.btn_scan = QPushButton("🔍  ПРОВЕРИТЬ ФАЙЛ")
        self.btn_scan.setObjectName("primaryButton")
        self.btn_scan.setMinimumHeight(70)
        self.btn_scan.clicked.connect(self.scan_requested.emit)
        layout.addWidget(self.btn_scan)

        # Карточки статистики
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(15)

        self.card_scanned = StatCard("ПРОВЕРЕНО ФАЙЛОВ", "0", "за эту сессию")
        self.card_threats = StatCard("ОБНАРУЖЕНО УГРОЗ", "0", "за эту сессию")
        self.card_ai = StatCard("ИИ-МОДЕЛЬ", "Активна", "LightGBM · 88.9% точность")

        cards_layout.addWidget(self.card_scanned)
        cards_layout.addWidget(self.card_threats)
        cards_layout.addWidget(self.card_ai)
        layout.addLayout(cards_layout)

        # Уровни защиты
        info = QFrame()
        info.setObjectName("infoCard")
        info.setStyleSheet(INFO_CARD_QSS)

        info_outer = QVBoxLayout(info)
        info_outer.setContentsMargins(20, 18, 20, 18)
        info_outer.setSpacing(8)

        info_title = QLabel("🛡  УРОВНИ ЗАЩИТЫ")
        info_title.setStyleSheet(CARD_TITLE_QSS)
        info_outer.addWidget(info_title)

        for text in [
            "✅  YARA — локальные сигнатуры",
            "✅  MalwareBazaar — облачная база malware",
            "✅  URLhaus — проверка ссылок",
            "✅  ИИ-модель — детект zero-day",
            "✅  Резидентная защита — мониторинг в реальном времени",
            "⚪  VirusTotal — опционально",
        ]:
            lbl = QLabel(text)
            lbl.setStyleSheet("color: #cdd6f4; font-size: 13px; padding: 3px 0;")
            info_outer.addWidget(lbl)

        layout.addWidget(info)
        layout.addStretch()

    def update_stats(self, scanned: int, threats: int):
        self.card_scanned.set_value(str(scanned))
        self.card_threats.set_value(str(threats))

    def set_protection_state(self, enabled: bool):
        self.protect_card.set_state(enabled)