"""Главная страница."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QCheckBox, QSizePolicy, QLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint
from PyQt6.QtGui import (
    QPainter, QPixmap, QColor, QBrush, QPen, QLinearGradient
)

from gui.smooth_scroll import SmoothScrollArea


CARD_QSS = """
QFrame#statCard {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
}
QFrame#statCard:hover {
    border: 1px solid #30363d;
}
"""

INFO_CARD_QSS = """
QFrame#infoCard {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
}
"""

PROTECT_ON_QSS = """
QFrame#protectCard {
    background-color: rgba(16, 185, 129, 0.08);
    border: 1px solid rgba(16, 185, 129, 0.35);
    border-radius: 12px;
}
"""

PROTECT_OFF_QSS = """
QFrame#protectCard {
    background-color: rgba(239, 68, 68, 0.08);
    border: 1px solid rgba(239, 68, 68, 0.35);
    border-radius: 12px;
}
"""

PRIMARY_BTN_QSS = """
QPushButton {
    background-color: #10b981;
    color: #0a0d12;
    font-weight: 600;
    font-size: 15px;
    border: none;
    border-radius: 12px;
    padding: 0;
}
QPushButton:hover {
    background-color: #34d399;
}
QPushButton:pressed {
    background-color: #059669;
}
"""

SCROLL_QSS = """
QScrollArea {
    background-color: transparent;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background-color: transparent;
}
"""

CARD_TITLE_QSS = (
    "color: #8b949e; font-size: 11px; font-weight: 600; "
    "background: transparent;"
)
CARD_VALUE_QSS = (
    "color: #e6edf3; font-size: 32px; font-weight: 700; "
    "background: transparent;"
)
CARD_SUBTITLE_QSS = (
    "color: #6e7681; font-size: 12px; background: transparent;"
)


def make_shield_pixmap(size: int = 44) -> QPixmap:
    """Рисует щит с градиентом прямо в коде."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    gradient = QLinearGradient(0, 0, size, size)
    gradient.setColorAt(0.0, QColor("#10b981"))
    gradient.setColorAt(1.0, QColor("#06b6d4"))

    painter.setBrush(QBrush(gradient))
    painter.setPen(Qt.PenStyle.NoPen)

    s = size
    points = [
        (s * 0.5, s * 0.05),
        (s * 0.88, s * 0.2),
        (s * 0.88, s * 0.53),
        (s * 0.5, s * 0.95),
        (s * 0.12, s * 0.53),
        (s * 0.12, s * 0.2),
    ]
    polygon = [QPoint(int(x), int(y)) for x, y in points]
    painter.drawPolygon(polygon)

    painter.setPen(QPen(
        QColor("#0a0d12"), max(2, int(s * 0.09)),
        Qt.PenStyle.SolidLine,
        Qt.PenCapStyle.RoundCap,
        Qt.PenJoinStyle.RoundJoin,
    ))
    painter.drawLine(
        int(s * 0.3), int(s * 0.5),
        int(s * 0.44), int(s * 0.66),
    )
    painter.drawLine(
        int(s * 0.44), int(s * 0.66),
        int(s * 0.7), int(s * 0.35),
    )

    painter.end()
    return pix


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", subtitle: str = ""):
        super().__init__()
        self.setObjectName("statCard")
        self.setStyleSheet(CARD_QSS)
        self.setMinimumHeight(120)
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(8)

        lbl_title = QLabel(title)
        lbl_title.setStyleSheet(CARD_TITLE_QSS)
        layout.addWidget(lbl_title)

        self.lbl_value = QLabel(value)
        self.lbl_value.setStyleSheet(CARD_VALUE_QSS)
        layout.addWidget(self.lbl_value)

        self.lbl_subtitle = QLabel(subtitle)
        self.lbl_subtitle.setStyleSheet(CARD_SUBTITLE_QSS)
        layout.addWidget(self.lbl_subtitle)

    def set_value(self, value: str):
        self.lbl_value.setText(value)


class ProtectionStatusCard(QFrame):
    toggled = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setObjectName("protectCard")
        self.setMinimumHeight(100)
        self.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed
        )
        self._enabled = True

        layout = QHBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 18)
        layout.setSpacing(18)

        self.icon = QLabel()
        self.icon.setPixmap(make_shield_pixmap(44))
        self.icon.setFixedSize(52, 52)
        self.icon.setStyleSheet("background: transparent;")
        layout.addWidget(self.icon)

        info = QVBoxLayout()
        info.setSpacing(4)

        self.title = QLabel("ЗАЩИТА В РЕАЛЬНОМ ВРЕМЕНИ")
        self.title.setStyleSheet(
            "color: #e6edf3; font-size: 12px; font-weight: 600; "
            "letter-spacing: 0.5px; background: transparent;"
        )
        info.addWidget(self.title)

        self.subtitle = QLabel(
            "Активна — файлы проверяются автоматически"
        )
        self.subtitle.setStyleSheet(
            "color: #8b949e; font-size: 12.5px; background: transparent;"
        )
        self.subtitle.setWordWrap(True)
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
                width: 44px;
                height: 24px;
                border-radius: 12px;
                background-color: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.15);
            }
            QCheckBox::indicator:checked {
                background-color: #10b981;
                border: 1px solid #10b981;
            }
        """)
        self.toggle.toggled.connect(self._on_toggle)
        layout.addWidget(self.toggle)

        self.setStyleSheet(PROTECT_ON_QSS)

    def _on_toggle(self, checked: bool):
        self._enabled = checked
        if checked:
            self.setStyleSheet(PROTECT_ON_QSS)
            self.subtitle.setText(
                "Активна — файлы проверяются автоматически"
            )
        else:
            self.setStyleSheet(PROTECT_OFF_QSS)
            self.subtitle.setText(
                "Отключена — файлы не проверяются автоматически"
            )
        self.toggled.emit(checked)

    def set_state(self, enabled: bool):
        self.toggle.blockSignals(True)
        self.toggle.setChecked(enabled)
        self.toggle.blockSignals(False)
        self._enabled = enabled
        if enabled:
            self.setStyleSheet(PROTECT_ON_QSS)
            self.subtitle.setText(
                "Активна — файлы проверяются автоматически"
            )
        else:
            self.setStyleSheet(PROTECT_OFF_QSS)
            self.subtitle.setText(
                "Отключена — файлы не проверяются автоматически"
            )


class HomePage(QWidget):
    scan_requested = pyqtSignal()
    protection_toggled = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.scroll = SmoothScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet(SCROLL_QSS)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: transparent;")

        layout = QVBoxLayout(self.scroll_content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinAndMaxSize)

        title = QLabel("Добро пожаловать в AegisScan")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Ваш персональный антивирус с искусственным интеллектом"
        )
        subtitle.setObjectName("pageSubtitle")
        layout.addWidget(subtitle)

        self.protect_card = ProtectionStatusCard()
        self.protect_card.toggled.connect(self.protection_toggled.emit)
        layout.addWidget(self.protect_card)

        self.btn_scan = QPushButton("ПРОВЕРИТЬ ФАЙЛ")
        self.btn_scan.setStyleSheet(PRIMARY_BTN_QSS)
        self.btn_scan.setMinimumHeight(72)
        self.btn_scan.setMaximumHeight(72)
        self.btn_scan.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.clicked.connect(self.scan_requested.emit)
        layout.addWidget(self.btn_scan)

        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(14)

        self.card_scanned = StatCard(
            "ПРОВЕРЕНО ФАЙЛОВ", "0", "за эту сессию"
        )
        self.card_threats = StatCard(
            "ОБНАРУЖЕНО УГРОЗ", "0", "за эту сессию"
        )
        self.card_ai = StatCard(
            "ИИ-МОДЕЛЬ", "Активна", "LightGBM · точность 88.9%"
        )

        cards_layout.addWidget(self.card_scanned)
        cards_layout.addWidget(self.card_threats)
        cards_layout.addWidget(self.card_ai)
        layout.addLayout(cards_layout)

        info = QFrame()
        info.setObjectName("infoCard")
        info.setStyleSheet(INFO_CARD_QSS)
        info.setSizePolicy(
            QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum
        )

        info_outer = QVBoxLayout(info)
        info_outer.setContentsMargins(22, 20, 22, 20)
        info_outer.setSpacing(10)

        info_title = QLabel("УРОВНИ ЗАЩИТЫ")
        info_title.setStyleSheet(CARD_TITLE_QSS)
        info_outer.addWidget(info_title)

        protections = [
            ("YARA", "локальные сигнатуры", True),
            ("MalwareBazaar", "облачная база malware", True),
            ("URLhaus", "проверка ссылок", True),
            ("ИИ-модель", "детект zero-day угроз", True),
            ("Резидентная защита", "мониторинг в реальном времени", True),
            ("VirusTotal", "опционально, требует VPN", False),
        ]

        for name, desc, enabled in protections:
            row = QHBoxLayout()
            row.setSpacing(10)

            dot = QLabel("●")
            dot.setStyleSheet(
                f"color: {'#10b981' if enabled else '#484f58'}; "
                f"font-size: 10px; background: transparent;"
            )
            dot.setFixedWidth(12)
            row.addWidget(dot)

            name_lbl = QLabel(name)
            name_lbl.setStyleSheet(
                "color: #e6edf3; font-size: 13px; font-weight: 500; "
                "background: transparent;"
            )
            name_lbl.setFixedWidth(160)
            row.addWidget(name_lbl)

            desc_lbl = QLabel(desc)
            desc_lbl.setStyleSheet(
                "color: #6e7681; font-size: 12px; background: transparent;"
            )
            row.addWidget(desc_lbl)
            row.addStretch()

            info_outer.addLayout(row)

        layout.addWidget(info)
        layout.addStretch()

        self.scroll.setWidget(self.scroll_content)
        root.addWidget(self.scroll)

    def update_stats(self, scanned: int, threats: int):
        self.card_scanned.set_value(str(scanned))
        self.card_threats.set_value(str(threats))

    def set_protection_state(self, enabled: bool):
        self.protect_card.set_state(enabled)