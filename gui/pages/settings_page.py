"""Страница настроек — минималистичная, без глобальных конфликтов стилей."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QSlider, QCheckBox, QMessageBox
)
from PyQt6.QtCore import Qt
from core import config


# Локальный стиль карточки (без padding — отступы через layout)
CARD_QSS = """
QFrame#settingsCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
    border-radius: 12px;
}
"""

# Локальный стиль заголовка карточки
CARD_TITLE_QSS = "color: #89b4fa; font-size: 14px; font-weight: 600;"

# Локальный стиль чекбокса — только цвет и шрифт, БЕЗ indicator
CHECKBOX_QSS = """
QCheckBox {
    color: #cdd6f4;
    font-size: 14px;
    font-family: 'Segoe UI', Arial, sans-serif;
    spacing: 10px;
    padding: 6px 0;
    background-color: transparent;
}
"""


def make_card(title: str) -> tuple:
    """Создаёт QFrame-карточку с заголовком. Возвращает (карточка, layout)."""
    frame = QFrame()
    frame.setObjectName("settingsCard")
    frame.setStyleSheet(CARD_QSS)

    outer = QVBoxLayout(frame)
    outer.setContentsMargins(20, 18, 20, 18)
    outer.setSpacing(12)

    lbl = QLabel(title)
    lbl.setStyleSheet(CARD_TITLE_QSS)
    outer.addWidget(lbl)

    content = QVBoxLayout()
    content.setSpacing(2)
    outer.addLayout(content)

    return frame, content


def make_checkbox(text: str) -> QCheckBox:
    """Создаёт чекбокс со стандартным виджетом Qt (без своих indicator-правил)."""
    cb = QCheckBox(text)
    cb.setStyleSheet(CHECKBOX_QSS)
    cb.setMinimumHeight(32)
    cb.setCursor(Qt.CursorShape.PointingHandCursor)
    return cb


class SettingsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.settings = config.load()
        self._loading = False
        self._build_ui()
        self._load_values()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 30, 30, 30)
        root.setSpacing(15)

        title = QLabel("⚙️  Настройки")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        root.addWidget(title)

        subtitle = QLabel("Изменения сохраняются автоматически.")
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # ===== Источники проверки =====
        card_sources, sources_layout = make_card("Источники проверки")

        self.cb_yara = make_checkbox("YARA — локальные сигнатуры")
        self.cb_yara.toggled.connect(self._save_sources)
        sources_layout.addWidget(self.cb_yara)

        self.cb_mb = make_checkbox("MalwareBazaar — облачная база malware")
        self.cb_mb.toggled.connect(self._save_sources)
        sources_layout.addWidget(self.cb_mb)

        self.cb_vt = make_checkbox("VirusTotal — 70+ движков (требует VPN)")
        self.cb_vt.toggled.connect(self._save_sources)
        sources_layout.addWidget(self.cb_vt)

        self.cb_ai = make_checkbox("ИИ-модель — детект zero-day")
        self.cb_ai.toggled.connect(self._save_sources)
        sources_layout.addWidget(self.cb_ai)

        root.addWidget(card_sources)

        # ===== Порог ИИ =====
        card_ai, ai_layout = make_card("Чувствительность ИИ-модели")

        row = QHBoxLayout()
        lbl = QLabel("Порог срабатывания:")
        lbl.setStyleSheet("color: #cdd6f4; font-size: 13px;")
        row.addWidget(lbl)
        row.addStretch()

        self.lbl_threshold_value = QLabel("0.70")
        self.lbl_threshold_value.setStyleSheet(
            "color: #89b4fa; font-weight: bold; font-size: 16px;"
        )
        row.addWidget(self.lbl_threshold_value)
        ai_layout.addLayout(row)

        self.slider_threshold = QSlider(Qt.Orientation.Horizontal)
        self.slider_threshold.setMinimum(40)
        self.slider_threshold.setMaximum(95)
        self.slider_threshold.valueChanged.connect(self._on_threshold_changed)
        ai_layout.addWidget(self.slider_threshold)

        hint = QLabel(
            "Ниже порог — больше находок, но больше ложных срабатываний.\n"
            "Выше порог — строже фильтр, но можно пропустить угрозу."
        )
        hint.setStyleSheet("color: #7f849c; font-size: 11px; padding-top: 5px;")
        ai_layout.addWidget(hint)

        root.addWidget(card_ai)

        # ===== Прочее =====
        card_misc, misc_layout = make_card("Прочее")

        self.cb_history = make_checkbox("Сохранять историю проверок")
        self.cb_history.toggled.connect(self._save_misc)
        misc_layout.addWidget(self.cb_history)

        root.addWidget(card_misc)

        # ===== Кнопки =====
        btn_layout = QHBoxLayout()

        self.btn_reset = QPushButton("Сбросить настройки")
        self.btn_reset.clicked.connect(self._reset_settings)
        btn_layout.addWidget(self.btn_reset)

        btn_layout.addStretch()

        self.btn_save = QPushButton("Сохранить")
        self.btn_save.setObjectName("primaryButton")
        self.btn_save.setMinimumHeight(40)
        self.btn_save.clicked.connect(self._save_all)
        btn_layout.addWidget(self.btn_save)

        root.addLayout(btn_layout)
        root.addStretch()

    def _load_values(self):
        self._loading = True

        self.cb_yara.setChecked(self.settings.get("enable_yara", True))
        self.cb_mb.setChecked(self.settings.get("enable_malwarebazaar", True))
        self.cb_vt.setChecked(self.settings.get("enable_virustotal", False))
        self.cb_ai.setChecked(self.settings.get("enable_ai", True))
        self.cb_history.setChecked(self.settings.get("save_history", True))

        threshold = self.settings.get("ai_threshold", 0.70)
        self.slider_threshold.setValue(int(threshold * 100))
        self.lbl_threshold_value.setText(f"{threshold:.2f}")

        self._loading = False

    def _on_threshold_changed(self, value: int):
        self.lbl_threshold_value.setText(f"{value / 100:.2f}")

    def _save_sources(self):
        if self._loading:
            return
        self.settings["enable_yara"] = self.cb_yara.isChecked()
        self.settings["enable_malwarebazaar"] = self.cb_mb.isChecked()
        self.settings["enable_virustotal"] = self.cb_vt.isChecked()
        self.settings["enable_ai"] = self.cb_ai.isChecked()
        config.save(self.settings)

    def _save_misc(self):
        if self._loading:
            return
        self.settings["save_history"] = self.cb_history.isChecked()
        config.save(self.settings)

    def _save_all(self):
        self.settings["ai_threshold"] = self.slider_threshold.value() / 100
        self.settings["enable_yara"] = self.cb_yara.isChecked()
        self.settings["enable_malwarebazaar"] = self.cb_mb.isChecked()
        self.settings["enable_virustotal"] = self.cb_vt.isChecked()
        self.settings["enable_ai"] = self.cb_ai.isChecked()
        self.settings["save_history"] = self.cb_history.isChecked()

        if config.save(self.settings):
            QMessageBox.information(self, "AegisScan", "Настройки сохранены.")
        else:
            QMessageBox.warning(self, "AegisScan", "Не удалось сохранить настройки.")

    def _reset_settings(self):
        reply = QMessageBox.question(
            self, "Сброс настроек",
            "Вернуть все настройки к значениям по умолчанию?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.settings = config.DEFAULT_CONFIG.copy()
        config.save(self.settings)
        self._load_values()
        QMessageBox.information(self, "AegisScan", "Настройки сброшены.")