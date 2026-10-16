"""Страница настроек."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QSlider, QCheckBox, QMessageBox,
    QSizePolicy, QLayout
)
from PyQt6.QtCore import Qt
from core import config, autostart
from gui.smooth_scroll import SmoothScrollArea


CARD_QSS = """
QFrame#settingsCard {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
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

CARD_TITLE_QSS = "color: #10b981; font-size: 13px; font-weight: 600;"

CHECKBOX_QSS = """
QCheckBox {
    color: #e6edf3;
    font-size: 13.5px;
    font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
    spacing: 10px;
    padding: 5px 0;
    background: transparent;
}
"""

SAVE_BTN_QSS = """
QPushButton {
    background-color: #10b981;
    color: #0a0d12;
    font-weight: 600;
    font-size: 14px;
    border: none;
    border-radius: 8px;
    padding: 12px 30px;
}
QPushButton:hover { background-color: #34d399; }
"""


def make_card(title: str) -> tuple:
    frame = QFrame()
    frame.setObjectName("settingsCard")
    frame.setStyleSheet(CARD_QSS)
    frame.setSizePolicy(
        QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum
    )

    outer = QVBoxLayout(frame)
    outer.setContentsMargins(22, 20, 22, 20)
    outer.setSpacing(12)

    lbl = QLabel(title)
    lbl.setStyleSheet(CARD_TITLE_QSS)
    outer.addWidget(lbl)

    content = QVBoxLayout()
    content.setSpacing(4)
    outer.addLayout(content)

    return frame, content


def make_checkbox(text: str) -> QCheckBox:
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

        content_layout = QVBoxLayout(self.scroll_content)
        content_layout.setContentsMargins(32, 32, 32, 32)
        content_layout.setSpacing(16)
        content_layout.setSizeConstraint(
            QLayout.SizeConstraint.SetMinAndMaxSize
        )

        title = QLabel("Настройки")
        title.setObjectName("pageTitle")
        content_layout.addWidget(title)

        subtitle = QLabel("Изменения сохраняются автоматически.")
        subtitle.setObjectName("pageSubtitle")
        content_layout.addWidget(subtitle)

        # ===== Источники проверки =====
        card_sources, sources_layout = make_card("ИСТОЧНИКИ ПРОВЕРКИ")

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

        content_layout.addWidget(card_sources)

        # ===== Порог ИИ =====
        card_ai, ai_layout = make_card("ЧУВСТВИТЕЛЬНОСТЬ ИИ-МОДЕЛИ")

        row = QHBoxLayout()
        lbl = QLabel("Порог срабатывания:")
        lbl.setStyleSheet(
            "color: #e6edf3; font-size: 13px; background: transparent;"
        )
        row.addWidget(lbl)
        row.addStretch()

        self.lbl_threshold_value = QLabel("0.70")
        self.lbl_threshold_value.setStyleSheet(
            "color: #10b981; font-weight: 700; font-size: 16px; "
            "background: transparent;"
        )
        row.addWidget(self.lbl_threshold_value)
        ai_layout.addLayout(row)

        self.slider_threshold = QSlider(Qt.Orientation.Horizontal)
        self.slider_threshold.setMinimum(40)
        self.slider_threshold.setMaximum(95)
        self.slider_threshold.valueChanged.connect(
            self._on_threshold_changed
        )
        ai_layout.addWidget(self.slider_threshold)

        hint = QLabel(
            "Ниже порог — больше находок, но больше ложных срабатываний.\n"
            "Выше порог — строже фильтр, но можно пропустить угрозу."
        )
        hint.setStyleSheet(
            "color: #6e7681; font-size: 11.5px; padding-top: 4px; "
            "background: transparent;"
        )
        hint.setWordWrap(True)
        ai_layout.addWidget(hint)

        content_layout.addWidget(card_ai)

        # ===== Интерфейс =====
        card_ui, ui_layout = make_card("ИНТЕРФЕЙС")

        self.cb_smooth = make_checkbox(
            "Плавная прокрутка (с инерцией)"
        )
        self.cb_smooth.toggled.connect(self._save_ui)
        ui_layout.addWidget(self.cb_smooth)

        speed_row = QHBoxLayout()
        speed_lbl = QLabel("Скорость прокрутки:")
        speed_lbl.setStyleSheet(
            "color: #e6edf3; font-size: 13px; background: transparent;"
        )
        speed_row.addWidget(speed_lbl)
        speed_row.addStretch()

        self.lbl_speed_value = QLabel("50")
        self.lbl_speed_value.setStyleSheet(
            "color: #10b981; font-weight: 700; font-size: 16px; "
            "background: transparent;"
        )
        speed_row.addWidget(self.lbl_speed_value)
        ui_layout.addLayout(speed_row)

        self.slider_speed = QSlider(Qt.Orientation.Horizontal)
        self.slider_speed.setMinimum(0)
        self.slider_speed.setMaximum(100)
        self.slider_speed.valueChanged.connect(self._on_speed_changed)
        ui_layout.addWidget(self.slider_speed)

        speed_hint = QLabel(
            "Меньше — медленнее и плавнее. Больше — быстрее."
        )
        speed_hint.setStyleSheet(
            "color: #6e7681; font-size: 11.5px; padding-top: 4px; "
            "background: transparent;"
        )
        speed_hint.setWordWrap(True)
        ui_layout.addWidget(speed_hint)

        content_layout.addWidget(card_ui)

        # ===== Система =====
        card_sys, sys_layout = make_card("СИСТЕМА")

        self.cb_autostart = make_checkbox(
            "Запускать AegisScan при входе в Windows"
        )
        self.cb_autostart.toggled.connect(self._save_autostart)
        sys_layout.addWidget(self.cb_autostart)

        self.cb_minimized = make_checkbox(
            "При автозапуске стартовать свёрнутым в трей"
        )
        self.cb_minimized.toggled.connect(self._save_misc)
        sys_layout.addWidget(self.cb_minimized)

        hint2 = QLabel(
            "Антивирус зарегистрируется в автозагрузке Windows "
            "(реестр HKCU\\...\\Run)."
        )
        hint2.setStyleSheet(
            "color: #6e7681; font-size: 11.5px; padding-top: 4px; "
            "background: transparent;"
        )
        hint2.setWordWrap(True)
        sys_layout.addWidget(hint2)

        content_layout.addWidget(card_sys)

        # ===== Прочее =====
        card_misc, misc_layout = make_card("ПРОЧЕЕ")

        self.cb_history = make_checkbox("Сохранять историю проверок")
        self.cb_history.toggled.connect(self._save_misc)
        misc_layout.addWidget(self.cb_history)

        content_layout.addWidget(card_misc)

        # ===== Кнопки =====
        btn_layout = QHBoxLayout()

        self.btn_reset = QPushButton("Сбросить настройки")
        self.btn_reset.setMinimumHeight(42)
        self.btn_reset.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_reset.clicked.connect(self._reset_settings)
        btn_layout.addWidget(self.btn_reset)

        btn_layout.addStretch()

        self.btn_save = QPushButton("Сохранить")
        self.btn_save.setStyleSheet(SAVE_BTN_QSS)
        self.btn_save.setMinimumHeight(42)
        self.btn_save.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_save.clicked.connect(self._save_all)
        btn_layout.addWidget(self.btn_save)

        content_layout.addLayout(btn_layout)
        content_layout.addStretch()

        self.scroll.setWidget(self.scroll_content)
        root.addWidget(self.scroll)

    def _load_values(self):
        self._loading = True

        self.cb_yara.setChecked(self.settings.get("enable_yara", True))
        self.cb_mb.setChecked(
            self.settings.get("enable_malwarebazaar", True)
        )
        self.cb_vt.setChecked(
            self.settings.get("enable_virustotal", False)
        )
        self.cb_ai.setChecked(self.settings.get("enable_ai", True))
        self.cb_history.setChecked(
            self.settings.get("save_history", True)
        )
        self.cb_minimized.setChecked(
            self.settings.get("start_minimized", True)
        )
        self.cb_smooth.setChecked(
            self.settings.get("smooth_scroll", True)
        )

        threshold = self.settings.get("ai_threshold", 0.70)
        self.slider_threshold.setValue(int(threshold * 100))
        self.lbl_threshold_value.setText(f"{threshold:.2f}")

        speed = self.settings.get("scroll_speed", 50)
        self.slider_speed.setValue(speed)
        self.lbl_speed_value.setText(str(speed))

        real_autostart = autostart.is_enabled()
        self.cb_autostart.setChecked(real_autostart)
        self.settings["autostart"] = real_autostart

        self._loading = False

    def _on_threshold_changed(self, value: int):
        self.lbl_threshold_value.setText(f"{value / 100:.2f}")

    def _on_speed_changed(self, value: int):
        self.lbl_speed_value.setText(str(value))

    def _save_sources(self):
        if self._loading:
            return
        self.settings["enable_yara"] = self.cb_yara.isChecked()
        self.settings["enable_malwarebazaar"] = self.cb_mb.isChecked()
        self.settings["enable_virustotal"] = self.cb_vt.isChecked()
        self.settings["enable_ai"] = self.cb_ai.isChecked()
        config.save(self.settings)

    def _save_ui(self):
        if self._loading:
            return
        self.settings["smooth_scroll"] = self.cb_smooth.isChecked()
        self.settings["scroll_speed"] = self.slider_speed.value()
        config.save(self.settings)

    def _save_autostart(self, checked: bool):
        if self._loading:
            return

        if checked:
            res = autostart.enable()
            if res.get("status") != "ok":
                QMessageBox.warning(
                    self, "AegisScan",
                    f"Не удалось включить автозапуск:\n"
                    f"{res.get('message', '')}"
                )
                self.cb_autostart.blockSignals(True)
                self.cb_autostart.setChecked(False)
                self.cb_autostart.blockSignals(False)
                return
            QMessageBox.information(
                self, "AegisScan", "Автозапуск включён."
            )
        else:
            res = autostart.disable()
            if res.get("status") != "ok":
                QMessageBox.warning(
                    self, "AegisScan",
                    f"Не удалось отключить:\n{res.get('message', '')}"
                )
                return
            QMessageBox.information(
                self, "AegisScan", "Автозапуск отключён."
            )

        self.settings["autostart"] = checked
        config.save(self.settings)

    def _save_misc(self):
        if self._loading:
            return
        self.settings["save_history"] = self.cb_history.isChecked()
        self.settings["start_minimized"] = self.cb_minimized.isChecked()
        config.save(self.settings)

    def _save_all(self):
        self.settings["ai_threshold"] = (
            self.slider_threshold.value() / 100
        )
        self.settings["enable_yara"] = self.cb_yara.isChecked()
        self.settings["enable_malwarebazaar"] = self.cb_mb.isChecked()
        self.settings["enable_virustotal"] = self.cb_vt.isChecked()
        self.settings["enable_ai"] = self.cb_ai.isChecked()
        self.settings["save_history"] = self.cb_history.isChecked()
        self.settings["start_minimized"] = self.cb_minimized.isChecked()
        self.settings["autostart"] = self.cb_autostart.isChecked()
        self.settings["smooth_scroll"] = self.cb_smooth.isChecked()
        self.settings["scroll_speed"] = self.slider_speed.value()

        if config.save(self.settings):
            QMessageBox.information(
                self, "AegisScan", "Настройки сохранены."
            )
        else:
            QMessageBox.warning(
                self, "AegisScan", "Не удалось сохранить."
            )

    def _reset_settings(self):
        reply = QMessageBox.question(
            self, "Сброс настроек",
            "Вернуть все настройки к значениям по умолчанию?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        autostart.disable()
        self.settings = config.DEFAULT_CONFIG.copy()
        config.save(self.settings)
        self._load_values()
        QMessageBox.information(
            self, "AegisScan", "Настройки сброшены."
        )