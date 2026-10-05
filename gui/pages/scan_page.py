"""Страница сканирования в стиле VirusTotal."""
import os
import hashlib

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QFileDialog, QInputDialog, QProgressBar,
    QSizePolicy, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

from core import scanner


# ---------- QSS ----------
CARD_QSS = """
QFrame#scanCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
    border-radius: 12px;
}
"""

VERDICT_CLEAN_QSS = """
QFrame#verdictFrame {
    background-color: #1e3a2f;
    border: 1px solid #28a745;
    border-radius: 12px;
}
"""

VERDICT_DANGER_QSS = """
QFrame#verdictFrame {
    background-color: #3a1e1e;
    border: 1px solid #dc3545;
    border-radius: 12px;
}
"""

VERDICT_WARN_QSS = """
QFrame#verdictFrame {
    background-color: #3a2f1e;
    border: 1px solid #f9a825;
    border-radius: 12px;
}
"""

VERDICT_INFO_QSS = """
QFrame#verdictFrame {
    background-color: #24273a;
    border: 1px solid #45475a;
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

TITLE_QSS = "color: #89b4fa; font-size: 13px; font-weight: 600;"
VALUE_QSS = "color: #cdd6f4; font-size: 13px;"
SUBTLE_QSS = "color: #7f849c; font-size: 12px;"


# ---------- Утилиты ----------
def sha256_of(filepath: str) -> str:
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return "—"


def human_size(size: int) -> str:
    for unit in ["Б", "КБ", "МБ", "ГБ"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} ТБ"


# ---------- Воркер ----------
class ScanWorker(QThread):
    finished = pyqtSignal(dict)

    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args

    def run(self):
        try:
            result = self.func(*self.args)
        except Exception as e:
            result = {"status": "error", "message": str(e)}
        self.finished.emit(result)


# ---------- Хелперы ----------
def make_card(title: str) -> tuple:
    """Карточка с заголовком. Возвращает (frame, content_layout)."""
    frame = QFrame()
    frame.setObjectName("scanCard")
    frame.setStyleSheet(CARD_QSS)

    outer = QVBoxLayout(frame)
    outer.setContentsMargins(20, 18, 20, 18)
    outer.setSpacing(12)

    if title:
        lbl = QLabel(title)
        lbl.setStyleSheet(TITLE_QSS)
        outer.addWidget(lbl)

    content = QVBoxLayout()
    content.setSpacing(8)
    outer.addLayout(content)

    return frame, content


def make_row(label: str, value: str) -> QWidget:
    """Строка label: value."""
    w = QWidget()

    h = QHBoxLayout(w)
    h.setContentsMargins(0, 4, 0, 4)
    h.setSpacing(12)

    l1 = QLabel(label)
    l1.setStyleSheet(SUBTLE_QSS)
    l1.setFixedWidth(100)
    l1.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

    l2 = QLabel(value)
    l2.setStyleSheet(VALUE_QSS)
    l2.setWordWrap(True)
    l2.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

    h.addWidget(l1)
    h.addWidget(l2, 1)
    return w


# ---------- Страница ----------
class ScanPage(QWidget):
    scan_completed = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.worker = None
        self.current_filepath = None
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 30, 30, 30)
        root.setSpacing(15)

        # Заголовок
        title = QLabel("🔍  Сканер")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        root.addWidget(title)

        subtitle = QLabel(
            "Проверка файлов и ссылок с помощью YARA, MalwareBazaar и ИИ-модели"
        )
        subtitle.setStyleSheet(SUBTLE_QSS)
        root.addWidget(subtitle)

        # Кнопки
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.btn_file = QPushButton("📁  Проверить файл")
        self.btn_file.setMinimumHeight(45)
        self.btn_file.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_file.clicked.connect(self.scan_file)

        self.btn_url = QPushButton("🔗  Проверить ссылку")
        self.btn_url.setMinimumHeight(45)
        self.btn_url.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_url.clicked.connect(self.scan_url)

        btn_row.addWidget(self.btn_file)
        btn_row.addWidget(self.btn_url)
        root.addLayout(btn_row)

        # Скролл
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet(SCROLL_QSS)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: transparent;")

        self.result_area = QVBoxLayout(self.scroll_content)
        self.result_area.setContentsMargins(0, 5, 10, 5)
        self.result_area.setSpacing(14)
        self.result_area.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.scroll.setWidget(self.scroll_content)
        root.addWidget(self.scroll, 1)

        self._show_placeholder()

    def _clear_result(self):
        while self.result_area.count():
            item = self.result_area.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            elif item.layout():
                self._clear_layout(item.layout())

    def _clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()
            elif item.layout():
                self._clear_layout(item.layout())

    # ---------- Плейсхолдер ----------
    def _show_placeholder(self):
        self._clear_result()

        ph = QFrame()
        ph.setObjectName("scanCard")
        ph.setStyleSheet(CARD_QSS)
        ph.setMinimumHeight(300)

        layout = QVBoxLayout(ph)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(16)

        icon = QLabel("🔍")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon.setStyleSheet("font-size: 64px; color: #45475a;")

        text = QLabel("Выберите файл или ссылку для проверки")
        text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        text.setStyleSheet("color: #7f849c; font-size: 16px;")

        hint = QLabel(
            "Мы проверим его по 4 источникам:\n"
            "YARA, MalwareBazaar, VirusTotal и ИИ-модель"
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: #585b70; font-size: 12px;")
        hint.setWordWrap(True)

        layout.addStretch()
        layout.addWidget(icon)
        layout.addWidget(text)
        layout.addWidget(hint)
        layout.addStretch()

        self.result_area.addWidget(ph)

    # ---------- Загрузка ----------
    def _show_checking(self, name: str, size: str = ""):
        self._clear_result()

        card, c = make_card("📄  Файл")
        c.addWidget(make_row("Имя:", name))
        if size:
            c.addWidget(make_row("Размер:", size))
        self.result_area.addWidget(card)

        card2 = QFrame()
        card2.setObjectName("scanCard")
        card2.setStyleSheet(CARD_QSS)
        card2.setMinimumHeight(110)

        l2 = QVBoxLayout(card2)
        l2.setContentsMargins(20, 20, 20, 20)
        l2.setSpacing(14)

        lbl = QLabel("⏳  Идёт проверка...")
        lbl.setStyleSheet("color: #89b4fa; font-size: 16px; font-weight: 600;")
        l2.addWidget(lbl)

        progress = QProgressBar()
        progress.setRange(0, 0)
        progress.setTextVisible(False)
        progress.setFixedHeight(6)
        progress.setStyleSheet("""
            QProgressBar {
                background-color: #181825;
                border: none;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                border-radius: 3px;
            }
        """)
        l2.addWidget(progress)

        self.result_area.addWidget(card2)

    # ---------- Логика ----------
    def scan_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Выберите файл для проверки")
        if not filepath:
            return

        self.current_filepath = filepath
        self._set_busy(True)

        name = os.path.basename(filepath)
        try:
            size = human_size(os.path.getsize(filepath))
        except Exception:
            size = ""

        self._show_checking(name, size)

        self.worker = ScanWorker(scanner.scan_file, filepath)
        self.worker.finished.connect(lambda r: self._on_scan_done(r, name, size))
        self.worker.start()

    def scan_url(self):
        url, ok = QInputDialog.getText(self, "Проверить ссылку", "Введите URL:")
        if not ok or not url:
            return

        self._set_busy(True)
        self._show_checking(url)

        self.worker = ScanWorker(scanner.scan_url, url)
        self.worker.finished.connect(lambda r: self._on_scan_done(r, url, ""))
        self.worker.start()

    def _set_busy(self, busy: bool):
        self.btn_file.setEnabled(not busy)
        self.btn_url.setEnabled(not busy)

    def _on_scan_done(self, result: dict, name: str, size: str):
        self._set_busy(False)
        self._render_result(result, name, size)
        self.scan_completed.emit(result)

        # Если обнаружена угроза и есть путь — предложить карантин
        if result.get("verdict") == "malware" and self.current_filepath:
            self._ask_quarantine(name)

    def _ask_quarantine(self, name: str):
        """Предлагает изолировать опасный файл."""
        reply = QMessageBox.question(
            self, "AegisScan — Обнаружена угроза",
            f"Файл «{name}» опасен!\n\n"
            f"Поместить его в карантин?\n"
            f"(Файл будет зашифрован и перемещён в защищённую папку)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        from core import quarantine, journal
        res = quarantine.quarantine_file(
            self.current_filepath,
            reason="Обнаружена угроза",
            source="Scanner",
        )
        if res.get("status") == "ok":
            journal.add_event(
                "quarantine",
                name,
                self.current_filepath,
                "quarantined",
                "Scanner",
                "Файл помещён в карантин",
            )
            QMessageBox.information(
                self, "AegisScan",
                f"Файл помещён в карантин.\n\n"
                f"ID: {res['record']['id']}"
            )
        else:
            QMessageBox.warning(
                self, "AegisScan",
                f"Не удалось изолировать:\n{res.get('message', '')}"
            )

    # ---------- Рендер ----------
    def _render_result(self, result: dict, name: str, size: str):
        self._clear_result()

        status = result.get("status")

        if status in ("error", "timeout"):
            self._render_error(result, name)
            return

        if status == "not_found":
            self.result_area.addWidget(self._make_verdict(
                "⚠️", "НЕ НАЙДЕНО",
                "Объект отсутствует в базах проверки",
                VERDICT_WARN_QSS
            ))
            return

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        ai_prob = result.get("ai_probability", None)

        if malicious > 0:
            icon, text, sub = "🚨", "ОБНАРУЖЕНА УГРОЗА", f"Найдено {malicious} срабатываний"
            style = VERDICT_DANGER_QSS
        elif suspicious > 0:
            icon, text, sub = "⚠️", "ПОДОЗРИТЕЛЬНЫЙ", f"{suspicious} подозрительных"
            style = VERDICT_WARN_QSS
        else:
            icon, text, sub = "✅", "ЧИСТО", "Угроз не обнаружено"
            style = VERDICT_CLEAN_QSS

        self.result_area.addWidget(self._make_verdict(icon, text, sub, style))

        row = QHBoxLayout()
        row.setSpacing(14)

        file_card = self._make_file_card(name, size)
        detect_card = self._make_detection_card(malicious, suspicious)

        row.addWidget(file_card, 1)
        row.addWidget(detect_card, 1)

        row_widget = QWidget()
        row_widget.setLayout(row)
        self.result_area.addWidget(row_widget)

        self.result_area.addWidget(self._make_sources_card(result))

        if ai_prob is not None:
            self.result_area.addWidget(self._make_ai_card(ai_prob))

        extra = self._make_extra_card(result)
        if extra:
            self.result_area.addWidget(extra)

    # ---------- Виджеты ----------
    def _make_verdict(self, icon: str, title: str, sub: str, style: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName("verdictFrame")
        frame.setStyleSheet(style)
        frame.setMinimumHeight(120)

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(20)

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 52px;")
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_lbl.setFixedWidth(80)
        layout.addWidget(icon_lbl)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(6)
        text_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        t = QLabel(title)
        t.setStyleSheet("color: white; font-size: 26px; font-weight: bold;")
        text_layout.addWidget(t)

        s = QLabel(sub)
        s.setStyleSheet("color: rgba(255,255,255,0.8); font-size: 14px;")
        text_layout.addWidget(s)

        layout.addLayout(text_layout, 1)
        return frame

    def _make_file_card(self, name: str, size: str) -> QFrame:
        card, c = make_card("📄  ФАЙЛ")
        c.addWidget(make_row("Имя:", name))
        if size:
            c.addWidget(make_row("Размер:", size))
        if self.current_filepath and os.path.isfile(self.current_filepath):
            h = sha256_of(self.current_filepath)
            if h != "—":
                short = f"{h[:16]}...{h[-8:]}"
                c.addWidget(make_row("SHA-256:", short))
        return card

    def _make_detection_card(self, malicious: int, suspicious: int) -> QFrame:
        card, c = make_card("🎯  ОБНАРУЖЕНИЯ")

        total = max(malicious + suspicious + 2, 4)
        detected = malicious + suspicious
        percent = int((detected / total) * 100) if total else 0

        big = QLabel(f"{detected} / {total}")
        big.setStyleSheet("color: #cdd6f4; font-size: 30px; font-weight: bold;")
        c.addWidget(big)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(percent)
        bar.setTextVisible(False)
        bar.setFixedHeight(10)
        bar_color = "#dc3545" if detected > 0 else "#28a745"
        bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #181825;
                border: none;
                border-radius: 5px;
            }}
            QProgressBar::chunk {{
                background-color: {bar_color};
                border-radius: 5px;
            }}
        """)
        c.addWidget(bar)

        sub = QLabel(f"Сработало источников: {detected}")
        sub.setStyleSheet(SUBTLE_QSS)
        c.addWidget(sub)

        return card

    def _make_sources_card(self, result: dict) -> QFrame:
        card, c = make_card("🛡  ИСТОЧНИКИ ПРОВЕРКИ")

        source = result.get("source", "")
        malicious = result.get("malicious", 0)
        ai_prob = result.get("ai_probability", None)
        matches = result.get("matches", [])

        if matches:
            names = ", ".join(m["rule"] for m in matches[:3])
            c.addWidget(self._source_row("🚨", "YARA", f"Сработало: {names}"))
        else:
            c.addWidget(self._source_row("✅", "YARA", "Сигнатуры не сработали"))

        if "MalwareBazaar" in source and malicious > 0:
            c.addWidget(self._source_row(
                "🚨", "MalwareBazaar",
                result.get("signature", "Найден в базе")
            ))
        elif "MalwareBazaar" in source:
            c.addWidget(self._source_row(
                "✅", "MalwareBazaar", "Не найден в базе malware"
            ))
        else:
            c.addWidget(self._source_row("⚪", "MalwareBazaar", "Пропущен"))

        if "VirusTotal" in source:
            c.addWidget(self._source_row("✅", "VirusTotal", "Проверен"))
        else:
            c.addWidget(self._source_row(
                "⚪", "VirusTotal", "Пропущен (нет ключа/VPN)"
            ))

        if ai_prob is not None:
            if ai_prob >= 0.7:
                mark = "🚨"
            elif ai_prob >= 0.4:
                mark = "⚠️"
            else:
                mark = "✅"
            c.addWidget(self._source_row(
                mark, "ИИ-модель",
                f"Вероятность malware: {ai_prob * 100:.1f}%"
            ))
        else:
            c.addWidget(self._source_row("⚪", "ИИ-модель", "Не выполнен"))

        return card

    def _source_row(self, icon: str, name: str, text: str) -> QWidget:
        w = QWidget()
        w.setMinimumHeight(28)

        h = QHBoxLayout(w)
        h.setContentsMargins(0, 4, 0, 4)
        h.setSpacing(12)

        i = QLabel(icon)
        i.setStyleSheet("font-size: 16px;")
        i.setFixedWidth(24)
        i.setAlignment(Qt.AlignmentFlag.AlignCenter)

        n = QLabel(name)
        n.setStyleSheet("color: #cdd6f4; font-size: 13px; font-weight: 600;")
        n.setFixedWidth(150)

        t = QLabel(text)
        t.setStyleSheet(SUBTLE_QSS)
        t.setWordWrap(True)

        h.addWidget(i)
        h.addWidget(n)
        h.addWidget(t, 1)
        return w

    def _make_ai_card(self, prob: float) -> QFrame:
        card, c = make_card("🧠  ИИ-МОДЕЛЬ")

        percent = int(prob * 100)
        row = QHBoxLayout()
        row.setSpacing(8)

        lbl = QLabel("Вероятность malware:")
        lbl.setStyleSheet("color: #cdd6f4; font-size: 13px;")
        row.addWidget(lbl)
        row.addStretch()

        if percent >= 70:
            color = "#dc3545"
        elif percent >= 40:
            color = "#f9a825"
        else:
            color = "#28a745"

        val = QLabel(f"{percent}%")
        val.setStyleSheet(f"color: {color}; font-size: 22px; font-weight: bold;")
        row.addWidget(val)
        c.addLayout(row)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(percent)
        bar.setTextVisible(False)
        bar.setFixedHeight(12)
        bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #181825;
                border: none;
                border-radius: 6px;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 6px;
            }}
        """)
        c.addWidget(bar)

        hint = QLabel("Модель LightGBM · 18 статических признаков PE-файла")
        hint.setStyleSheet("color: #585b70; font-size: 11px;")
        c.addWidget(hint)

        return card

    def _make_extra_card(self, result: dict):
        rows = []
        if result.get("signature"):
            rows.append(("Сигнатура:", result["signature"]))
        if result.get("file_type"):
            rows.append(("Тип файла:", result["file_type"]))
        if result.get("first_seen"):
            rows.append(("Впервые:", result["first_seen"]))
        if result.get("threat"):
            rows.append(("Угроза:", result["threat"]))

        engines = result.get("engines", [])
        if engines:
            rows.append(("Движков нашли:", str(len(engines))))
            for e in engines[:5]:
                rows.append((f"  • {e['name']}:", str(e.get("result", ""))))

        if not rows:
            return None

        card, c = make_card("📋  ДОПОЛНИТЕЛЬНО")
        for label, value in rows:
            c.addWidget(make_row(label, value))
        return card

    # ---------- Ошибка ----------
    def _render_error(self, result: dict, name: str):
        msg = result.get("message", "Неизвестная ошибка")

        frame = QFrame()
        frame.setObjectName("verdictFrame")
        frame.setStyleSheet(VERDICT_WARN_QSS)
        frame.setMinimumHeight(120)

        layout = QHBoxLayout(frame)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(20)

        icon = QLabel("⚠️")
        icon.setStyleSheet("font-size: 52px;")
        icon.setFixedWidth(80)
        layout.addWidget(icon)

        text_layout = QVBoxLayout()
        text_layout.setSpacing(6)
        text_layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        t = QLabel("ОШИБКА ПРОВЕРКИ")
        t.setStyleSheet("color: white; font-size: 24px; font-weight: bold;")
        text_layout.addWidget(t)

        s = QLabel(msg)
        s.setStyleSheet("color: rgba(255,255,255,0.8); font-size: 13px;")
        s.setWordWrap(True)
        text_layout.addWidget(s)

        layout.addLayout(text_layout, 1)
        self.result_area.addWidget(frame)

        card, c = make_card("📄  ФАЙЛ")
        c.addWidget(make_row("Имя:", name))
        self.result_area.addWidget(card)