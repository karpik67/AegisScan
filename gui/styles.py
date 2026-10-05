"""Стили QSS для AegisScan — минималистичные, без конфликтов Qt."""

DARK_THEME = """
/* ---------- Основное ---------- */
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}

/* ---------- Заголовок окна ---------- */
QLabel#appTitle {
    font-size: 20px;
    font-weight: bold;
    color: #89b4fa;
    padding: 12px 15px;
}

QLabel#statusBadge {
    color: white;
    font-size: 12px;
    font-weight: 600;
    padding: 6px 14px;
    border-radius: 12px;
    background-color: #28a745;
}
QLabel#statusBadge[state="warning"] { background-color: #f9a825; }
QLabel#statusBadge[state="danger"]  { background-color: #dc3545; }
QLabel#statusBadge[state="busy"]    { background-color: #6c757d; }

/* ---------- Сайдбар ---------- */
QFrame#sidebar {
    background-color: #181825;
    border-right: 1px solid #313244;
    min-width: 210px;
    max-width: 210px;
}

QPushButton#navButton {
    background-color: transparent;
    color: #cdd6f4;
    border: none;
    text-align: left;
    padding: 12px 20px;
    font-size: 14px;
    border-radius: 8px;
    margin: 3px 10px;
}
QPushButton#navButton:hover {
    background-color: #313244;
    color: #89b4fa;
}
QPushButton#navButton:checked {
    background-color: #313244;
    color: #89b4fa;
    font-weight: 600;
    border-left: 3px solid #89b4fa;
}

/* ---------- Кнопки ---------- */
QPushButton {
    background-color: #45475a;
    color: #cdd6f4;
    border: none;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton:hover  { background-color: #585b70; }
QPushButton:pressed { background-color: #313244; }
QPushButton:disabled { background-color: #313244; color: #585b70; }

QPushButton#primaryButton {
    background-color: #89b4fa;
    color: #1e1e2e;
    font-weight: bold;
    font-size: 15px;
    padding: 15px 30px;
    border-radius: 10px;
}
QPushButton#primaryButton:hover { background-color: #b4befe; }

/* ---------- Поля ввода ---------- */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #363a4f;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #89b4fa;
}

/* ---------- Чат ---------- */
QTextEdit#chatHistory {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #363a4f;
    border-radius: 10px;
    padding: 15px;
    font-size: 13px;
}

QPushButton#sendButton {
    background-color: #89b4fa;
    color: #1e1e2e;
    font-weight: bold;
    padding: 10px 22px;
    border-radius: 8px;
    font-size: 13px;
}
QPushButton#sendButton:hover { background-color: #b4befe; }

/* ---------- Слайдер ---------- */
QSlider::groove:horizontal {
    border: none;
    height: 6px;
    background: #313244;
    border-radius: 3px;
}
QSlider::sub-page:horizontal {
    background: #89b4fa;
    border-radius: 3px;
}
QSlider::add-page:horizontal {
    background: #313244;
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background: #89b4fa;
    border: 2px solid #1e1e2e;
    width: 16px;
    height: 16px;
    margin: -6px 0;
    border-radius: 9px;
}
QSlider::handle:horizontal:hover {
    background: #b4befe;
}

/* ---------- Скроллбары ---------- */
QScrollBar:vertical {
    background-color: transparent;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background-color: #45475a;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover { background-color: #89b4fa; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }

QScrollBar:horizontal {
    background-color: transparent;
    height: 10px;
    border-radius: 5px;
}
QScrollBar::handle:horizontal {
    background-color: #45475a;
    border-radius: 5px;
    min-width: 30px;
}

/* ---------- Тултипы ---------- */
QToolTip {
    background-color: #313244;
    color: #cdd6f4;
    border: 1px solid #89b4fa;
    border-radius: 4px;
    padding: 5px 10px;
}
"""