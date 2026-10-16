"""Стили QSS для AegisScan — тёмная тема с зелёным акцентом."""

DARK_THEME = """
/* ============= ОСНОВНОЕ ============= */
QMainWindow, QWidget {
    background-color: #0f1318;
    color: #e6edf3;
    font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}

/* ============= ЗАГОЛОВОК ОКНА ============= */
QLabel#appTitle {
    font-size: 17px;
    font-weight: 600;
    color: #e6edf3;
    padding: 10px 14px;
    background: transparent;
}

QLabel#statusBadge {
    color: #10b981;
    font-size: 12px;
    font-weight: 500;
    padding: 6px 14px;
    border-radius: 8px;
    background-color: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.3);
}
QLabel#statusBadge[state="warning"] {
    color: #f59e0b;
    background-color: rgba(245, 158, 11, 0.12);
    border: 1px solid rgba(245, 158, 11, 0.3);
}
QLabel#statusBadge[state="danger"] {
    color: #ef4444;
    background-color: rgba(239, 68, 68, 0.12);
    border: 1px solid rgba(239, 68, 68, 0.3);
}
QLabel#statusBadge[state="busy"] {
    color: #8b949e;
    background-color: rgba(139, 148, 158, 0.12);
    border: 1px solid rgba(139, 148, 158, 0.3);
}

/* ============= САЙДБАР ============= */
QFrame#sidebar {
    background-color: #0a0d12;
    border-right: 1px solid #21262d;
    min-width: 220px;
    max-width: 220px;
}

QPushButton#navButton {
    background-color: transparent;
    color: #8b949e;
    border: none;
    text-align: left;
    padding: 11px 20px;
    font-size: 13.5px;
    font-weight: 500;
    border-radius: 8px;
    margin: 2px 10px;
}

QPushButton#navButton:hover {
    background-color: rgba(16, 185, 129, 0.06);
    color: #e6edf3;
}

QPushButton#navButton:checked {
    background-color: rgba(16, 185, 129, 0.12);
    color: #10b981;
    font-weight: 600;
    border-left: 2px solid #10b981;
}

/* ============= ЗАГОЛОВКИ СТРАНИЦ ============= */
QLabel#pageTitle {
    font-size: 22px;
    font-weight: 700;
    color: #e6edf3;
    padding-bottom: 4px;
    background: transparent;
}

QLabel#pageSubtitle {
    font-size: 13px;
    color: #8b949e;
    padding-bottom: 8px;
    background: transparent;
}

/* ============= КАРТОЧКИ ============= */
QFrame#card {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
}

QLabel#cardTitle {
    font-size: 11px;
    font-weight: 600;
    color: #8b949e;
    background: transparent;
}

QLabel#cardValue {
    font-size: 32px;
    font-weight: 700;
    color: #e6edf3;
    background: transparent;
}

QLabel#cardSubtitle {
    font-size: 12px;
    color: #6e7681;
    background: transparent;
}

/* ============= КНОПКИ ============= */
QPushButton {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 9px 18px;
    border-radius: 8px;
    font-size: 13px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #404a55;
}
QPushButton:pressed {
    background-color: #1a1f26;
}
QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}

/* Главная кнопка — зелёная */
QPushButton#primaryButton {
    background-color: #10b981;
    color: #0a0d12;
    border: none;
    font-weight: 600;
    font-size: 15px;
    padding: 14px 28px;
    border-radius: 10px;
}
QPushButton#primaryButton:hover {
    background-color: #34d399;
}
QPushButton#primaryButton:pressed {
    background-color: #059669;
}

/* Опасная кнопка — красная */
QPushButton#dangerButton {
    background-color: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}
QPushButton#dangerButton:hover {
    background-color: rgba(239, 68, 68, 0.25);
    color: #ff6b6b;
}

/* ============= ПОЛЯ ВВОДА ============= */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #0a0d12;
    color: #e6edf3;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 10px 14px;
    font-size: 13px;
    selection-background-color: #10b981;
    selection-color: #0a0d12;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border: 1px solid #10b981;
    background-color: #0f1318;
}

/* ============= ЧАТ ============= */
QTextEdit#chatHistory {
    background-color: #0a0d12;
    color: #e6edf3;
    border: 1px solid #21262d;
    border-radius: 10px;
    padding: 16px;
    font-size: 13px;
}

QPushButton#sendButton {
    background-color: #10b981;
    color: #0a0d12;
    font-weight: 600;
    padding: 10px 22px;
    border-radius: 8px;
    border: none;
}
QPushButton#sendButton:hover {
    background-color: #34d399;
}

/* ============= СЛАЙДЕР ============= */
QSlider {
    min-height: 24px;
}
QSlider::groove:horizontal {
    border: none;
    height: 6px;
    background: #21262d;
    border-radius: 3px;
    margin: 0;
}
QSlider::sub-page:horizontal {
    background: #10b981;
    border-radius: 3px;
}
QSlider::add-page:horizontal {
    background: #21262d;
    border-radius: 3px;
}
QSlider::handle:horizontal {
    background: #10b981;
    border: 3px solid #0f1318;
    width: 18px;
    height: 18px;
    margin: -9px 0;
    border-radius: 12px;
}
QSlider::handle:horizontal:hover {
    background: #34d399;
}

/* ============= ТАБЛИЦЫ ============= */
QTableWidget {
    background-color: #0a0d12;
    color: #e6edf3;
    border: 1px solid #21262d;
    border-radius: 10px;
    gridline-color: #161b22;
    font-size: 12.5px;
}
QTableWidget::item {
    padding: 6px;
    border: none;
}
QTableWidget::item:selected {
    background-color: rgba(16, 185, 129, 0.15);
    color: #e6edf3;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 10px 8px;
    border: none;
    border-bottom: 1px solid #21262d;
    font-weight: 600;
    font-size: 11.5px;
}

/* ============= ЧЕКБОКСЫ ============= */
QCheckBox {
    color: #e6edf3;
    font-size: 13px;
    spacing: 10px;
    padding: 5px 0;
    background: transparent;
}
QCheckBox::indicator {
    width: 20px;
    height: 20px;
    border-radius: 5px;
    border: 2px solid #30363d;
    background-color: #0a0d12;
}
QCheckBox::indicator:hover {
    border-color: #10b981;
}
QCheckBox::indicator:checked {
    background-color: #10b981;
    border-color: #10b981;
}

/* ============= ПРОГРЕСС-БАР ============= */
QProgressBar {
    background-color: #161b22;
    border: none;
    border-radius: 6px;
    text-align: center;
    color: #e6edf3;
    font-size: 11px;
    font-weight: 600;
    min-height: 12px;
}
QProgressBar::chunk {
    background-color: #10b981;
    border-radius: 6px;
}

/* ============= СКРОЛЛБАРЫ ============= */
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    border: none;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover {
    background: #10b981;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}

QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    border: none;
}
QScrollBar::handle:horizontal {
    background: #30363d;
    border-radius: 5px;
    min-width: 30px;
}
QScrollBar::handle:horizontal:hover {
    background: #10b981;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* ============= ТУЛТИПЫ ============= */
QToolTip {
    background-color: #161b22;
    color: #e6edf3;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}
"""