"""Иконка в системном трее."""
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QBrush, QPen, QLinearGradient
from PyQt6.QtCore import Qt, pyqtSignal, QPoint


def create_icon(color: str = "#10b981") -> QIcon:
    """Создаёт иконку-щит с градиентом."""
    size = 64
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Градиент от изумруда к бирюзе
    gradient = QLinearGradient(0, 0, size, size)
    gradient.setColorAt(0.0, QColor("#10b981"))
    gradient.setColorAt(1.0, QColor("#06b6d4"))

    painter.setBrush(QBrush(gradient))
    painter.setPen(Qt.PenStyle.NoPen)

    points = [
        (32, 4), (56, 14), (56, 34), (32, 60), (8, 34), (8, 14)
    ]
    polygon = [QPoint(x, y) for x, y in points]
    painter.drawPolygon(polygon)

    # Галочка
    painter.setPen(QPen(
        QColor("#0a0d12"), 5,
        Qt.PenStyle.SolidLine,
        Qt.PenCapStyle.RoundCap,
        Qt.PenJoinStyle.RoundJoin,
    ))
    painter.drawLine(20, 32, 28, 42)
    painter.drawLine(28, 42, 44, 22)

    painter.end()
    return QIcon(pix)


class TrayIcon(QSystemTrayIcon):
    show_window_requested = pyqtSignal()
    quit_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setIcon(create_icon("#10b981"))
        self.setToolTip("AegisScan — защита активна")

        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #161b22;
                color: #e6edf3;
                border: 1px solid #21262d;
                border-radius: 8px;
                padding: 6px;
            }
            QMenu::item {
                padding: 8px 24px 8px 16px;
                border-radius: 6px;
            }
            QMenu::item:selected {
                background-color: rgba(16, 185, 129, 0.15);
                color: #10b981;
            }
        """)

        action_open = menu.addAction("Открыть AegisScan")
        action_open.triggered.connect(self.show_window_requested.emit)

        menu.addSeparator()

        action_quit = menu.addAction("Выход")
        action_quit.triggered.connect(self.quit_requested.emit)

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window_requested.emit()

    def set_protection_state(self, enabled: bool):
        if enabled:
            self.setIcon(create_icon("#10b981"))
            self.setToolTip("AegisScan — защита активна")
        else:
            self.setIcon(create_icon("#6e7681"))
            self.setToolTip("AegisScan — защита отключена")

    def notify(self, title: str, message: str,
               icon_type=QSystemTrayIcon.MessageIcon.Information):
        self.showMessage(title, message, icon_type, 5000)