"""Иконка в системном трее."""
from PyQt6.QtWidgets import QSystemTrayIcon, QMenu
from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QBrush, QPen, QFont
from PyQt6.QtCore import Qt, pyqtSignal


def create_icon(color: str = "#89b4fa") -> QIcon:
    """Создаёт иконку-щит программно."""
    size = 64
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Щит
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(QPen(QColor("#1e1e2e"), 2))
    points = [
        (32, 4), (56, 14), (56, 34), (32, 60), (8, 34), (8, 14)
    ]
    from PyQt6.QtCore import QPoint
    polygon = [QPoint(x, y) for x, y in points]
    painter.drawPolygon(polygon)

    # Галочка
    painter.setPen(QPen(QColor("#1e1e2e"), 5, Qt.PenStyle.SolidLine,
                         Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    painter.drawLine(20, 32, 28, 42)
    painter.drawLine(28, 42, 44, 22)

    painter.end()
    return QIcon(pix)


class TrayIcon(QSystemTrayIcon):
    """Иконка в трее с меню."""
    show_window_requested = pyqtSignal()
    quit_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setIcon(create_icon("#89b4fa"))
        self.setToolTip("AegisScan — защита активна")

        menu = QMenu()
        menu.setStyleSheet("""
            QMenu {
                background-color: #24273a;
                color: #cdd6f4;
                border: 1px solid #363a4f;
                border-radius: 6px;
                padding: 4px;
            }
            QMenu::item {
                padding: 8px 20px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #313244;
                color: #89b4fa;
            }
        """)

        action_open = menu.addAction("🛡  Открыть AegisScan")
        action_open.triggered.connect(self.show_window_requested.emit)

        menu.addSeparator()

        action_quit = menu.addAction("🚪  Выход")
        action_quit.triggered.connect(self.quit_requested.emit)

        self.setContextMenu(menu)
        self.activated.connect(self._on_activated)

    def _on_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show_window_requested.emit()

    def set_protection_state(self, enabled: bool):
        """Меняет цвет иконки и тултип."""
        if enabled:
            self.setIcon(create_icon("#89b4fa"))
            self.setToolTip("AegisScan — защита активна")
        else:
            self.setIcon(create_icon("#585b70"))
            self.setToolTip("AegisScan — защита отключена")

    def notify(self, title: str, message: str,
               icon_type=QSystemTrayIcon.MessageIcon.Information):
        """Показывает уведомление Windows."""
        self.showMessage(title, message, icon_type, 5000)