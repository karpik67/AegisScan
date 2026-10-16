"""
Плавная прокрутка для QScrollArea через QPropertyAnimation.
Перехватывает колесо мыши и анимирует движение scrollbar.
"""
from PyQt6.QtWidgets import QScrollArea
from PyQt6.QtCore import (
    Qt, QPropertyAnimation, QEasingCurve, QAbstractAnimation
)

from core import config


class SmoothScrollArea(QScrollArea):
    """
    QScrollArea с плавной прокруткой колесом мыши.
    """
    def __init__(self, parent=None):
        super().__init__(parent)

        self._animation = QPropertyAnimation(
            self.verticalScrollBar(), b"value", self
        )
        self._animation.setDuration(320)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def wheelEvent(self, event):
        settings = config.load()
        if not settings.get("smooth_scroll", True):
            # Обычное поведение
            super().wheelEvent(event)
            return

        # Скорость прокрутки (0..100) → множитель (0.4..2.0)
        speed = settings.get("scroll_speed", 50)
        multiplier = 0.4 + (speed / 100) * 1.6

        # Стандартный шаг — 120. Умножаем на скорость
        delta = event.angleDelta().y()
        if delta == 0:
            super().wheelEvent(event)
            return

        # Одна "ступенька" колеса = ~80 пикселей * multiplier
        step = int(80 * multiplier)
        direction = -1 if delta > 0 else 1
        distance = step * direction

        bar = self.verticalScrollBar()
        current = bar.value()
        target = current + distance

        # Ограничиваем
        target = max(bar.minimum(), min(bar.maximum(), target))

        # Запускаем анимацию
        self._animation.stop()
        self._animation.setStartValue(current)
        self._animation.setEndValue(target)
        self._animation.setDuration(320)
        self._animation.start(QAbstractAnimation.DeletionPolicy.KeepWhenStopped)

        event.accept()