"""
Тест виджетов Qt для проверки отображения.
Запуск: py -m gui.test_widgets
"""
import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QCheckBox, QLineEdit, QSlider, QFrame,
    QGroupBox, QTextEdit
)
from PyQt6.QtCore import Qt


class TestWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Тест виджетов Qt")
        self.setMinimumSize(700, 700)

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # 1. Простой текст
        lbl1 = QLabel("1. QLabel — обычный текст")
        layout.addWidget(lbl1)

        # 2. QLabel с цветом через setStyleSheet
        lbl2 = QLabel("2. QLabel с цветом через stylesheet")
        lbl2.setStyleSheet("color: #89b4fa; font-size: 16px; font-weight: bold;")
        layout.addWidget(lbl2)

        # 3. Кнопка обычная
        btn1 = QPushButton("3. QPushButton — обычная")
        layout.addWidget(btn1)

        # 4. Кнопка со стилем
        btn2 = QPushButton("4. QPushButton с цветом")
        btn2.setStyleSheet(
            "QPushButton { background-color: #89b4fa; color: #1e1e2e; "
            "padding: 10px; border-radius: 6px; font-weight: bold; }"
        )
        layout.addWidget(btn2)

        # 5. Кнопка-переключатель
        btn3 = QPushButton("5. QPushButton checkable (кликни меня)")
        btn3.setCheckable(True)
        btn3.toggled.connect(
            lambda c: btn3.setText(f"5. Состояние: {'ВКЛ' if c else 'ВЫКЛ'}")
        )
        layout.addWidget(btn3)

        # 6. QCheckBox — обычный
        cb1 = QCheckBox("6. QCheckBox — обычный чекбокс")
        layout.addWidget(cb1)

        # 7. QCheckBox со стилем
        cb2 = QCheckBox("7. QCheckBox со стилем")
        cb2.setStyleSheet("QCheckBox { color: #89b4fa; font-size: 14px; }")
        layout.addWidget(cb2)

        # 8. Поле ввода
        le = QLineEdit()
        le.setPlaceholderText("8. QLineEdit — введите текст")
        layout.addWidget(le)

        # 9. Слайдер
        lbl9 = QLabel("9. QSlider")
        layout.addWidget(lbl9)
        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setMinimum(0)
        slider.setMaximum(100)
        slider.setValue(50)
        layout.addWidget(slider)

        # 10. QGroupBox с содержимым
        group = QGroupBox("10. QGroupBox с содержимым")
        group_layout = QVBoxLayout(group)
        group_layout.addWidget(QLabel("  Текст внутри группы"))
        group_layout.addWidget(QCheckBox("  Чекбокс внутри группы"))
        group_layout.addWidget(QPushButton("  Кнопка внутри группы"))
        layout.addWidget(group)

        # 11. QFrame в стиле card
        card = QFrame()
        card.setStyleSheet(
            "QFrame { background-color: #24273a; "
            "border: 1px solid #363a4f; border-radius: 8px; padding: 15px; }"
        )
        card_layout = QVBoxLayout(card)
        card_layout.addWidget(QLabel("11. QFrame-карточка"))
        card_layout.addWidget(QCheckBox("  Чекбокс внутри карточки"))
        layout.addWidget(card)

        # 12. TextEdit
        te = QTextEdit()
        te.setPlainText("12. QTextEdit — многострочное поле")
        te.setMaximumHeight(80)
        layout.addWidget(te)


def main():
    app = QApplication(sys.argv)
    window = TestWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()