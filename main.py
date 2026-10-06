"""AegisScan — точка входа."""
import sys
import os


def _setup_paths():
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        os.chdir(exe_dir)


def main():
    _setup_paths()

    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtGui import QIcon
    from gui.main_window import MainWindow
    from gui.tray_icon import create_icon

    # Запрещаем закрытие приложения, когда последнее окно скрыто
    QApplication.setQuitOnLastWindowClosed(False)

    app = QApplication(sys.argv)
    app.setApplicationName("AegisScan")
    app.setWindowIcon(create_icon("#89b4fa"))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()