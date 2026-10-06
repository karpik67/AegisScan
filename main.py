"""AegisScan — точка входа."""
import sys
import os


def _setup_paths():
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        os.chdir(exe_dir)


def main():
    _setup_paths()

    # Проверяем флаг --minimized (используется при автозапуске)
    start_minimized = "--minimized" in sys.argv

    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    from gui.tray_icon import create_icon

    QApplication.setQuitOnLastWindowClosed(False)

    app = QApplication(sys.argv)
    app.setApplicationName("AegisScan")
    app.setWindowIcon(create_icon("#89b4fa"))

    window = MainWindow()
    window.start_minimized = start_minimized

    if start_minimized:
        # При автозапуске — только в трей, окно не показываем
        window.hide()
        try:
            window.tray.notify(
                "AegisScan запущен",
                "Защита активна. Приложение свёрнуто в трей."
            )
        except Exception:
            pass
    else:
        window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()