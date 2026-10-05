"""AegisScan — точка входа."""
import sys
import os


def _setup_paths():
    """
    Если запущено из .exe — переходим в папку, где лежит .exe,
    чтобы .env, data/ и model/ находились корректно.
    """
    if getattr(sys, "frozen", False):
        # Папка с .exe
        exe_dir = os.path.dirname(sys.executable)
        os.chdir(exe_dir)


def main():
    _setup_paths()

    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("AegisScan")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()