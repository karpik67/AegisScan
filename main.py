"""AegisScan — точка входа."""
import sys
import os


def _setup_paths():
    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
        os.chdir(exe_dir)


def _load_fonts():
    """Загружает кастомные шрифты из assets/fonts."""
    try:
        from PyQt6.QtGui import QFontDatabase

        # Ищем в папке рядом с .exe или в корне проекта
        if getattr(sys, "frozen", False):
            base = os.path.dirname(sys.executable)
        else:
            base = os.path.dirname(os.path.abspath(__file__))

        fonts_dir = os.path.join(base, "assets", "fonts")

        if not os.path.isdir(fonts_dir):
            return

        loaded = 0
        for fname in os.listdir(fonts_dir):
            if fname.lower().endswith((".ttf", ".otf")):
                path = os.path.join(fonts_dir, fname)
                fid = QFontDatabase.addApplicationFont(path)
                if fid != -1:
                    loaded += 1

        print(f"[Fonts] Загружено шрифтов: {loaded}")
    except Exception as e:
        print(f"[Fonts] Ошибка: {e}")


def main():
    _setup_paths()

    start_minimized = "--minimized" in sys.argv

    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    from gui.tray_icon import create_icon

    QApplication.setQuitOnLastWindowClosed(False)

    app = QApplication(sys.argv)
    app.setApplicationName("AegisScan")
    app.setWindowIcon(create_icon("#10b981"))

    _load_fonts()

    window = MainWindow()
    window.start_minimized = start_minimized

    if start_minimized:
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