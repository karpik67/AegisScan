"""
Управление автозапуском AegisScan в Windows.
Через реестр HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
"""
import os
import sys
import winreg


APP_NAME = "AegisScan"
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _get_exe_command() -> str:
    """Команда для автозапуска (с флагом --minimized)."""
    if getattr(sys, "frozen", False):
        # Запущено из .exe
        return f'"{sys.executable}" --minimized'
    else:
        # Из исходников — pythonw без консоли
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.isfile(pythonw):
            pythonw = sys.executable
        main_py = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "main.py",
        )
        return f'"{pythonw}" "{main_py}" --minimized'


def is_enabled() -> bool:
    """Проверяет, зарегистрирован ли автозапуск."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ
        ) as key:
            try:
                winreg.QueryValueEx(key, APP_NAME)
                return True
            except FileNotFoundError:
                return False
    except Exception:
        return False


def enable() -> dict:
    """Включает автозапуск."""
    try:
        cmd = _get_exe_command()
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
        return {"status": "ok", "command": cmd}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def disable() -> dict:
    """Отключает автозапуск."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE
        ) as key:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def sync_with_config(enabled: bool) -> dict:
    """Синхронизирует реестр с настройкой из config."""
    if enabled:
        return enable()
    else:
        return disable()