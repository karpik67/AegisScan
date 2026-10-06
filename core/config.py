"""
Управление настройками AegisScan.
Хранит настройки в JSON рядом с .exe (или в корне проекта).
"""
import os
import sys
import json


DEFAULT_CONFIG = {
    "ai_threshold": 0.70,
    "enable_yara": True,
    "enable_malwarebazaar": True,
    "enable_virustotal": False,
    "enable_ai": True,
    "save_history": True,
    "autostart": False,
    "start_minimized": True,
    "theme": "dark",
}


def _config_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "config.json")


def load() -> dict:
    path = _config_path()
    if not os.path.isfile(path):
        return DEFAULT_CONFIG.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = DEFAULT_CONFIG.copy()
        result.update(data)
        return result
    except Exception as e:
        print(f"[Config] Ошибка загрузки: {e}")
        return DEFAULT_CONFIG.copy()


def save(config: dict) -> bool:
    path = _config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"[Config] Ошибка сохранения: {e}")
        return False


def get(key: str):
    return load().get(key, DEFAULT_CONFIG.get(key))


def set_value(key: str, value) -> bool:
    config = load()
    config[key] = value
    return save(config)