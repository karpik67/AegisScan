"""
ИИ-модель (LightGBM) для обнаружения zero-day malware.
Загружает model/lgbm_model.txt и делает предсказание по PE-файлу.
Работает и из исходников, и из .exe (PyInstaller).
"""
import os
import sys
import lightgbm as lgb
import pandas as pd

from core.feature_extractor import extract_features, FEATURE_ORDER


def _resource_path(relative: str) -> str:
    """Возвращает абсолютный путь к ресурсу (из .exe или из исходников)."""
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
        return os.path.join(base, relative)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, relative)


MODEL_PATH = _resource_path("model/lgbm_model.txt")

_model = None


def _load_model():
    """Ленивая загрузка модели при первом обращении."""
    global _model
    if _model is not None:
        return _model

    if not os.path.isfile(MODEL_PATH):
        print(f"[AI] Модель не найдена: {MODEL_PATH}")
        return None

    try:
        _model = lgb.Booster(model_file=MODEL_PATH)
        return _model
    except Exception as e:
        print(f"[AI] Ошибка загрузки модели: {e}")
        return None


def scan_file(filepath: str) -> dict:
    """Проверяет файл через ИИ-модель."""
    model = _load_model()
    if model is None:
        return {
            "status": "error",
            "message": "Модель не загружена (model/lgbm_model.txt отсутствует)",
        }

    features = extract_features(filepath)
    if features is None:
        return {
            "status": "error",
            "message": "Файл не является PE — ИИ-анализ невозможен",
        }

    vector = [features.get(name, 0) for name in FEATURE_ORDER]
    df = pd.DataFrame([vector], columns=FEATURE_ORDER)

    prob = float(model.predict(df)[0])

    if prob >= 0.70:
        verdict = "malware"
        malicious = 1
    elif prob >= 0.40:
        verdict = "suspicious"
        malicious = 0
    else:
        verdict = "clean"
        malicious = 0

    return {
        "status": "found",
        "source": "AI Model",
        "malicious": malicious,
        "total": 1,
        "verdict": verdict,
        "probability": prob,
        "features": features,
        "message": f"Вероятность malware: {prob*100:.1f}%",
    }