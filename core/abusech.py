"""
Модуль проверки файлов и URL через abuse.ch (MalwareBazaar, URLhaus).
"""
import os
import hashlib
import requests
from requests.exceptions import Timeout, ConnectionError, RequestException
from dotenv import load_dotenv

load_dotenv()

ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY")
TIMEOUT = 15


def _headers():
    if not ABUSECH_AUTH_KEY:
        return None
    return {"Auth-Key": ABUSECH_AUTH_KEY}


def sha256_of(filepath: str) -> str:
    """Считает SHA-256 файла."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _safe(method, url, **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    try:
        return requests.request(method, url, **kwargs), None
    except Timeout:
        return None, "Таймаут: abuse.ch не ответил"
    except ConnectionError:
        return None, "Нет соединения с abuse.ch"
    except RequestException as e:
        return None, f"Ошибка сети: {e}"


def check_malwarebazaar(filepath: str) -> dict:
    if not ABUSECH_AUTH_KEY:
        return {
            "status": "error",
            "message": "ABUSECH_AUTH_KEY не задан в .env",
        }

    file_hash = sha256_of(filepath)
    headers = _headers()

    response, err = _safe(
        "POST",
        "https://mb-api.abuse.ch/api/v1/",
        headers=headers,
        data={"query": "get_info", "hash": file_hash},
    )
    if err:
        return {"status": "error", "message": err}

    if response.status_code == 401:
        return {"status": "error", "message": "Неверный ABUSECH_AUTH_KEY (401)"}
    if response.status_code != 200:
        return {"status": "error", "message": f"HTTP {response.status_code}"}

    result = response.json()
    qs = result.get("query_status")

    if qs == "hash_not_found":
        return {
            "status": "found",
            "source": "MalwareBazaar",
            "hash": file_hash,
            "malicious": 0,
            "total": 1,
            "verdict": "clean",
            "message": "Файл не найден в базе malware — вероятно, чистый",
        }

    if qs == "ok":
        info = result["data"][0]
        return {
            "status": "found",
            "source": "MalwareBazaar",
            "hash": file_hash,
            "malicious": 1,
            "total": 1,
            "verdict": "malware",
            "signature": info.get("signature"),
            "file_type": info.get("file_type"),
            "first_seen": info.get("first_seen"),
            "message": f"Найден в базе malware: {info.get('signature', 'неизвестно')}",
        }

    return {"status": "error", "message": f"Неизвестный ответ: {qs}"}


def check_url_urlhaus(url_to_check: str) -> dict:
    if not ABUSECH_AUTH_KEY:
        return {"status": "error", "message": "ABUSECH_AUTH_KEY не задан в .env"}

    headers = _headers()
    response, err = _safe(
        "POST",
        "https://urlhaus-api.abuse.ch/v1/url/",
        headers=headers,
        data={"url": url_to_check},
    )
    if err:
        return {"status": "error", "message": err}
    if response.status_code == 401:
        return {"status": "error", "message": "Неверный ABUSECH_AUTH_KEY (401)"}
    if response.status_code != 200:
        return {"status": "error", "message": f"HTTP {response.status_code}"}

    result = response.json()
    qs = result.get("query_status")

    if qs == "no_results":
        return {
            "status": "found",
            "source": "URLhaus",
            "malicious": 0,
            "total": 1,
            "verdict": "clean",
            "message": "URL не найден в базе вредоносных",
        }

    if qs == "ok":
        return {
            "status": "found",
            "source": "URLhaus",
            "malicious": 1,
            "total": 1,
            "verdict": "malware",
            "threat": result.get("threat"),
            "message": f"URL в базе: {result.get('threat')}",
        }

    return {"status": "error", "message": f"Неизвестный ответ: {qs}"}