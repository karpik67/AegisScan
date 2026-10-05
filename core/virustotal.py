import os
import sys
import requests
from requests.exceptions import Timeout, ConnectionError, RequestException
from dotenv import load_dotenv


def _find_env():
    """Ищет .env рядом с .exe (для frozen) или в корне проекта."""
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), ".env")
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
    )


load_dotenv(_find_env())

VT_API_KEY = os.getenv("VT_API_KEY")
PROXY_URL = os.getenv("PROXY_URL")
VT_API_URL = "https://www.virustotal.com/api/v3"

TIMEOUT = 10
_cache = {}


def _headers():
    return {"x-apikey": VT_API_KEY}


def _proxies():
    if not PROXY_URL:
        return None
    return {"http": PROXY_URL, "https": PROXY_URL}


def get_file_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _extract_engines(results: dict) -> list:
    engines = []
    for name, info in results.items():
        if info.get("category") in ("malicious", "suspicious"):
            engines.append({
                "name": name,
                "result": info.get("result"),
                "category": info.get("category"),
            })
    return engines


def _safe_request(method: str, url: str, **kwargs):
    """Обёртка вокруг requests с обработкой ошибок."""
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("proxies", _proxies())
    try:
        return requests.request(method, url, **kwargs), None
    except Timeout:
        return None, "Таймаут: VirusTotal не ответил за 10 секунд"
    except ConnectionError:
        return None, "Нет соединения с VirusTotal (DPI-блокировка или нужен VPN)"
    except RequestException as e:
        return None, f"Ошибка сети: {e}"


def scan_hash(file_hash: str) -> dict:
    if file_hash in _cache:
        return _cache[file_hash]

    url = f"{VT_API_URL}/files/{file_hash}"
    response, err = _safe_request("GET", url, headers=_headers())
    if err:
        return {"status": "error", "message": err}

    if response.status_code == 404:
        result = {"status": "not_found", "message": "Файл не найден в базе VirusTotal"}
        _cache[file_hash] = result
        return result

    if response.status_code == 401:
        return {"status": "error", "message": "Неверный API-ключ VT (401)"}

    if response.status_code == 429:
        return {"status": "error", "message": "Лимит запросов VT исчерпан (429)"}

    if response.status_code != 200:
        return {"status": "error", "message": f"Ошибка API: {response.status_code}"}

    data = response.json()
    stats = data["data"]["attributes"]["last_analysis_stats"]
    result = {
        "status": "found",
        "hash": file_hash,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "total": sum(stats.values()),
        "source": "VirusTotal",
        "engines": _extract_engines(
            data["data"]["attributes"].get("last_analysis_results", {})
        ),
    }
    _cache[file_hash] = result
    return result


def upload_file(filepath: str) -> dict:
    url = f"{VT_API_URL}/files"
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        response, err = _safe_request(
            "POST", url, headers=_headers(), files=files, timeout=60
        )
    if err:
        return {"status": "error", "message": err}

    if response.status_code != 200:
        return {"status": "error", "message": f"Ошибка загрузки: {response.status_code}"}

    return {"status": "uploaded", "analysis_id": response.json()["data"]["id"]}


def get_analysis(analysis_id: str, max_wait: int = 30) -> dict:
    url = f"{VT_API_URL}/analyses/{analysis_id}"
    waited = 0
    while waited < max_wait:
        response, err = _safe_request("GET", url, headers=_headers())
        if err:
            return {"status": "error", "message": err}
        if response.status_code != 200:
            return {"status": "error", "message": f"Ошибка: {response.status_code}"}

        data = response.json()
        if data["data"]["attributes"]["status"] == "completed":
            stats = data["data"]["attributes"]["stats"]
            return {
                "status": "completed",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "source": "VirusTotal",
            }

        time.sleep(5)
        waited += 5

    return {"status": "timeout", "message": "Анализ не завершился за 30 секунд"}


def scan_file(filepath: str) -> dict:
    if not VT_API_KEY:
        return {"status": "error", "message": "VT_API_KEY не задан в .env"}

    file_hash = get_file_hash(filepath)
    result = scan_hash(file_hash)

    if result["status"] == "found":
        result["source"] = "VirusTotal (по хешу)"
        return result

    if result["status"] == "not_found":
        upload = upload_file(filepath)
        if upload["status"] != "uploaded":
            return upload
        time.sleep(3)
        analysis = get_analysis(upload["analysis_id"])
        analysis["source"] = "VirusTotal (загрузка)"
        analysis["hash"] = file_hash
        return analysis

    return result


def scan_url(url_to_scan: str) -> dict:
    if not VT_API_KEY:
        return {"status": "error", "message": "VT_API_KEY не задан в .env"}

    url = f"{VT_API_URL}/urls"
    response, err = _safe_request(
        "POST", url, headers=_headers(), data={"url": url_to_scan}
    )
    if err:
        return {"status": "error", "message": err}
    if response.status_code != 200:
        return {"status": "error", "message": f"Ошибка: {response.status_code}"}

    analysis_id = response.json()["data"]["id"]
    return get_analysis(analysis_id)