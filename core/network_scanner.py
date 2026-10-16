"""
Сканер сетевых соединений.
"""
import socket
import psutil
import requests
from requests.exceptions import RequestException


# Порты, которые обычно безопасны
SAFE_PORTS = {
    80, 443, 53, 25, 110, 143, 993, 995,
    587, 465, 8080, 8443, 5228, 5229, 5230,
    3478, 3479, 3480, 27015, 27016,
}

# Порты, часто используемые malware/backdoor'ами
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 1337, 31337,
    12345, 54321, 65535, 9999,
    8081, 9998, 10000, 10001,
}

_country_cache = {}


def _is_local(ip: str) -> bool:
    """Проверяет, локальный ли адрес."""
    if not ip or ip == "0.0.0.0" or ip == "::" or ip == "—":
        return True
    if ip.startswith("127.") or ip.startswith("192.168."):
        return True
    if ip.startswith("10.") or ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    if ip.startswith("fe80:") or ip == "::1":
        return True
    return False


def _get_process_info(pid: int) -> dict:
    if not pid:
        return {"name": "—", "exe": "—"}
    try:
        p = psutil.Process(pid)
        return {"name": p.name(), "exe": p.exe() or "—"}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return {"name": "—", "exe": "—"}
    except Exception:
        return {"name": "—", "exe": "—"}


def _is_suspicious_exe(exe: str) -> bool:
    """Только явные признаки: temp, appdata\\local\\temp."""
    if not exe:
        return False
    low = exe.lower()
    bad = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\"]
    return any(s in low for s in bad)


def get_connections(only_established: bool = True) -> list:
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print("[Network] Нужны права администратора")
        return []
    except Exception as e:
        print(f"[Network] Ошибка: {e}")
        return []

    result = []

    for c in conns:
        try:
            status = c.status or "—"
            if only_established and status not in ("ESTABLISHED", "SYN_SENT"):
                continue

            if c.type == socket.SOCK_STREAM:
                ctype = "TCP"
            elif c.type == socket.SOCK_DGRAM:
                ctype = "UDP"
            else:
                ctype = "?"

            l_ip = c.laddr.ip if c.laddr else "—"
            l_port = c.laddr.port if c.laddr else 0
            local = f"{l_ip}:{l_port}" if l_ip != "—" else "—"

            r_ip = c.raddr.ip if c.raddr else "—"
            r_port = c.raddr.port if c.raddr else 0
            remote = f"{r_ip}:{r_port}" if r_ip != "—" else "—"

            pinfo = _get_process_info(c.pid)

            # === Определяем "внешний" ли трафик ===
            # Локальные соединения (127.x, 192.168.x) — не считаем трафиком
            is_local_conn = _is_local(r_ip) or r_ip == "—"

            reasons = []

            # 1. Подозрительный удалённый порт (только для внешних)
            if (not is_local_conn and r_port
                    and r_port in SUSPICIOUS_PORTS):
                reasons.append(f"Подозрительный порт {r_port}")

            # 2. Процесс из temp — только если это ВНЕШНЕЕ соединение
            if (not is_local_conn
                    and _is_suspicious_exe(pinfo["exe"])):
                reasons.append("Процесс из temp с внешним соединением")

            # 3. Слушает порт (LISTEN) с подозрительным номером
            if status == "LISTEN" and l_port in SUSPICIOUS_PORTS:
                reasons.append(f"Слушает подозрительный порт {l_port}")

            # 4. Соединение с портом 0 (странно)
            if r_port == 0 and not is_local_conn:
                reasons.append("Удалённый порт = 0")

            suspicious = len(reasons) > 0

            result.append({
                "pid": c.pid or 0,
                "process": pinfo["name"],
                "exe": pinfo["exe"],
                "local": local,
                "remote": remote,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "status": status,
                "type": ctype,
                "country": "—",
                "is_local": is_local_conn,
                "suspicious": suspicious,
                "reasons": reasons,
            })
        except Exception:
            continue

    # Подозрительные вверху, потом по имени
    result.sort(key=lambda x: (not x["suspicious"], x["process"].lower()))
    return result


def get_country(ip: str) -> str:
    if not ip or ip == "—" or _is_local(ip):
        return "Локальный"

    if ip in _country_cache:
        return _country_cache[ip]

    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                country = data.get("country", "—")
                city = data.get("city", "")
                code = data.get("country_code", "")
                flag = ""
                if code and len(code) == 2:
                    try:
                        flag = "".join(
                            chr(0x1F1E6 + ord(c) - ord("A"))
                            for c in code.upper()
                        )
                    except Exception:
                        flag = ""
                text = f"{flag} {country}"
                if city:
                    text += f", {city}"
                _country_cache[ip] = text
                return text
    except RequestException:
        pass
    except Exception:
        pass

    _country_cache[ip] = "—"
    return "—"


def enrich_with_countries(connections: list, progress_callback=None) -> list:
    unique_ips = list({
        c["remote_ip"] for c in connections
        if c["remote_ip"] and c["remote_ip"] != "—"
        and not _is_local(c["remote_ip"])
    })

    total = len(unique_ips)
    for i, ip in enumerate(unique_ips, 1):
        get_country(ip)
        if progress_callback:
            progress_callback(i, total)

    for c in connections:
        ip = c["remote_ip"]
        if ip and ip != "—":
            c["country"] = _country_cache.get(ip, "—")

    return connections


def kill_process(pid: int) -> dict:
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
        return {"status": "ok"}
    except psutil.NoSuchProcess:
        return {"status": "error", "message": "Процесс уже завершён"}
    except psutil.AccessDenied:
        return {"status": "error",
                "message": "Нет прав. Запустите от администратора"}
    except Exception as e:
        return {"status": "error", "message": str(e)}