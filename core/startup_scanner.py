"""
Сканер автозагрузки Windows.
Проверяет: реестр Run/RunOnce, папки Startup, планировщик задач, службы.
"""
import os
import subprocess
import winreg


def _run_ps(cmd: str, timeout: int = 10) -> str:
    """Выполняет PowerShell-команду, возвращает stdout."""
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=0x08000000,
        )
        return r.stdout
    except Exception:
        return ""


def _is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    low = path.lower()
    bad = [
        "\\temp\\", "\\tmp\\", "\\downloads\\", "\\public\\",
        "\\programdata\\", "\\$recycle.bin", "\\appdata\\local\\temp",
    ]
    return any(s in low for s in bad)


def _extract_exe_path(command: str) -> str:
    """Извлекает путь к .exe из командной строки."""
    if not command:
        return ""
    cmd = command.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end > 0:
            return cmd[1:end]
    # без кавычек — до первого пробела
    parts = cmd.split(" ", 1)
    return parts[0] if parts else ""


def _check_file(path: str) -> dict:
    """Проверяет файл: существует, подписан."""
    if not path or not os.path.isfile(path):
        return {"exists": False, "signature": "unknown"}

    try:
        cmd = f"(Get-AuthenticodeSignature '{path}').Status"
        status = _run_ps(cmd, timeout=5).strip()
        if status == "Valid":
            sig = "valid"
        elif status in ("NotSigned", "HashMismatch", "UnknownError"):
            sig = "unsigned"
        else:
            sig = "unknown"
    except Exception:
        sig = "unknown"

    return {"exists": True, "signature": sig}


# ============= Источники автозагрузки =============

def scan_registry_run() -> list:
    """Сканирует ключи реестра Run/RunOnce."""
    items = []

    locations = [
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run",
         "HKCU\\Run"),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
         "HKLM\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
         "HKLM\\Run (x86)"),
    ]

    for hive, path, label in locations:
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                    except OSError:
                        break

                    exe = _extract_exe_path(value)
                    info = _check_file(exe)
                    items.append({
                        "name": name,
                        "command": value,
                        "exe": exe,
                        "source": label,
                        "type": "registry",
                        "exists": info["exists"],
                        "signature": info["signature"],
                    })
        except FileNotFoundError:
            continue
        except Exception:
            continue

    return items


def scan_startup_folders() -> list:
    """Сканирует папки Startup (пользователь + система)."""
    items = []

    folders = [
        (os.path.join(os.environ.get("APPDATA", ""),
                      r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "Startup (пользователь)"),
        (os.path.join(os.environ.get("PROGRAMDATA", ""),
                      r"Microsoft\Windows\Start Menu\Programs\Startup"),
         "Startup (система)"),
    ]

    for folder, label in folders:
        if not os.path.isdir(folder):
            continue
        try:
            for fname in os.listdir(folder):
                if fname.lower() == "desktop.ini":
                    continue
                fpath = os.path.join(folder, fname)
                info = _check_file(fpath)
                items.append({
                    "name": fname,
                    "command": fpath,
                    "exe": fpath,
                    "source": label,
                    "type": "startup_folder",
                    "exists": info["exists"],
                    "signature": info["signature"],
                })
        except Exception:
            continue

    return items


def scan_scheduled_tasks() -> list:
    """Сканирует задачи планировщика, которые запускаются при входе/старте."""
    items = []

    # PowerShell → CSV список задач
    cmd = (
        "Get-ScheduledTask | "
        "Where-Object { $_.State -ne 'Disabled' -and "
        "($_.Triggers.CimClass.CimClassName -contains 'MSFT_TaskLogonTrigger' "
        "-or $_.Triggers.CimClass.CimClassName -contains 'MSFT_TaskBootTrigger') } | "
        "Select-Object TaskName, TaskPath, "
        "@{N='Action';E={$_.Actions.Execute}} | "
        "ConvertTo-Csv -NoTypeInformation"
    )
    out = _run_ps(cmd, timeout=20)

    if not out:
        return items

    lines = out.strip().splitlines()
    for line in lines[1:]:  # пропускаем заголовок
        try:
            # CSV: "TaskName","TaskPath","Action"
            parts = []
            cur = ""
            in_q = False
            for ch in line:
                if ch == '"':
                    in_q = not in_q
                elif ch == ',' and not in_q:
                    parts.append(cur)
                    cur = ""
                else:
                    cur += ch
            parts.append(cur)

            if len(parts) < 3:
                continue

            name = parts[0].strip().strip('"')
            task_path = parts[1].strip().strip('"')
            action = parts[2].strip().strip('"')

            exe = _extract_exe_path(action)
            info = _check_file(exe)

            items.append({
                "name": f"{task_path}{name}",
                "command": action,
                "exe": exe,
                "source": "Планировщик задач",
                "type": "scheduled_task",
                "exists": info["exists"],
                "signature": info["signature"],
            })
        except Exception:
            continue

    return items


# ============= Анализ подозрительности =============

def analyze(item: dict) -> dict:
    """Добавляет к записи флаг suspicious + причины."""
    reasons = []

    exe = item.get("exe", "")
    cmd = item.get("command", "")

    if not item.get("exists", True) and exe:
        reasons.append("Файл не существует")

    if _is_suspicious_path(exe):
        reasons.append("Запуск из временной папки")

    if item.get("signature") == "unsigned":
        reasons.append("Без цифровой подписи")

    low = cmd.lower()
    if "powershell" in low and ("-enc" in low or "-encodedcommand" in low):
        reasons.append("Запуск PowerShell с шифрованной командой")

    if "cmd.exe" in low and ("/c " in low and len(cmd) < 200):
        # Что-то типа cmd /c start ... — подозрительно
        reasons.append("Запуск через cmd /c")

    if "wscript" in low or "cscript" in low:
        reasons.append("Запуск через WScript/Cscript")

    item["reasons"] = reasons
    item["suspicious"] = len(reasons) > 0
    return item


def get_all_startup_items() -> list:
    """Возвращает все записи автозагрузки с анализом."""
    items = []
    items.extend(scan_registry_run())
    items.extend(scan_startup_folders())
    try:
        items.extend(scan_scheduled_tasks())
    except Exception as e:
        print(f"[Startup] Ошибка планировщика: {e}")

    # Анализ
    items = [analyze(i) for i in items]

    # Сортировка: подозрительные вверху
    items.sort(key=lambda x: (not x["suspicious"], x["name"].lower()))
    return items


# ============= Удаление записей =============

def remove_registry_item(source_label: str, name: str) -> dict:
    """Удаляет запись из реестра."""
    locations = {
        "HKCU\\Run": (winreg.HKEY_CURRENT_USER,
                      r"Software\Microsoft\Windows\CurrentVersion\Run"),
        "HKCU\\RunOnce": (winreg.HKEY_CURRENT_USER,
                          r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        "HKLM\\Run": (winreg.HKEY_LOCAL_MACHINE,
                      r"Software\Microsoft\Windows\CurrentVersion\Run"),
        "HKLM\\RunOnce": (winreg.HKEY_LOCAL_MACHINE,
                          r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        "HKLM\\Run (x86)": (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        ),
    }

    if source_label not in locations:
        return {"status": "error", "message": "Неизвестный источник"}

    hive, path = locations[source_label]
    try:
        with winreg.OpenKey(hive, path, 0,
                            winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
        return {"status": "ok"}
    except FileNotFoundError:
        return {"status": "error", "message": "Запись не найдена"}
    except PermissionError:
        return {"status": "error",
                "message": "Нет прав. Запустите от администратора"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def remove_startup_file(path: str) -> dict:
    """Удаляет файл из папки Startup."""
    try:
        if os.path.isfile(path):
            os.remove(path)
            return {"status": "ok"}
        return {"status": "error", "message": "Файл не найден"}
    except PermissionError:
        return {"status": "error",
                "message": "Нет прав. Запустите от администратора"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def remove_scheduled_task(task_name: str) -> dict:
    """Удаляет задачу планировщика."""
    try:
        out = _run_ps(f"Unregister-ScheduledTask -TaskName '{task_name}' "
                      f"-Confirm:$false", timeout=15)
        return {"status": "ok", "output": out}
    except Exception as e:
        return {"status": "error", "message": str(e)}