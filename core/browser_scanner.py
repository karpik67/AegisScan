"""
Сканер браузеров: расширения, прокси, настройки.
Поддерживает Chrome, Edge, Brave, Firefox.
"""
import os
import json
import winreg


def _get_browser_paths() -> dict:
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")

    return {
        "Chrome": {
            "user_data": os.path.join(local, r"Google\Chrome\User Data"),
            "type": "chromium",
        },
        "Edge": {
            "user_data": os.path.join(local, r"Microsoft\Edge\User Data"),
            "type": "chromium",
        },
        "Brave": {
            "user_data": os.path.join(
                local, r"BraveSoftware\Brave-Browser\User Data"
            ),
            "type": "chromium",
        },
        "Firefox": {
            "profiles_dir": os.path.join(
                roaming, r"Mozilla\Firefox\Profiles"
            ),
            "type": "firefox",
        },
    }


def _get_chromium_extensions(user_data_dir: str, browser: str) -> list:
    """Расширения Chrome/Edge/Brave."""
    extensions = []

    if not os.path.isdir(user_data_dir):
        return extensions

    for profile in os.listdir(user_data_dir):
        if not (profile == "Default" or profile.startswith("Profile ")):
            continue

        profile_dir = os.path.join(user_data_dir, profile)
        ext_dir = os.path.join(profile_dir, "Extensions")

        if not os.path.isdir(ext_dir):
            continue

        for ext_id in os.listdir(ext_dir):
            ext_path = os.path.join(ext_dir, ext_id)
            if not os.path.isdir(ext_path):
                continue

            for version in os.listdir(ext_path):
                version_path = os.path.join(ext_path, version)
                manifest_path = os.path.join(version_path, "manifest.json")

                if not os.path.isfile(manifest_path):
                    continue

                try:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        manifest = json.load(f)

                    name = manifest.get("name", "—")
                    version_str = manifest.get("version", "—")
                    description = manifest.get("description", "")
                    permissions = manifest.get("permissions", [])
                    host_permissions = manifest.get("host_permissions", [])

                    all_perms = permissions + host_permissions
                    reasons = []

                    if "<all_urls>" in all_perms or "*://*/*" in all_perms:
                        reasons.append("Доступ ко всем сайтам")

                    if ("webRequest" in permissions
                            and "webRequestBlocking" in permissions):
                        reasons.append("Перехват трафика")

                    if "cookies" in permissions and "<all_urls>" in all_perms:
                        reasons.append("Чтение cookies всех сайтов")

                    if "downloads" in permissions:
                        reasons.append("Управление загрузками")

                    if not name or len(name) < 3:
                        reasons.append("Подозрительное имя")

                    if description:
                        desc_short = description[:80]
                        if len(description) > 80:
                            desc_short += "..."
                    else:
                        desc_short = ""

                    extensions.append({
                        "id": ext_id,
                        "name": name,
                        "version": version_str,
                        "description": desc_short,
                        "browser": browser,
                        "profile": profile,
                        "permissions": len(all_perms),
                        "path": version_path,
                        "suspicious": len(reasons) > 0,
                        "reasons": reasons,
                    })
                    break
                except Exception:
                    continue

    return extensions


def _get_firefox_extensions(profiles_dir: str) -> list:
    """Расширения Firefox."""
    extensions = []

    if not os.path.isdir(profiles_dir):
        return extensions

    for profile in os.listdir(profiles_dir):
        profile_dir = os.path.join(profiles_dir, profile)
        ext_json = os.path.join(profile_dir, "extensions.json")

        if not os.path.isfile(ext_json):
            continue

        try:
            with open(ext_json, "r", encoding="utf-8") as f:
                data = json.load(f)

            for addon in data.get("addons", []):
                if addon.get("type") != "extension":
                    continue
                if addon.get("location") == "app-builtin":
                    continue

                name = addon.get("defaultLocale", {}).get("name", "—")
                version = addon.get("version", "—")
                ext_id = addon.get("id", "—")
                description = addon.get("defaultLocale", {}).get(
                    "description", ""
                )

                perms = addon.get("permissions", {})
                hosts = perms.get("hosts", [])
                apis = perms.get("permissions", [])

                reasons = []
                if "<all_urls>" in hosts or "*://*/*" in hosts:
                    reasons.append("Доступ ко всем сайтам")
                if not name or len(name) < 3:
                    reasons.append("Подозрительное имя")

                desc_short = description[:80]
                if len(description) > 80:
                    desc_short += "..."

                extensions.append({
                    "id": ext_id,
                    "name": name,
                    "version": version,
                    "description": desc_short,
                    "browser": "Firefox",
                    "profile": profile,
                    "permissions": len(hosts) + len(apis),
                    "path": profile_dir,
                    "suspicious": len(reasons) > 0,
                    "reasons": reasons,
                })
        except Exception:
            continue

    return extensions


def get_extensions() -> list:
    """Все расширения из всех браузеров."""
    result = []
    paths = _get_browser_paths()

    for name, info in paths.items():
        if info["type"] == "chromium":
            exts = _get_chromium_extensions(info["user_data"], name)
            result.extend(exts)
        elif info["type"] == "firefox":
            exts = _get_firefox_extensions(info["profiles_dir"])
            result.extend(exts)

    result.sort(
        key=lambda x: (not x["suspicious"], x["browser"], x["name"].lower())
    )
    return result


def get_proxy_settings() -> dict:
    """Читает настройки прокси Windows из реестра."""
    result = {
        "enabled": False,
        "server": "—",
        "bypass": "—",
        "autoconfig_url": "—",
        "suspicious": False,
        "reasons": [],
    }

    try:
        key_path = (
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                            winreg.KEY_READ) as key:
            try:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                result["enabled"] = bool(enabled)
            except FileNotFoundError:
                pass

            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                result["server"] = server
            except FileNotFoundError:
                pass

            try:
                bypass, _ = winreg.QueryValueEx(key, "ProxyOverride")
                result["bypass"] = bypass
            except FileNotFoundError:
                pass

            try:
                ac, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                result["autoconfig_url"] = ac
                if ac:
                    result["suspicious"] = True
                    result["reasons"].append(
                        f"Автонастройка прокси через URL: {ac}"
                    )
            except FileNotFoundError:
                pass

        if result["enabled"] and result["server"]:
            srv = result["server"].lower()
            if not ("127.0.0.1" in srv or "localhost" in srv):
                result["suspicious"] = True
                result["reasons"].append(
                    f"Активен внешний прокси: {result['server']}"
                )
    except Exception as e:
        result["reasons"].append(f"Ошибка чтения: {e}")

    return result