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

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-chat"
TIMEOUT = 60

# Системный промпт — жёстко ограничиваем роль
SYSTEM_PROMPT = """Ты — ИИ-помощник антивируса AegisScan. Твоя ЕДИНСТВЕННАЯ задача — помогать пользователю с:
1. Работой программы AegisScan (сканирование, карантин, журнал, настройки).
2. Кибербезопасностью (вирусы, фишинг, пароли, безопасность в сети).
3. Компьютерной грамотностью (как работают программы, ОС, файлы).

СТРОГИЕ ПРАВИЛА:
- Если вопрос НЕ относится к этим темам — вежливо откажись отвечать и предложи вернуться к работе антивируса. Пример: «Извините, я могу помочь только с вопросами об AegisScan и кибербезопасности».
- НИКОГДА не обсуждай: политику, религию, войны, конфликты, национальность, историю, спорт, знаменитостей, личные темы.
- Не давай советы по взлому, обходу защиты, созданию вирусов — это запрещено.
- Отвечай кратко (до 5 предложений), дружелюбно, на русском языке.
- Если не знаешь ответа — честно скажи об этом.

Помни: ты — часть антивируса, а не универсальный чат-бот."""


def is_available() -> bool:
    """Проверяет, задан ли API-ключ."""
    return bool(DEEPSEEK_API_KEY)


def chat(messages: list) -> dict:
    """
    Отправляет список сообщений в DeepSeek API.

    messages — список словарей вида:
        [{"role": "user", "content": "Привет!"}, ...]

    Возвращает:
        {"status": "ok", "reply": "..."}
        или
        {"status": "error", "message": "..."}
    """
    if not DEEPSEEK_API_KEY:
        return {
            "status": "error",
            "message": "DEEPSEEK_API_KEY не задан в .env",
        }

    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json",
    }

    # Добавляем системный промпт в начало
    full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages

    payload = {
        "model": MODEL,
        "messages": full_messages,
        "temperature": 0.7,
        "max_tokens": 800,
    }

    try:
        response = requests.post(
            DEEPSEEK_API_URL,
            headers=headers,
            json=payload,
            timeout=TIMEOUT,
        )
    except Timeout:
        return {"status": "error", "message": "Таймаут: DeepSeek не ответил за 60 сек"}
    except ConnectionError:
        return {"status": "error", "message": "Нет соединения с DeepSeek (проверьте интернет)"}
    except RequestException as e:
        return {"status": "error", "message": f"Ошибка сети: {e}"}

    if response.status_code == 401:
        return {"status": "error", "message": "Неверный API-ключ DeepSeek (401)"}
    if response.status_code == 402:
        return {"status": "error", "message": "Недостаточно средств на балансе DeepSeek (402)"}
    if response.status_code == 429:
        return {"status": "error", "message": "Слишком много запросов, подождите немного (429)"}
    if response.status_code != 200:
        return {"status": "error", "message": f"Ошибка API: {response.status_code}"}

    data = response.json()
    try:
        reply = data["choices"][0]["message"]["content"]
        return {"status": "ok", "reply": reply}
    except (KeyError, IndexError):
        return {"status": "error", "message": f"Неожиданный ответ: {data}"}