import asyncio
import logging
import os
from typing import Dict, List, Set
from pydantic import HttpUrl, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict
import httpx

class ScannerConfig(BaseSettings):
    """
    Класс конфигурации. Pydantic автоматически валидирует типы данных
    из перемнных окружения или .env файла, предотвращая Command Injection
    и некорректный формат URL.
    """
    target_base_url: HttpUrl
    api_bearer_token: str
    request_timeout: float = 10.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s"
)
logger = logging.getLogger("APISecurityScanner")

REQUIRED_SECURITY_HEADERS: Set[str] = {
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
}

async def check_endpoint_security_headers(
        client: httpx.AsyncClient,
        endpoint: str,
        headers: Dict[str, str]
) -> None:
    """
    Отправляет GET-запрос к эндпоинту и проверяет наличие заголовков безопасности.
    Реализована отказоустойчивость: падение одного запроса не ломает весь цикл.
    """
    clean_endpoint = endpoint.lstrip("/")
    url = f"{client.base_url}{clean_endpoint}"

    logger.info(f"Сканирование эндпоинта: {url}")

    try:
        response = await client.get(clean_endpoint, headers=headers)

        response_headers = response.headers
        missing_headers = []

        for req_header in REQUIRED_SECURITY_HEADERS:
            if req_header not in response_headers:
                missing_headers.append(req_header)

        if missing_headers:
            logger.warning(
                f"[УЯЗВИМОСТЬ] Эндпоинт {url} уязвим! "
                f"Отсутствуют критические заголовки: {', '.join(missing_headers)}"
            )
        else:
            logger.info(f"[БЕЗОПАСНО] Эндпоинт {url} содержит все базовые заголовки безопасности.")

    except httpx.TimeoutException:
        logger.error(f"[ОШИБКА] Таймаут соединения при запросе к {url}")
    except httpx.HTTPStatusError as exc:
        logger.error(f"[ОШИБКА] HTTP Error {exc.response.status_code} для {url}")
    except httpx.RequestError as exc:
        logger.error(f"[ОШИБКА] Ошибка запроса к {url}: {exc}")
    except Exception as exc:
        logger.critical(f"[КРИТИЧЕСКАЯ ОШИБКА] Непредвиденная ошибка при анализе {url}: {exc}")


async def main() -> None:
    try:
        config = ScannerConfig()
    except ValidationError as e:
        logger.critical(f"Ошибка валидации конфигурации .env: {e}")
        return

    request_headers = {
        "Authorization": f"Bearer {config.api_bearer_token}",
        "User-Agent": "SecOps-API-Scanner/1.0",
        "Accept": "application/json"
    }

    endpoints_to_scan: List[str] = [
        "/v1/users/me",
        "/v1/auth/status",
        "/v2/data/analytics",
        "invalid-path-test"
    ]

    logger.info(f"Запуск сканирования для API: {config.target_base_url}")

    limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)

    async with httpx.AsyncClient(
            base_url=str(config.target_base_url),
            timeout=config.request_timeout,
            limits=limits
    ) as client:

        tasks = [
            check_endpoint_security_headers(client, endpoint, request_headers)
            for endpoint in endpoints_to_scan
        ]

        await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Сканирование прервано пользователем.")