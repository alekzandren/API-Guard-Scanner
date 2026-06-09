import asyncio
import logging
import httpx
from pydantic_settings import SettingsConfigDict, BaseSettings
from typing import List, Dict, Set

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger("APISecurityScanner")


class ScannerConfig(BaseSettings):
    target_base_url: str
    api_bearer_token: str
    request_timeout: float = 10.0
    max_retries: int = 3

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


class APIScanner:
    REQUIRED_HEADERS: Set[str] = {
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options"
    }

    def __init__(self, config: ScannerConfig):
        self.config = config

    async def check_endpoint(self, client: httpx.AsyncClient, endpoint: str):
        url = f"{self.config.target_base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.config.api_bearer_token}"}

        for attempt in range(self.config.max_retries):
            try:
                response = await client.get(url, headers=headers, timeout=self.config.request_timeout)
                missing = [h for h in self.REQUIRED_HEADERS if h not in response.headers]

                if missing:
                    logger.warning(f"[УЯЗВИМ] {url} | Нет заголовков: {', '.join(missing)}")
                else:
                    logger.info(f"[БЕЗОПАСНО] {url}")
                return
            except httpx.HTTPError as e:
                logger.error(f"Попытка {attempt + 1} провалена для {url}: {e}")
                await asyncio.sleep(1)

        logger.critical(f"Не удалось просканировать {url} после {self.config.max_retries} попыток.")


async def main():
    config = ScannerConfig()
    endpoints = ["/v1/users/me", "/v1/auth/status"]

    async with httpx.AsyncClient() as client:
        scanner = APIScanner(config)
        tasks = [scanner.check_endpoint(client, ep) for ep in endpoints]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
