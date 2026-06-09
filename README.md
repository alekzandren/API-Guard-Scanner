# API-Guard-Scanner

An advanced, asynchronous Python-based security tool designed to audit API endpoints for missing critical security headers. Built with modern Python 3.13 features, `httpx`, `pydantic-settings` and `Pydantic v2` following **Security by Design** principles and **OWASP API Security Top 10** best practices.

## Key Features

* **Object-Oriented Architecture**: Formulated around a modular, class-based design ( class) to ensure code reusability, strict encapsulation, and clean state management. `APIScanner`
* **Asynchronous & High-Performance**: Powered by and for fast, non-blocking parallel scanning of multiple endpoints. `asyncio` `httpx`
* **Security by Design**: Strict input and environmental validation via to eliminate configuration injection risks. `pydantic-settings`
* **Sensitive Data Protection**: Safe logging mechanisms that ensure authorization tokens (e.g., JWT) never leak into stdout or log files.
* **OWASP API Security Alignment**: Specifically targets **API10:2023 (Improper Inventory Management)** by ensuring the API baseline transport defense is properly configured.
* **Resilient Architecture**: Implements connection pool management () to prevent accidental DoS on target environments and includes an automated linear retry mechanism () with graceful exception handling for unstable network conditions. `httpx.Limits` `MAX_RETRIES`

---

## Monitored Security Headers

The scanner checks for the missing presence of the following critical security headers:

| Header | Purpose | Risk if Missing |
| :--- | :--- | :--- |
| `Strict-Transport-Security` (HSTS) | Forces HTTPS connections | MitM (Man-in-the-Middle) attacks |
| `Content-Security-Policy` (CSP) | Restricts resource loading | Cross-Site Scripting (XSS), Data Injections |
| `X-Content-Type-Options` | Prevents MIME-sniffing | Drive-by downloads, execution of malicious payloads |
| `X-Frame-Options` | Controls framing/iFrames | Clickjacking attacks |

---

## Installation & Setup

### Prerequisites
* **Python 3.13+**
* `pip` or `poetry`


### 1. Clone the Repository
```bash
git clone [https://github.com/your-username/API-Guard-Scanner.git](https://github.com/your-username/API-Guard-Scanner.git)
cd API-Guard-Scanner
```

### Install Dependencies
```bash
pip install -r requirements.txt
```
(Dependencies: `httpx`, `pydantic`, `pydantic-settings`)


### 3. Configuration
Create a `.env` file in the root directory of the project:
```Code snippet
# Target API Base URL (Strictly validated as a proper URL)
TARGET_BASE_URL=[https://api.example.com](https://api.example.com)

# Your Authorization Token (Passed securely in request headers)
API_BEARER_TOKEN=your_secret_jwt_token_here

# Request timeout in seconds (Default: 10.0)
REQUEST_TIMEOUT=10.0
```

---

## Usage
To define the specific endpoints you want to scan, modify the `endpoints_to_scan` list within the `main()` function inside `security_scanner.py`.
Run the scanner:
```bash
python security_scanner.py
```

### Example Output
```Plaintext
2026-06-04 12:00:01 - [INFO] - Запуск сканирования для API: [https://api.example.com](https://api.example.com)
2026-06-04 12:00:01 - [INFO] - Сканирование эндпоинта: [https://api.example.com/v1/users/me](https://api.example.com/v1/users/me)
2026-06-04 12:00:02 - [WARNING] - [УЯЗВИМОСТЬ] Эндпоинт [https://api.example.com/v1/users/me](https://api.example.com/v1/users/me) уязвим! Отсутствуют критические заголовки: Content-Security-Policy, X-Frame-Options
2026-06-04 12:00:02 - [INFO] - [БЕЗОПАСНО] Эндпоинт [https://api.example.com/v1/auth/status](https://api.example.com/v1/auth/status) содержит все базовые заголовки безопасности.
```

---

## Security Disclaimer
**Disclaimer**: This tool is developed strictly for authorized security auditing, vulnerability assessment, and educational purposes. Scaling tests against environments without prior written consent from the system owners is illegal. The author holds no liability for misuse or damage caused by this program.

---

## License
This project is licensed under the MIT License - see the LICENSE file for details.
