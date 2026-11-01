<h1 align="center">🛡️ leak-guard</h1>

<p align="center">
  Автоматический аудит и поиск утечек API-ключей, токенов и секретов в публичных репозиториях и истории коммитов GitHub
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/CLI-Rich-blueviolet" alt="CLI">
  <img src="https://img.shields.io/badge/status-active-brightgreen" alt="Status">
</p>

---

## ✨ Возможности

- 🔍 **Аудит портфолио GitHub**: автоматическое сканирование всех публичных репозиториев пользователя или организации.
- 🕰️ **Глубокий анализ истории Git**: находит секреты в старых коммитах, даже если они были удалены позже.
- 🎯 **Высокоточные правила детекции**:
  - **AI-провайдеры**: OpenAI (`sk-`), Anthropic Claude (`sk-ant-`), Google Gemini (`AIzaSy...`)
  - **Облачные сервисы**: AWS Access Key ID, AWS Secret Keys
  - **VCS & токены**: GitHub PAT (`ghp_`), GitLab токены
  - **Боты и мессенджеры**: токены Telegram-ботов, вебхуки и токены Slack / Discord
  - **Платежные шлюзы**: Stripe, Twilio
  - **Ключи и сертификаты**: приватные ключи RSA, SSH, PGP, EC
  - **Базы данных**: строки подключения с паролями (PostgreSQL, MySQL, MongoDB, Redis)
  - **Опасные файлы**: `.env`, `.env.local`, `serviceAccountKey.json`, `credentials.json`, `id_rsa`
- 🧠 **Энтропия Шеннона**: отсекает ложные срабатывания и отделяет настоящие токены от обычных строк.
- 🧼 **Фильтрация плейсхолдеров**: игнорирует шаблоны вроде `YOUR_API_KEY_HERE` и `process.env`.
- 📊 **Экспорт отчетов**:
  - Форматированный вывод в терминал с цветной индикацией критичности.
  - Интерактивный автономный HTML-отчет с темной/светлой темой и мгновенным поиском.
  - Экспорт в JSON и Markdown для пайплайнов автоматизации.
- 🛑 **CI/CD Quality Gate**: поддержка флага `--fail-on` для проверки в CI/CD.

## 🛠 Стек технологий

- **Python 3.10+**
- **Rich** — консольный интерфейс и форматированные таблицы
- **Pytest** — модульное тестирование

## 🚀 Быстрый старт

```bash
# 1. Клонирование репозитория
git clone https://github.com/egorfm/leak-guard.git
cd leak-guard

# 2. Создание и активация виртуального окружения
python3 -m venv .venv
source .venv/bin/activate

# 3. Установка пакета
pip install -e .
```

## 💻 Использование

### 1. Сканирование всех репозиториев пользователя
```bash
leak-guard scan-user egorfm --output audit_report.html
```
*(Для увеличения лимита GitHub API с 60 до 5000 запросов/час укажите токен через `--token <TOKEN>` или переменную `GITHUB_TOKEN`)*

### 2. Сканирование одного репозитория с глубокой историей
```bash
leak-guard scan-repo https://github.com/egorfm/project --output report.html
```

### 3. Локальное сканирование директории
```bash
leak-guard scan-local ./my-app --min-severity HIGH
```

### 4. Быстрый аудит текущего состояния файлов (без истории)
```bash
leak-guard scan-repo egorfm/project --fast
```

### 5. Проверка в CI/CD с блокировкой сборки
```bash
leak-guard scan-local . --fail-on HIGH --output report.json
```

## 📁 Структура проекта

```
leak-guard/
├── git_leak_guard/        # Исходный код сканера
│   ├── cli.py             # Точка входа и парсинг аргументов
│   ├── engine.py          # Движок сканирования и анализа истории
│   ├── rules.py           # Паттерны и сигнатуры детекции секретов
│   ├── reporters/         # Генераторы отчетов (Terminal, HTML, JSON, MD)
│   └── entropy.py         # Вычисление энтропии Шеннона
├── tests/                 # Модульные тесты
├── pyproject.toml         # Конфигурация сборки и зависимостей
└── README.md
```

## 📄 Лицензия

Проект распространяется под лицензией [MIT](LICENSE).
