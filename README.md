# 🌌 f3dorovv.bypass - Ultimate Connectivity Framework 🌌

<p align="center">
  <img src="https://vercel.app" alt="Header" />
</p>

<p align="center">
  <a href="https://github.com">
    <img src="https://shields.io" alt="Version">
  </a>
  <a href="https://github.com/stargazers">
    <img src="https://shields.io" alt="Stars">
  </a>
  <a href="https://github.com/network/members">
    <img src="https://shields.io" alt="Forks">
  </a>
</p>

---

## 🛡️ О Проекте
**f3dorovv.bypass** — это высокотехнологичное решение для автоматизации сетевого доступа. Система представляет собой конвейер (pipeline), который объединяет разрозненные источники данных в единые, проверенные и структурированные подписки.

### Основные возможности:
- ⚡ **Multi-Stream Processing**: Раздельные потоки обработки для Desktop и Mobile конфигураций.
- 🔍 **Deep Verification**: Проверка TCP-отклика на портах с использованием 30-потоковой многозадачности.
- 🐍 **Python Engine**: Интеллектуальная генерация VLESS-ссылок на основе динамических вайтлистов.
- 🕒 **Time-Zone Sync**: Автоматическая метка времени для Якутска (UTC+9) в каждом конфиге.

---

## 🚦 Текущий статус мониторинга (CI/CD)


| Операция | Описание | Последний запуск | Статус |
| :--- | :--- | :--- | :--- |
| **Global Sync** | Синхронизация основной базы узлов | `Every 3 Hours` | ![Update VPN Configs](https://github.com/actions/workflows/main.yml/badge.svg) |
| **Mobile Core** | Оптимизация под мобильные частоты | `Every 3 Hours` | ![Update Mobile Configs](https://github.com/actions/workflows/update-mobile.yml/badge.svg) |
| **Generator** | Сборка из White-List и CIDR | `On Push` | ![Generate VLESS](https://github.com/actions/workflows/generate-vless.yml/badge.svg) |

---

## 📥 Быстрый старт (Ссылки подписки)

> [!IMPORTANT]
> Для использования просто скопируйте одну из ссылок ниже и добавьте её в ваш клиент как **Subscription URL**.

### 💎 Премиум подписки

| Тип | Прямая ссылка (RAW) | Обновление |
| :--- | :--- | :--- |
| **🏠 Главная** | [Копировать ссылку](https://githubusercontent.com) | 🔄 180 мин |
| **📱 Мобильная** | [Копировать ссылку](https://githubusercontent.com) | 🔄 180 мин |
| **⚙️ Генератор** | [Копировать ссылку](https://githubusercontent.com) | ⚡ Auto |

---

## 🧪 Технический стек и логика

### Схема работы Generator.py
Скрипт анализирует файлы в директории `data/`, применяя следующие алгоритмы:
1.  **DnsParser**: Преобразует доменные имена в легитимные TLS-хосты.
2.  **CidrShaper**: Извлекает головные IP из широковещательных диапазонов.
3.  **Encapsulator**: Оборачивает данные в `VLESS` URI с параметрами `security=tls` и `encryption=none`.
4.  **Chunker**: Автоматически нарезает базу на блоки по **200 записей** для стабильной работы мобильных приложений.

### Параметры верификации
Воркфлоу использует параллельную проверку `xargs -P 30`. Это позволяет обрабатывать тысячи узлов менее чем за 5 минут, отсеивая до 95% нерабочего "мусора".

---

## 📱 Инструкция по настройке

<details>
<summary><b>Для пользователей Android (v2rayNG / Nekobox)</b></summary>
1. Откройте приложение.<br>
2. Нажмите на иконку "гамбургер" (три полоски) -> "Группы подписок".<br>
3. Нажмите "+", введите любое имя и вставьте <b>ссылку из таблицы выше</b>.<br>
4. Вернитесь на главный экран, нажмите три точки -> "Обновить подписку".
</details>

<details>
<summary><b>Для пользователей iOS (Streisand / Shadowrocket)</b></summary>
1. Скопируйте RAW ссылку.<br>
2. В приложении выберите "Add Subscription".<br>
3. Вставьте URL и сохраните. Приложение автоматически загрузит все прокси.
</details>

---

## 📊 Глобальная активность
<p align="center">
  <img src="https://githubusercontent.com" alt="Snake Animation" />
</p>

![Metric](https://vercel.app)
![Languages](https://vercel.app)

---

## 🤝 Обратная связь и вклад
Если вы нашли ошибку или хотите предложить новый источник (Source), пожалуйста:
1. Создайте **Issue** с описанием предложения.
2. Сделайте **Pull Request** с изменениями в файле `data/sources.txt`.

---

<p align="center">
  <b>Project maintained by <a href="https://github.com">f3dorovv</a></b><br>
  <i>Built with passion in Yakutsk ❄️</i>
</p>
