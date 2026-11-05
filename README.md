# Proxy Checker 24/7 — GitHub Actions + Pages

Чекер публичных прокси крутится в GitHub Actions по расписанию, результаты
коммитятся обратно в репу (там живёт хранилище `store.json`, по нему считается
дифф «новые/исчезнувшие»), дашборд публикуется на GitHub Pages.

Деплой — 10 минут, бесплатно (репа должна быть **публичной**: для публичных
репозиторий Actions безлимитный, Pages тоже бесплатен).

## 1. Создай репозиторий

На github.com → New repository → имя, например `proxy-checker` → **Public** →
Create (без README, без .gitignore).

## 2. Залей файлы

Скопируй **содержимое** этой папки в корень репозитория (не саму папку!):

```
proxy_checker.py
requirements.txt
.github/workflows/check.yml
README.md
```

Из командной строки:

```bash
cd путь-к-папке-с-файлами
git init
git add .
git commit -m "init proxy checker"
git branch -M main
git remote add origin https://github.com/ТВОЙ_НИК/proxy-checker.git
git push -u origin main
```

## 3. Включи Pages

Settings → Pages → Build and deployment → **Source: GitHub Actions**.

## 4. Первый запуск

Actions → proxy-check → **Run workflow** (кнопка справа) → Run.
Или просто жди ближайшего слота по крону (каждые 30 мин, UTC).

## 5. Дашборд

Через 10–15 минут после первого прогона:

```
https://ТВОЙ_НИК.github.io/proxy-checker/
```

Страница сама перечитывается каждые 5 минут. Внутри: фильтры по протоколу /
стране / анонимности / HTTPS / residential, поиск, сортировка, кнопка Copy.

## Что важно знать

- **Частота**: расписание в `.github/workflows/check.yml`, строка `cron`.
  GitHub не гарантирует точность запуска по крону — возможна задержка ±15–20 мин.
- **Приватная репа**: Actions платные (2000 мин/мес, полный прогон ~10–15 мин,
  т.е. 48 запусков/сутки влезать не будут) → либо сделай репу публичной,
  либо снизь частоту до `0 * * * *` (раз в час).
- **Состояние**: `out/store.json` коммитится после каждого прогона, это и есть
  память «что уже видели». Стирать его не надо — иначе первый дифф посчитает
  всё новым.
- **История изменений**: `out/changes.jsonl` — по строке на каждый прогон
  (+добавлено, −исчезло, сколько живых).
- **Свои источники**: положи в репу `sources.json`
  (`[{"name":"...","url":"...","proto":"http|socks4|socks5|null"}]`) и добавь
  в workflow к строке запуска флаг `--sources-json sources.json`.
- **Остановить**: Actions → proxy-check → ⋯ → Disable workflow.
