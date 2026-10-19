# Публичная CDN-конфигурация получена и разобрана

19 октября 2026. HTTPS-запрос по профилю основного Game.ini вернул status 200,
6000 байт. Существующий общий decode_cdn_config_document разобрал ответ:
NetmarbleS/Zone=`real`, SDK mode=2; select_cdn_server выбрал index=6,
type=`REAL`, с заполненными lobbyAddress/lobbyPort/patchURL/dataURL.
Порт лобби — строка `12000`. Подключение к лобби и авторизация не выполнялись.
Это первая проверка этих общих декодеров на реальном публичном CDN-ответе.

## Происхождение адреса и границы результата

Источник профиля — [base Game config](HEADLESS-PAK-CONFIG-RECOVERY.md):
snapshot `393c0697115ec6beceeb0e822bed0f6907eab83dfe9a47f81e9c7875deff35db`.
ConfigPrefix=real, AppVersion=1.12.14, CdnConfig=True; normal base из строки 14.
Существующая prepare_cdn_config_url_ascii использует подтверждённые правила
base/prefix/version и Windows platform code=2 → window.
Получена строка `red.gcdn.netmarble.com/red/config/window/real/1_12_14/config.json`.
Для публичного запроса инструмент явно добавляет `https://` как локальную
политику. Это не утверждение о native TLS: найденный INI scheme не содержит.

Сетевой адрес ограничен ровно этим публичным URL. urllib выполняет HTTPS
с обычной проверкой сертификата/hostname, без environment proxy, redirects,
cookies, авторизации и retry. User-Agent=Aqua/1.0, Accept-Encoding=identity.
На операцию установлен timeout 10 с, бюджет чтения 30 с проверяется между
read1 (текущая операция может добавить до 10 с), body максимум 2 МиБ.
Content-Length проверяется при наличии, duplicate/negative/oversize и
неполное тело отклоняются. Native HTTP/1.0 wire/header этим не воспроизводится.

Доступность URL подтверждает публичный документ профиля основного INI,
но не определяет [порядок Game cache/overrides](HEADLESS-CONFIG-STARTUP.md).
Найденные адреса лобби ещё не проверены, полный native ReadJson/validation
не исполнен. Публичный ответ не содержит сессию аккаунта. Еженедельное
обновление ресурсов и совместимость протокола остаются отдельными задачами.

## Снимок и воспроизведение

Инструмент [fetch-public-cdn-config.py](fetch-public-cdn-config.py).
Для нового явного запроса: `python -X utf8 phone-exit/bots/resource-tools/vampir/fetch-public-cdn-config.py --fetch`.
В ходе исследования выполнены два GET: первичный probe и затем запрос этим
инструментом с сохранением происхождения; оба тела имели одинаковый SHA256.
Повторная загрузка не выполняется тестами или offline-командой.

Указатель: `F:/PhoneExit Resources/Vampir/code-clues/public-cdn-recovery.json`.
Snapshot: `F:/PhoneExit Resources/Vampir/public-cdn-snapshots/41eb52455e20af86619b33ea4b2b434ef74bd7162eecbb7f28817174aaef9e89/manifest.json`.
SHA256 манифеста совпадает с именем каталога. Рядом `body.bin`, SHA256
`15a9b8d47a0b45f8e493842f48ee2e5d889663241294ed3f3fa1ac581ad62e5d`.
Время получения UTC: `2026-10-19T04:57:58.100666+00:00`.
Manifest хранит source profile/INI/archive SHA, tool SHA, заголовки ответа,
локальные transport limits и результат существующих общих декодеров.
Старые снимки не заменяются. Данные остаются вне Git.

Offline-проверка без сети:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/fetch-public-cdn-config.py --snapshot "F:/PhoneExit Resources/Vampir/public-cdn-snapshots/41eb52455e20af86619b33ea4b2b434ef74bd7162eecbb7f28817174aaef9e89/manifest.json"
```

Четыре теста проверяют offline-разбор реального body, source profile,
TLS/redirect/proxy policy, status/URL/encoding/length/size/timeout/certificate
failure на искусственных HTTP responses и неизменяемость snapshot.
`native_config_acceptance_verified=false`, `active_runtime_settings_verified=false`,
`network_ready=false`. Следом — связать SDK bootstrap с полученным Zone,
восстановить оставшиеся параметры авторизации и приём ответа сессии.
