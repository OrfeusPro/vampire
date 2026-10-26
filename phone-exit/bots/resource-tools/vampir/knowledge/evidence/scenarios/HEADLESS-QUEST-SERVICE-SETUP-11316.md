# Service filter: native настройка RegionType / ServerId

Source EXE:
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Начальный caller request:
`aa133488d5f5b3d1aaeee24c83ee1ec37def6b60cefded6a29d40aaaeb1a5007`.
Он переиспользовал source-checked handler export run-83255b6c29bc, SHA
`d811a7f48b0c5c91ca936e30f91437057dfe597da31081dcebbb7a876035b4ec`.
Setter prepare request:
`09a94381c6ea531323a9d639a1a6eeec5d88887e90b3b21fef15dd3145204fe1`.
Новая collection run-9fb0bec39db3, SHA
`cfa5468fc2d359930922367c5bc279ac766693fcef83808a0b1a7ca82e01ff53`.
Целая функция `145c21f20` имеет block/direct-flow coverage.

## Связь вызова

Handler `14679aec0` получает service singleton через `145bfe3d0` по адресу
callsite `14679b2ca`, загружает EDX из selected state +30C (`14679b2cf`) и
вызывает setter `145c21f20` (`14679b2e2`). Exact bytes этих инструкций сверены
с EXE и caller export. Целый login handler здесь не выполняется; origin поля
selected state и его актуальное значение отдельны от этой локальной цепочки.

Setter записывает числовое окружение, которое читает
[проверенный service policy](HEADLESS-QUEST-SERVICE-POLICY-11316.md):

1. Сравнивает входной ServerId с manager+7C; при отличии ставит byte+80=1.
2. Получает объект через `14556ae90` и вызывает region lookup `14556b8b0`,
   передав адрес локального uint32 результата.
3. Если lookup вернул false, повторно получает объект и читает fallback+А8.
4. Сравнивает найденный/fallback region с manager+78; при отличии ставит +80=1.
5. Записывает region в +78, ready byte+81=1 и входной ServerId в +7C.

Название RegionType основано на source-policy сопоставлении с
[табличным RegionType](HEADLESS-QUEST-SERVICE-DATA-11316.md). Setter сам не
доказывает соответствие числового значения строкам JP/HK/KR. Внутренности
provider/lookup и актуальный fallback+А8 ещё не проверены.

## 144 bounded native случая

Region values 0/4/7 × server values 0/256/FFFFFFFF × lookup success/failure ×
initial dirty 0/1 × equal/different old region × equal/different old server.
Provider getter и region lookup — два явных fixtures; setter исполняется целиком.
При success getter вызывается один раз, при failure — два. Lookup output pointer
проверен точно: caller home space, entry RSP+10 (внутри функции RSP+48).

В каждом случае проверены final region/server, dirty/ready flags, getter/lookup
порядок, сохранность provider bytes, всех других manager fields и guards.
Dirty не очищается при совпавших inputs: остаётся initial value, а при любом
изменении становится 1. Server FFFFFFFF проверяет сохранение 32-битного значения,
не разрешение использовать sentinel как реальный выбранный сервер.

## Ограничения и следующий шаг

Manager/provider, lookup return/output и fallback+А8 synthetic. Region values
не являются текущими данными сессии. Проверка не вызывает login, сетевой код
или owner API, не читает и не меняет настройки пользователя. Native region
provider/cache/lookup и active current fields неизвестны.
`active_region_verified=false`, `order_admitted=false`.

Далее — whole `14556b8b0` и provider `14556ae90`, связь cache+А8 с выбором региона;
затем ServerGroup ServicePhase layout / current policy / whole catalog.
Действующая сессия сохраняется, Stop/relogin не выполнялись.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_quest_service_setup_11316.py
```

`replay-quest-service-setup-11316.py`, контекст
`knowledge/native-contexts/quest-service-setup-11316.json`, offline check
`native-quest-service-setup-11316`. Артефакт:
`code-clues/quest-service-setup-11316/e95854d70f6defad52d33e5750392c364e91255e3bf1046b1bb8fbb61f79baae/manifest.json`.
