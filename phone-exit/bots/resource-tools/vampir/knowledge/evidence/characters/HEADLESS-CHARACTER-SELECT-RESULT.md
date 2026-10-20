# ID110: минимальное тело и raw spatial vector, 20 октября 2026

Это промежуточный offline этап. Полный ID110 decoder, handler, реальный выбор
и получение позиции ещё не готовы. Игра не запускалась, сеть не использовалась.

## Источник и воспроизведение

Данные/код клиента: `C:/Program Files/Netmarble/Netmarble Game/VAMPIR/ProjectRED/Binaries/Win64/ProjectRED-Win64-Shipping.exe`.
SHA256: `c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Ghidra 12.1.4/JDK21 и Capstone 5.0.6/Unicorn 2.1.4 закреплены в
[ANALYSIS-TOOLS.md](../../../ANALYSIS-TOOLS.md). Инструменты остаются вне runtime.

Основной экспорт: `F:/PhoneExit Resources/Vampir/ghidra/export-c7552efd2125/run-ec3ca26f4570`,
151 функция/63 warnings. Manifest SHA256:
`fbe81b3b2a1f9dab72dcb9f6cb649b4f2f5b660b09e19d408b5de281d72415b4`.
Короткий callback `0x1456fa260` имеет явно проверенный bounded leaf range 28,
не PE unwind range; остальные источники диапазонов сохранены в manifest.

Ассемблерная математика отдельно экспортирована Ghidra:
`F:/PhoneExit Resources/Vampir/ghidra/math-c7552efd2125/run-2eacd2d870e9`.
Provenance SHA256 `3c6fd8eb4d8627dd1b2da3f9c516cb80b4e53dd5e49a92a5579f794120aa9edd`.
Девять диапазонов получены через machine basic blocks достигнутых p-code PC,
с ограничением 64 KiB на функцию. P-code min/max нельзя использовать как сплошной
диапазон: tail-merged helper может иметь далёкие блоки. Это отдельное расширение
Ghidra discovery, не собственный парсер машинного кода.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/build-ghidra-manifest.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-export.py --reuse
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-ghidra-export.py
python -X utf8 phone-exit/bots/resource-tools/vampir/run-ghidra-math.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-select-result.py
python -X utf8 phone-exit/bots/resource-tools/vampir/replay-character-select-apply.py
python -X utf8 -m unittest discover -s phone-exit/bots -p 'test_vampir_headless_character*.py'
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_headless_ghidra_export.py
```

Проверки: 27 character tests и 3 Ghidra integrity tests прошли.
Ghidra команды выполнять последовательно: они используют общий project.
Повторный math export требует сверки с новым provenance и регенерации replay.

## Проверенный минимальный профиль reader

Outer table `0x1498d8a80`, constructor `0x1456d4a40`, reader `0x1456d8f80`,
writer `0x1456e5410`, handler `0x14675e9a0` (последний пока только экспортирован).
Native outer object: code+10; main player+18 размер 278; block+290 размер 20;
rawQ+2b0; block+2b8 размер 60; TimeBase+318; FString+328/+338; bool+348/+349.
Main constructor `0x14577ce10`, table `0x1498d89c0`, reader `0x145780eb0`.

Native replay исполняет реальные constructor/readers/IO primitives и nested
direction math. Минимальное тело 203 bytes: пустые строки/массивы, absent optional
maps. 256 bodies покрывают все значения wire heading; ещё 12 проверяют три
вектора, signed zero, округление float32 и code 0/26/3c/ffffffff. Code здесь
только прочитан: принятие/ошибки handler этим не доказаны. Во всех 268 случаях
reader вернул 1 и потребил 203 bytes. Truncated bodies этим этапом не проверены.

- Wire offset 61: три LE float32, reader `0x144aa6660` через slot 40 читает каждый
  float и расширяет в double. В main+188 записываются 24 bytes трёх double.
- Wire offset 73: один byte, reader `0x145818150` интерпретирует его как signed
  char, умножает на 2 и создаёт direction vector в main+1b0. В main+1a8 сохраняет
  нормализованный byte через direction→angles и truncation. Например 1→0,
  90→90,91→167,128→52,180→180,255→0. Исходный wire byte и этот byte различаются.
- `0x141507880` исполняет guarded fmod `0x141444d00` и статически связанный SSE2
  sincos `0x1487969e0`. Импорт fmod thunk `0x1487a2efd` и atan2 thunk
  `0x1487a2ef7` сверены с import table. В replay они вызывают настоящую локальную
  `System32/ucrtbase.dll`; путь/SHA DLL записаны. Python trig их не подменяет.

Report: `F:/PhoneExit Resources/Vampir/code-clues/character-select-result-replay.json`,
SHA256 `f28b98934f61bc0874d76041afa3a7b3dba9a7593d444a38ad32670dc9effc7e`.
Включены source ranges/SHA, executed math trace и ограничения fixtures.
Два resize callbacks захвачены только для empty/fresh containers; cleanup
captures требуют count 0. Поддержку непустых контейнеров это не доказывает.

## Отдельная проверка применения player record

Actual apply `0x145d61e60` копирует main+188 raw24→player+20, main+8→player+8,
main+30→player+10; main+260==2→player+249. `0x1415055b0` преобразует direction
main+1b0 в pitch/yaw/zero roll→player+38. Guarded atan2 wrapper `0x14143fd00`
проверен по 27 bytes; для нулевых аргументов возвращает+0.

22 native cases покрывают оси, произвольные направления, большие/малые масштабы,
signed zero и два значения flag. Record/destination synthetic; nested apply,
пустой текст/class lookup/reset захвачены, listener list пуст. Это отдельный
apply replay, не сквозной handler→player/session сценарий.

Report: `F:/PhoneExit Resources/Vampir/code-clues/character-select-apply-replay.json`,
SHA256 `83241b13f2aaa07543109f52c65c0bc15f66ef769534d329ffed0c5f6c09b440`.
Семантика мировой позиции, система координат, единицы и world/location consumer
не доказаны; в отчёте используется имя raw_vector_input.

## Продолжение по уже экспортированным связям

Полный main reader содержит две optional maps (+98/+f8 внутри+90), appearance
и массивы+158/+168/+178/+1c8/+1d8/+1f8/+220/+238/+250. Непустые элементы ещё
не прогнаны. Map98 item `0x1456da4b0` вызывает find/insert `0x1456d37a0`:
entry stridef0, value+8; insert `0x1456d33f0` ещё требует экспорта.
Уже экспортированы callbacks/readers:
`14578bd80`(+158), `1456b3640`(+168/+220), `1457f0170/1457f0220`(+178),
`145738b70`(+1c8), `145780300`(+1d8), `145783f30`(+1f8),
`1456ef840`(+238), `1456f0170`(+250), block290 `1457f0c90/1457f0c00`,
block2b8 `14578ecd0`. Читать их вместо повторного исследования.

Следом: непустые коллекции/границы и полный bounded portable decoder ID110;
actual handler→acceptance/player→семантический position consumer; затем owner
lifecycle, SDK/device context/подтверждение устройства и согласованная live
сессия `bot-test@vampir.top`. Socket/reconnect/runtime/map/farm пока не закрыты.
