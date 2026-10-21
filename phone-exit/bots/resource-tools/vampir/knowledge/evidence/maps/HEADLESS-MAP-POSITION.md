# Текущая проекция серверной позиции на атлас

22 октября 2026. Продолжение [атласа](MAP-ATLAS.md) и
[живого ID 206](../characters/HEADLESS-LIVE-WORLD-FINISH.md).
EXE SHA256 `98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.

## Повторная проверка источников

Старый snapshot CSV с архивом `03a229f2…` не соответствует установленному
pakchunk1: полный SHA теперь
`365ceb7fc006633f4c2be9a38d33c2b8c8a527e4f1250f8b1579af170f16cdb6`.
Аудитор отклонил старую привязку до построения результата. Использован уже
сохранённый release manifest `2b9ee9bb…`, свежий индекс и отдельные CSV blobs;
исторический атлас, offsets и таблицы не заменялись.

`index-release-archives.py --archive-sha256` обработал только этот архив:
3107 записей, достигнут индекс; 3098 decoded / 9 size-skipped при индексировании.
`extract-release-tables.py` получил 3094 CSV без ошибок и skips в своём проходе.
959 совпали со старыми CSV, 2135 не имеют точного совпадения. Это не доказательство
имён всех таблиц и не полное обновление всех каталогов.

World найден по полному набору прежних колонок и изучен отдельно: current entry
3097, 262 строки, новый столбец `IsNavMoveLimit` и 8 новых ID. Map: entry 2923,
162 строки и 8 новых ID. Все значения прежних колонок у прежних ID совпали;
ключ Id уникален. Семантика нового столбца и новых миров пока не установлена.
Map 10/11 полностью совпали с прежними записями без служебного provenance.
MapId / LevelPath 36 прежних миров этих карт проверены явно.

## Код проекции и runtime

`inspect-release-map-projection.py` проверил по полному SHA старый и новый EXE,
искал только три явных префикса с маской RIP / CALL displacement. Уникальные
кандидаты на unwind roots: `0x145ac2770`, `0x1464ee890`, `0x1464fe280`.
Сходство префиксов само по себе не переносит роль; затем Ghidra выгрузила целые
функции. Проверены 15 опорных инструкций и literal GroundDistance / CenterX /
CenterY. Прочитана цепочка float +0x20/+0x24/+0x28 → widget ground / center,
деление размера текстуры на ground, вычитание центра и положительное умножение
координат значка. Это статическая проверка, не native replay всего виджета.

Для Map 10/11 параметры прежние: 10240 × 10240, центр (0, 0), GroundDistance
615000. `map_position.py` в лёгком ядре принимает проверенный manifest с текущим
SHA и явным World → Map. Он преобразует `ServerTargetPosition`, сохраняя Z и
семантику «серверная цель до коррекции движка». За границами результат не
обрезается; unknown world, неверный SHA и нечисловые параметры отклоняются.
Ghidra / CSV / библиотека ресурсов для вычисления в runtime не нужны.

Три локальных теста проверили центр, углы, порядок осей, высоту, выход за границы,
unknown world, NaN и source guards. Отдельный реальный source audit сверяет полный
SHA установленного архива, immutable CSV manifest / blobs и native bytes.
Полный SHA EXE snapshot проверяется; обновление установленного EXE контролируется
общим source profile перед живой сессией.

## Границы и следующий шаг

Модель подготовлена для read-only маркера существующего атласа. Живые координаты
через неё в этом проходе не передавались; UI слоя сессии ещё нет. Не объявлять
текстуры, проходимость или актуальные NPC подтверждёнными из совпадения World/Map.
Вход и 20 секунд heartbeat повторять ради той же проверки не нужно: следующий
новый эксперимент должен передать позицию в слой карты и проверить нужный мир.
Для активных перемещений остаются engine correction, высота, `IsNavMoveLimit`,
обновления положения и навигационные ограничения.

Материалы относительно `F:/PhoneExit Resources/Vampir/`:

- `code-clues/release-map-projection-candidates/e879bb4d81d6cc6e5be0314b1ce0378ed9a1908822b57010dd5b4be00f59ce2d/manifest.json`;
- comparison `ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`:
  `details/run-52ee72db9b11/details.json`, SHA256 `64f727d1de960cb0f5712ac27d10b4d65975367776eba90b0288d3dfdfd37726`;
- там же `map-projection-audit/2100fbeb6390900f22ac7a0743ac4550e2bfdd143d91f81eaa99dce8f80e681e/manifest.json`;
- release `release-snapshots/2b9ee9bbb180f064ae5f399cc41f063784f4f7b98dcc6b659d0707ed4d4cee08/`,
  record index `a4dd6f81f00ad3c4c84b560ca008960315aa5a84655860a517c4d69c16e98896/65fc8722324efe5d0988c9d81420e89db5c309db2eb5de5d4552b16fe1022016/`,
  table snapshot `54728d7a6bef3dfa8ea916b45f29fd1ec972e5e1a5ec1a25688b9a654ca1f7f2`.

Полные пути, source SHA, записи, offsets и hashes содержатся в manifest аудита;
имена content-addressed каталогов совпадают с SHA256 manifest.
