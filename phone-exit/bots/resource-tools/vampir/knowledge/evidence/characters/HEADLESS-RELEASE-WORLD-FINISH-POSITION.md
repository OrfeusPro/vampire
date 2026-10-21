# Завершение входа и путь позиции на текущей сборке

22 октября 2026. Продолжение [живого входа до ID 204](HEADLESS-LIVE-CHARACTER-SELECTION.md#живое-продолжение-id-204-принят-22-октября)
и [проверки запроса ID 205](HEADLESS-LIVE-CHARACTER-SELECTION.md#id-205-текущая-проверка-состояния-и-запрос-22-октября).
Новая авторизация не выполнялась. Runtime по-прежнему останавливается после ID 204.

Источник — EXE snapshot с SHA256
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Это собранный клиент, не доступный исходный C++ проект.

## Callback и состояние 4

Текущий receiver ID 204 `0x145dae5a0` передаёт управление callback
`0x145d99710` в одной из ветвей. Callback принимает closure с указателем на
сервис. Он уведомляет другой сервис о прежнем мире / enum и включает его,
затем проверяет наличие объекта мира:

- При отсутствии объекта вызывает service virtual +0x70 — ранее проверенный
  запрос ID 205. Само разрешение запроса зависит от его gate и состояния.
- При наличии объекта вызывает `0x14561f540(service, service+0x60, delegate)`.
  Этот метод запрашивает состояние 4 через setter `0x145619e00`, ищет actor
  класса `NnWaitingForWorldPartitionStreamingActor` и передаёт ему вектор и callback.

Класс получен по literal ссылки class getter `0x14555ada0`, а не по названию,
присвоенному аналитиком. Вектор используется для ожидания streaming окружения.
Этот actor не является подтверждением позиции игрового персонажа.

`replay-release-world-position-path.py` исполняет целый callback и ветвь bridge
без найденного streaming actor. Восемь сценариев проверяют наличие / отсутствие
мира и исходные состояния 1 / 2 / 3 / 4. В ветви с миром запрашивается состояние 4,
но finish slot при отсутствии streaming actor не вызывается. В ветви без мира
вызывается finish slot, исходное состояние сохраняется fixture.

World / class lookup, state setter, enable, очистка delegate и finish slot —
явные fixtures. Реальный event завершения streaming, actor-present ветвь и
вызов сохранённого delegate не исполнялись. Проверка не разрешает автоматически
отправлять ID 205 по одному принятому ID 204.

## Ответ ID 206 и позиция персонажа

Существующая полная запись `4c713eb525f1931c0cd285feae3faccc` повторно разобрана
без сетевых действий. Capture SHA256:
`d979ae6dbe0b7825d542fdcbf9990b5e0458038d73a6147de30bc383fdf9e5ca`.
Игровое соединение содержит 189 пакетов без ошибки framing. В нём:

| Пакет | Направление | Тело | Результат |
| --- | --- | --- | --- |
| ID 204 | сервер → клиент | 30 байт | Начало перехода |
| ID 205 | клиент → сервер | 0 байт | Завершение перехода |
| ID 206 | сервер → клиент | 2716 байт | Код 0, полное потребление тела существующим codec |

ID 206 содержит 205 записей массива +0xb8, ноль записей +0xc8,
одну запись +0xe8 и ноль записей +0x100. Вектор +0x30 побитно совпал с
вектором ID 204. Значения координат, идентификаторов персонажа и авторизации
в публичную сводку не перенесены.

Это проверка конкретного захвата существующим portable decoder, который пока
привязан к прежнему SHA `c7552efd…`. Она не доказывает все nested варианты
текущей сборки. `world_move_finish_result.py` не объявлен перенесённым на новый SHA.

Текущий constructor `0x14584db80` устанавливает table `0x14996d500`:
reader +0x20 → `0x1458503f0`, getter +0x28 → `0x145759170`.
В сохранённых инструкциях registration constructor связан с handler table
`0x149dc7630`; handler +0x10 → `0x1467cbae0`. Его принятый путь вызывает
receiver `0x145dade30`. Эти связи прочитаны статически; current whole ID 206
reader / handler / receiver вместе не исполнялись.

Внешний reader ID 206 имеет ту же наблюдаемую группировку полей, что portable
codec: result, scalar fields, vector, heading, appearance и четыре массива.
Для полного доказательства нужны вложенные readers и callbacks. Из constructor
установлены nested heading constructor `0x1458212d0` → table `0x1499237a0` →
reader `0x1458233c0`, appearance constructor `0x1457846f0` → table `0x149921fb0` →
готовый reader `0x145788d00`. Короткие constructors сохранены как проверенные leaf
границы, но не имеют однозначного unwind root в Ghidra. Оба constructor и getter
ID 206 исполнены в новом отчёте проверки пути позиции; это не исполнение полного
constructor или reader ID 206.

Receiver ID 206 использует vector packet+0x30 в пути создания / обновления actor.
Он ищет actor через `0x145514ef0` по ключу player+8; class guard этого lookup
использует `0x1454d2540` с literal **NnCharacterPC**. При отсутствии actor вектор
передаётся в `0x14567e7c0` для создания; при наличии проходит преобразование
`0x1456a6540` и условно передаётся в `0x1438228b0`. Также до этих ветвей есть
проверка / нормализация вектора. Поэтому raw vector — серверная целевая позиция
для этого пути; окончательное положение после коррекции, единицы и отображение
на 2D-карте ещё не установлены.

## Native проверка передачи позиции

Целая функция `0x1438228b0` исполнена с синтетическими actor / component.
Она читает root component из actor+0x1b8, вычисляет target минус текущие три
double component+0x1f0 и вызывает virtual component+0x548. На границу передаются
вычисленная разница, прежний rotation block, sweep, hit result и teleport.

36 сценариев покрывают три пары позиций, sweep 0 / 1, teleport 0 / 1 / 2
и возврат component fixture 0 / 1. Проверены разница координат, rotation block,
флаги и возврат. Перемещение компонента заменено фиксацией вызова: реальный actor,
коллизии, создание персонажа и применение преобразований receiver не выполняются.
Это доказывает назначение wrapper, но не получение live позиции самим ботом.

Три теста `test_vampir_release_world_position_path.py` прошли. Проверка
`release-world-position-path` зарегистрирована как offline; авторизации,
игровых действий и сетевого IO в ней нет.

## Материалы и следующий шаг

Каталог comparison:
`F:/PhoneExit Resources/Vampir/ghidra/release-comparisons/c7552efd2125-98802d550890/run-fd4956a37b3c/`.

| Материал | SHA256 |
| --- | --- |
| details/run-6b9214e917be/details.json | e19ef0084ed087d9c972a7e5fd47fd5d11251ffe0844243e03341dc06a99e31f |
| details/run-a74c5869b659/details.json | 4615a07bcfe85b5213cd0ecbaeffb4f7245cd48376fe5851c6a900add93f5bda |
| details/run-48179cd50ecb/details.json | 9b729c73f195ebb0401cf0bb98f53ccd57b41e78ec281c6e6b61d21a27260b5e |
| details/run-74bc593d49ac/details.json | 7635e508c5a742374aea37a9789f23dac2db586450a8cec4bad9fff8e5c19348 |
| details/run-3fff77629747/details.json | 6122ebd8e03562b24830417fbddd0c8790119db8e35ba78c1e1c11062edcb478 |
| world-position-path-replay/5f9817d51d4d2c3bcf28409257d340d6e17b3c8089e7dada0ea5bb5648534284/manifest.json | 5f9817d51d4d2c3bcf28409257d340d6e17b3c8089e7dada0ea5bb5648534284 |
| official-world-finish-summary/fa6a748d20b68e420b94e414c56a027824a320e45ff0a6502c7fd63a0a0f0ebd/manifest.json | fa6a748d20b68e420b94e414c56a027824a320e45ff0a6502c7fd63a0a0f0ebd |

Сводка захвата построена read-only скриптом
`F:/PhoneExit Resources/Vampir/code-clues/check-official-world-finish-20261022.py`.
Его SHA и SHA исходного derived report включены в immutable summary выше.

Следом завершить current whole reader ID 206: использовать готовые appearance /
time readers и получить только недостающие heading reader / callbacks массивов.
Затем ввести явную headless политику завершения загрузки без 3D streaming,
проверить её локально и выполнить один новый переход до ID 206. Позицию публиковать
как серверную целевую с указанием мира и границ преобразования, а готовность
длительной сессии подтверждать отдельно. Полный хвост ID 202 остаётся открытым.
