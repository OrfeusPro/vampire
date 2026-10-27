# Завершение окружения: virtual +78 и запись фазы 6

Источник: EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжение [инициализации и lookup](HEADLESS-QUEST-WORLD-RECORD-11316.md)
и [применения фазы](HEADLESS-QUEST-ENVIRONMENT-PHASE-11316.md).
На установленную 1.13.18 результат автоматически не переносится.

## Найденная связь

Поиск callers подтверждённого phase setter 145618B30 дал helper 145612A90.
Его whole body сначала вызывает setter с DL=6, затем обрабатывает объекты
движка, сохранённый delegate и listeners. Это отдельный переход после фаз
3/4/5, а не изменение правил готовности квеста.

В EXE найден и проверен по инструкции E8 caller: 145DA88F1, bytes
`e89aa186ff`, target 145612A90, unwind root 145DA88D0. Полный экспорт этого
root получен отдельным collect. Таблицы проверены непосредственно по EXE:

| Таблица | Слот | Метод |
| --- | --- | --- |
| Базовая 149909370 | +78 | 145612A90 |
| Производная 149A3DAC0 | +78 | 145DA88D0 |

Производный метод сначала вызывает базовое завершение, затем проверяет свои
ветви: flag +1A8, специальный world 10010, kind 0x12 и настройки. Эти ветви
видны в whole export, но их engine effects данным replay не проверены.
Это ещё не привязка обработчика серверного ID206 к virtual +78.

## 28 исполнений

Whole derived method, whole base helper и whole phase setter исполняются
одним harness. Матрица: base/derived × исходная фаза 0/2/3/4/5/6/7 × flag +79
false/true. Внешние providers задают пустой мир, отсутствие actor, группы,
сохранённого delegate и listeners. При flag +79 внешний UI predicate возвращает
1 и пропускает внутреннюю ветвь; истинное поведение этого predicate не доказано.

Во всех случаях native setter записывает 6. Fixture уведомления проверяет,
что новое значение уже находится в памяти. Порядок наблюдений:
форматирование old/new → уведомление после записи → очистка event +90 → UI reset.
Снимок всего окружения 0x1B0 байт отличается только байтом +30; committed +40,
pending +44 и прочие поля сохранены. Empty listener nesting +24 возвращается к 0.

Фаза 6 удовлетворяет ранее установленному условию `phase > 5` в
[Time lifecycle](HEADLESS-QUEST-TIME-GATES-11316.md). Полный Time tick в этом
replay не исполняется; остальные predicates и active task остаются отдельными
условиями. Нельзя объявлять весь квест готовым по одному байту фазы.

## Воспроизведение и источники

Tool: `replay-quest-environment-completion-11316.py`.
Тест: `test_vampir_quest_environment_completion_11316.py`.
Check: `native-quest-environment-completion-11316`.
Три whole exports проходят проверку source bytes, block/direct-flow coverage
и conditional fallthroughs. No-op leaf 141403B70 закреплён точными bytes
`c20000` (RET 0); это native leaf, а не подмена phase setter.

| Экспорт | SHA256 |
| --- | --- |
| run-b225d75559e5 | 4b48cda97394b83ffe6477c43ea7337852a89bba9fbd7164898d013ba019b85d |
| run-e3795e7cbff3 | c927f025a32e802e56bba3a91c20550847a88d252178020bf81f8927bbc90510 |
| run-5743ff88f614 | e410a7c3d7c3b8397bc33f92f2245075f1dd9dafb034d3955d1fa99ac354b1aa |

Артефакт:
`code-clues/quest-environment-completion-11316/8c37a353735e925a60a33f1f02e7bd19dad09e12782007eb2e66c2da3060fc8d/manifest.json`.

## Границы и следующий шаг

Строки/диагностика, class/world/actor lookup, UI, очистка event и providers —
явные fixtures. Реальные engine objects, listeners и callback не исполнялись.
Производные специальные ветви выключены: +1A8=0, world 10012, kind 0x20,
configuration predicate=false. Сетевая сессия и игровые команды не запускались.
`native_execution=true`, `network_used=false`, `action_admitted=false`.

Следом связать actual ID206 handler/receiver с этим virtual +78 и его аргументами,
затем объединить переход с source records и Time lifecycle. Загрузчик настоящих
полей record +0C/имени и активное состояние задачи всё ещё требуют доказательства.
