# Ожидающее действие квестовой панели

22 октября 2026. Пользователь сообщает о тексте квеста / обучения, ожидающем
нажатия панели. Ниже — найденный кандидат из данных, не установленный активный
шаг персонажа. Текущий EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.

## Готовая цепочка и её сверка

Существующий `quest-graph/early-quests.json` уже содержит:

1. Quest 110110 — Moving forward.
2. QuestTask 110110040 — Move Along the Path, Type 9 / Tutorial, tutorialInfoId 1001.
3. Tutorial 1001, step 1001002: TaskType 16, TaskParam `QuestPanel_PanelTouch`,
   `ServerProcessRequest=1`, `CloseAllPopUp=1`.
4. TutorialUI `QuestPanel_PanelTouch`: WBPName `WBP_GameUI`, WidgetName
   `DeferredQuestUI`, ControlName `TableViewQuestList`, ControlIndex 0.
5. Подсказка на английском просит нажать панель квестов справа для
   автоматического прохождения квеста.

`audit-release-quest-panel.py` сверил шесть выбранных строк с CSV текущего
извлечения. Значения всех прежних полей выбранных строк совпали; очередь пуста.
Таблица-кандидат выбрана по точному SHA либо по уже сохранённой уникальной
схеме исторического файла. Это сверка конкретных строк; схема сама по себе
не доказывает идентичность целой таблицы.

| Таблица / ключ | Current entry | SHA256 текущего CSV |
| --- | --- | --- |
| Quest / 110110 | 2977 | `f9b941f557103b79918b362aaeec0c50796631dedf1d5b6ab4d4092651ba74c2` |
| QuestTask / 110110040 | 2983 | `6f2eec83a42c722caca8b6d4e7d7ff0768b2873fcf40cbd476fd843ce4689a2a` |
| Tutorial / 1001 | 3080 | `56e6c67e968fb91bb92a9690a5fc8330771b11374adcd0ba76752249887d52db` |
| TutorialStep / 1001002 | 3084 | `b40d28346c5bb53e93f3e00ed634ac2c9322cd2ecc3cc589983073c72e83c8e7` |
| TutorialUI / QuestPanel_PanelTouch | 3085 | `657823e69fe37448e4f470c867f8683b0c0544bb2f24e9fe81d077cc14b6ee6f` |
| TutorialStep_Name_en / 1001002 | 719 | `ff3b7a781a025f479af90d8fa4a3bad36aa18c6da0d3c6b1c55bd588f40d968d` |

Аудит проверяет полный SHA manifest / CSV / установленного table PAK и
стабильность PAK при чтении. Результат:
`F:/PhoneExit Resources/Vampir/code-clues/release-quest-panel-audit/f6ce5181e1c30f7fcb0a3e0e98aa4ebb909b7fc4150b18d41d069dd9666a1ecf/manifest.json`.
SHA256 файла совпадает с именем каталога. Отчёт содержит полные строки,
логические csv_record и происхождение, без повторного извлечения ресурсов.

В прежнем UI catalog есть `WBP_QuestPanelUI` и tutorial focus / guide widgets.
Наличие ресурса и имя контрола не подтверждают его текущую видимость,
геометрию клика или callback; текущий UI PAK этим аудитом не проверяется.

## Текущие сетевые привязки

По точным именам и ID getters текущего EXE найдены:

| Имя | ID | Таблица | Reader / writer |
| --- | --- | --- | --- |
| PktQuestListReadResult | 1802 | `0x149966f80` | reader `0x14582cac0` |
| PktTutorialUpdateNotify | 9905 | `0x14996b9f8` | reader `0x1456b83a0` |
| PktQuestPanelSelect | 1836 | `0x1499670d0` | writer `0x1456ff620` |
| PktQuestPanelSelectResult | 1837 | `0x149967120` | reader-кандидат `0x14582cc00`, ещё не исследован |

ID 9905 присутствовал один раз в полном счётчике успешной
[сессии HONOR JP](../network/HEADLESS-LIVE-HONOR-SESSION.md).
ID 1802 в этой сессии не получен. Сохранены счётчики, не тело ID 9905,
поэтому активный tutorial ID из прежней сводки узнать нельзя.

Reader ID 9905 вызывает вложенное чтение packet+0x10. Конструктор
`0x14584d070` и leaf `0x1457fee70` связывают вложенный объект с таблицей
`0x14992b000`; slot +0x20 → `0x1457ff1e0`. Вложенный reader читает флаг +8
и массив +0x10. Дескриптор массива `0x149961ef0` содержит resize
`0x1456bb670` и callback `0x1457ff270`. Поля элемента и семантика флага
пока не восстановлены; готовый decoder ID 9905 не заявляется.

Writer ID 1836 передаёт поле packet+0x10 виртуальному output slot +0x48.
Producer, смысл поля и подтверждение результата ещё не установлены.
Нельзя подставлять статический QuestInfoId вместо неизвестного поля запроса.
`ServerProcessRequest=1` в таблице обучения также не доказывает, что его
единственное нужное сообщение — именно ID 1836.

Материалы в `F:/PhoneExit Resources/Vampir/`:

- Discovery: `code-clues/release-world-packet-discovery/`, manifests
  `30281576857039e389267d0b261e81a6e5eb4bc6f8001f25b4af35b3525d7f48` (1802),
  `7207344d30f0113fe7f0424c770ece9c2fe794831611a0480141c7ea1771a7f5` (9905),
  `b877615b0d904af16770c11831d13ddc3ba0db4f34f5c1737ab70151841e77d6` (1836),
  `956508e02365a2f44351ccd1d3d66303618d90d6dab0ebfe6aab580bf2951d75` (1837).
- Ghidra comparison `c7552efd2125-98802d550890/run-fd4956a37b3c/`:
  `details/run-df3c5d97b2b8/details.json`, SHA256
  `658e92284a85cbcd397427d8008910a209b148eb6c03151b6da3aa973b053f9b`;
  `details/run-653eecec5371/details.json`, SHA256
  `af30655ba1e062787af2fb28916d4719eedab9a421b2207dd6355b9bb1766597`.

Повторяемая offline-сверка:

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/audit-release-quest-panel.py
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-release-ping-result.py --packet PktTutorialUpdateNotify
```

Следующий explicit VA — `0x1457ff270`. Разобрать элемент массива, затем whole
reader / handler ID 9905 и текущую модель обучения. После этого новая живая
проверка должна получить активное состояние, а не угадывать его по статическому
квесту. Нажатие панели и игровые запросы пока не выполнялись.
