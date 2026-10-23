# CharacterCustomizeUI: constructor scale 1000 и путь создания CDO

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [путей пола](HEADLESS-CREATE-GENDER-PATHS.md).

## Точная identity экрана

Открытие экрана внешности `0x14641a500` / `0x14641b940` использует template
`0x146410ee0`. Он проверяет type getter `0x146404090`.
Тот регистрирует UTF-16 имя `CharacterCustomizeUI` по `0x149c94ab2`, размер
`0xca0` и constructor wrapper `0x14640a3f0`. Его точные байты:

```text
48 8b 09                mov rcx, [rcx]
48 85 c9                test rcx, rcx
0f 85 f4 c2 00 00       jne 1464166f0
c3                      ret
```

После RET — INT3 padding. Это условный tail transfer, поэтому поиск E8 callers
и обычного JMP не находил связи с `0x1464166f0`.
Соседний getter `0x1464058b0` и constructor `0x14640a6a0` принадлежат другому
типу и не используются как доказательство настроек CharacterCustomizeUI.

В bounded native replay исполняется wrapper и весь `0x1464166f0`.
На памяти с poison 0 / `0xa5` / `0xff` подтверждено:

- scale по `+0xc48` становится 1000;
- два preset ID по `+0xc54` / `+0xc58` становятся -1;
- owner и shared control по `+0xc90` / `+0xc98` обнуляются;
- vptr становится `0x149c9cee0`, guards вокруг `0xca0` байт не меняются.

При нулевом object pointer wrapper возвращается без вызовов и записей.
Всего шесть сценариев. Base / member constructors и settings lookup — fixtures;
settings count явно задан 0, ветки resize не покрыты. Это **native constructor
default**, а не доказательство отсутствия позднейшего override из Blueprint,
десериализации свойств или runtime. Реальные min/max виджетов пока неизвестны.

Настройка `0x14642e2e0`, case 5, читает owner float по имени виджета через
`0x146449fa0` и умножает на scale перед `0x145f96550`. Ранее проверенный
handler делит текущий int32 на scale. Следовательно, для default scale шаг
нормализации равен 1/1000; фактические значения после clamp и float rounding
проверять в полном пути применения пресета. Сам getter и этот case здесь
исполнены не были — связь установлена статически.

## CDO: найден путь, defaults ещё не разрешены

Generic class registration `0x1416aba00` сохраняет constructor в `UClass+0xb0`
и обнуляет pointer default object `+0x110`.
Поиск функций по одному offset дал несколько ложных кандидатов, которые
экспортированы и больше не считаются unknown создания:

| Функция | Фактически наблюдённая операция |
| --- | --- |
| 0x14169bc70 / 0x14169e230 | Инициализация самого UClass |
| 0x1416ac170 | Создание snapshot с class pointers / defaults / callbacks |
| 0x1416b3a40 | Восстановление UClass из snapshot |

`0x1416a4780` — следующий проверенный путь. При отсутствующем default object
он получает superclass CDO, вызывает `0x1417e6110(class, outer, 0, 0x31, …)`,
сохраняет результат в class `+0x110`, подготавливает initializer через
`0x1417ca780` и вызывает class constructor из `+0xb0`.
Затем выполняет `0x1417cbe90` и дальнейшие операции с объектом.
Это статическая последовательность, целый CDO creation не исполнялся.

Следующие явные функции для проверки: `0x1417e6110`, `0x1417ca780`,
`0x1417cbe90`. Их allocation / zero initialization / копирование superclass
defaults должны определить значения отсутствующих preset int32. Нельзя
заменять эти поля нулями лишь потому, что constructors их не записывают.

## Проверки и материалы

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_customize_scale.py
```

Report вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-customize-scale/bae44a31006c77ed95647ac166b4cbe1c25a45e4d3d1f2e3b3d28bde40761980/manifest.json`.
SHA256 совпадает с именем каталога. Ghidra comparison:
`c7552efd2125-98802d550890/run-fd4956a37b3c`, details:

| Run | SHA256 details.json |
| --- | --- |
| run-0e689084e517 | 9bda15f0ddb7d11ffac6c476f14082c3d5a97f8065e1f1b2c0aa3e88c53d7181 |
| run-66deb39fd709 | f28f7f19b1484959dc41726f7835fda697739464b1e9e4a8e5d7dc4d0d1368d1 |
| run-d32c2a8c385f | 168cf0dcd27768a56fd9ea463a04f3f250a3dd0367f8e41508443088ca5cc5b9 |
| run-508d565cecb3 | 11648ad0f104dfd4d3b89d1ee051a62d4288fdd82bf9628a87f4255f1229cf0f |
| run-fb0a2b76c21f | f5333575c5088e2e3c79997a344aa47440225098cf142692c1e2646a1c4bdc3d |
| run-9c9df39519a0 | f01301fa4488a83df798dddd6f031eed4d830ebf8582a468895f27d4a6564796 |
| run-847c261443de | 6153c0bf3c2e9d586896518875021a98a3609dace68369944516d6ef66d3296a |
| run-d838cda77918 | fef5c550abc1dcc1068e7c50b44b9479791780c37b28607e2ef0bc517148c25a |

Сеть, авторизация, создание персонажа и изменение его состояния не запускались.
Следом CDO defaults и реальные min/max, затем JSON output, producer и ID 104.
