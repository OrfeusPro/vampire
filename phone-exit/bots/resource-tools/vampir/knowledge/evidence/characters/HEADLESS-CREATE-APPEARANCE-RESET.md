# Внешность: создание owner и сброс перед preview

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [именованных BoneGroup](HEADLESS-CREATE-BONEGROUP-DIRECTORY.md)
и [входов JSON helper](HEADLESS-CREATE-APPEARANCE-JSON-INPUTS.md).

## Статически прослеженная последовательность

Единственный найденный прямой E8 caller constructor `0x146442670` — фабрика
`0x14642aa20`. При mode 0 она выделяет `0x88` байт и вызывает этот constructor;
при mode 1 — другой constructor `0x146442520` с выделением `0x90` байт.
Owner и shared control сохраняются в экран `+0xc90` / `+0xc98`.
Поиск E8 не покрывает непрямые вызовы, tail calls и inlining.

Один из двух найденных callers фабрики, `0x14641b940`, выбирает mode 0,
открывает экран и вызывает `0x146420910`, затем `0x146420260`.
`0x146420910` сначала вызывает owner vtable `+0xa0`, затем `+0x78`.
Текущая vtable `0x149ca7190` связывает эти слоты с `0x1464568a0`
и `0x146448bd0`. Первый — this-adjusting leaf:

```text
1464568a0  48 83 c1 08        add rcx, 8
1464568a4  e9 b7 fc ff ff     jmp 146456560
```

Следом идут INT3 padding. Ghidra не принял leaf как однозначный unwind root;
это сохранено в очереди, а не выдано за полный экспорт. Его девять байт и
vtable binding проверяются инструментом по полному SHA EXE.

`0x146448bd0` получает PlayerState создания, ищет связанные с классом и полом
данные и имеет две ветки: при найденной записи вызывает `0x145674330`, затем
`0x145dfd430`; без неё — `0x145dfdc80`. После получения preview вызывает
`0x1456779b0` с подготовленными данными. Эти вложенные операции здесь только
статические наблюдения: выбранный реальный пресет и его значения не установлены.
В каталоге текущего PAK есть отдельные DA_PresetGunner1_F / M, но одно имя
ресурса ещё не доказывает его выбор этой веткой.

После preview `0x146420910` вызывает `0x14642f090` при ненулевом Actor, а позднее
`0x14642d530` либо `0x14642ddc0`. Это следующие явные кандидаты для проверки
записи параметров; результат сброса нельзя считать финальной внешностью.

## Native-проверка сброса

`replay-release-appearance-reset.py` исполняет leaf, весь `0x146456560`,
container clear `0x143060690` и sparse iterator `0x14142e7d0`.
Начальная память содержит canary `0xa5`, исходная FString непустая.
24 случая: 0 / 1 / 4 / 35 слотов, пропуски в sparse bits, занятые слоты
0 / 31 / 32 / 34, пол 0 / 1 / 255 и число hash buckets 0 / 1.
Значение 255 — проверка сохранения байта, не разрешённый игровой пол.

Для всех случаев подтверждено:

- input `owner+8`: первые десять байт внешности обнуляются;
- FString input `+0x10` очищается, byte VoiceType input `+0x20` становится 0;
- input `+0x28` с полом и соседние байты сохраняются;
- занятые записи освобождаются в порядке native iterator, число слотов становится 0;
- внешние canary и участок owner до input остаются прежними.

Free, подготовка map и resize её storage — ограниченные fixtures / captures.
Они проверяют аргументы и воспроизводят освобождение storage; владение реальной
engine-памятью не проверяется. Ветка hash buckets >= 2 с `0x1415ecc50`
экспортирована, но этим replay не покрыта. Утверждение об очистке относится
к проверенной ветке и состояниям. Статический псевдокод Ghidra встраивает
container helper; replay использует реальные CALL / JMP границы из инструкций.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_appearance_reset.py
```

Report вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-appearance-reset/b779b88e9a21f12d6237fff794568b78bfc895064147a38a732178f9588eb3b6/manifest.json`.
SHA256 manifest совпадает с именем каталога. Ghidra comparison:
`c7552efd2125-98802d550890/run-fd4956a37b3c`, details:

| Набор | Run | SHA256 details.json |
| --- | --- | --- |
| Фабрика owner | run-1b6c1f61eeb2 | af460279584844959236c0427d2aa7abd0305344b9a4aa975d608943ccdbeb3d |
| Открытие экрана | run-edaeec9eeee2 | e851addd5a03fcc76d4b46b77766ad5363673f8201657291cb2b5ba849f0faf7 |
| Обновление экрана | run-9da4756598e9 | 1b9c837c6195708b0c9b9108b8ce5d5f31b260d399b1d365764433de4018fec2 |
| Preview | run-6ac561c59c6f | cd0c6ce1447bd1145cca6663ab65ccf5f18fae0abadcce7305ad67f292d408f1 |
| Сброс | run-2d15d3017ebd | 33addde274986e37eae7a189109e6fb77c3ce81cda4b7c4deb74b8efba9d75bc |
| Container clear / hash rebuild | run-b6794322d508 | bfee5b4de16d285f38052b0f269171408059b055997f0a6374dd146a918d2f1e |

Следом — записи после preview, выбранный preset и источник диапазонов float.
Затем реальное преобразование ключей / JSON, целый producer и handler ID 104.
Проверка не использовала сеть, авторизацию или создание персонажа.
