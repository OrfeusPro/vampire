# GridSlot: передача инициализации и границы defaults

Только offline static анализ текущего EXE SHA256
d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960.
Продолжение [связи класса и схемы](UI-GRID-CLASS-LINKS-11316.md).

## Явные источники

Новый запрос fdb6a135dce58a01c541bb724200457e674d19ee3cde768daf6f57a86dab0a6a
включает 1416ab8d0 и 1417cba90. Их полностью экспортировал Ghidra в
F:/PhoneExit Resources/Vampir/ghidra/request-exports/
d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960/run-ff83e1036bed/.
Ранее проверенные class / callback requests 52880dd4… и b39f3a5a… дают
143579900 и 14358e000. inspect-grid-construction-flow.py требует все три
задания с явными roots и тем же полным SHA, проверяет unwind и конкретные
инструкции; сохраняет четыре полных native фрагмента. Псевдокод сопоставлен
с инструкциями, угаданные типы Ghidra не принимаются за доказанные.

## Поток callback

GridSlot getter 143579900 сохраняет исходный RSP в R11, вычитает 0x78 и
помещает указатель 14358e000 в [R11−0x30]. После CALL в helper 1416ab8d0
это [entry_RSP+0x50], то есть десятый аргумент по Windows x64 ABI.
Helper делает три PUSH и SUB RSP,0x30: итоговое смещение его frame — 0x48.
Он читает [local_RSP+0x98] в RCX в 1416ab943 и сохраняет в [RBX+0xb0]
в 1416ab96e. Это подтверждённая передача callback в поле создаваемого объекта
класса; сам этот store callback не вызывает.

Helper вызывает arg14 через [local_RSP+0xb8] в 1416ababf, а arg13 через
[local_RSP+0xb0] в 1416abacc. Во втором случае GridSlot getter подал thunk
14356ab00 → именованный getter PanelSlot, подтверждённый предыдущим разбором.
Результат проходит в vtable+0x338 либо direct 1416bae10. Helper имеет и другие
calls / stores; их side effects здесь не исполнялись.

После восстановления стека helper переносит сохранённый R9 / R14 в RAX и
переходит JMP RAX. Getter передал в R9 1435d6ea0 — ранее экспортированный wrapper
регистрации девяти функций. Это отдельная ветка от store callback в +0xb0;
называть любой переданный указатель constructor только по его позиции нельзя.

## Почему значения пропущенных полей ещё неизвестны

14358e000 получает указатель объекта из [RCX], при non-null вызывает
1417cba90 с RCX=объект, RDX=исходный контекст. Затем выполняет десять MOV,
включая нули в +0x28/+0x30/+0x38/+0x40, word +0x48, dword +0x5c и qwords
+0x60/+0x68/+0x70, а также запись vtable по +0. Это явные stores данного
фрагмента, не полное утверждение о CDO defaults или именах всех полей.

Внутри 1417cba90 перед базовым завершением вызывается 14174c9f0. Контексту
назначается указатель объекта, byte +0x12 = 0; mismatch может вызвать
1415351b0. Callee 14174c9f0 и предшествующие allocation / property copying
не разобраны. Неизменённые этим фрагментом байты могли получить значения раньше.
Поэтому из этих stores нельзя выводить default Row=0, Column=0 или Span=1.
CDO / archetype copy и native defaults остаются отдельной зависимостью.

Ни helper, ни initializer не исполнялись в игре или эмуляторе. Нет fixtures,
выдаваемых за объект игры; проверены полные байты и статические аргументы.
Отчёт сохраняет anchors, callback_flow и все initialization_writes.
Геометрия, историческая cooked compatibility и реальный бот не проверены.

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/inspect-grid-construction-flow.py --request 'F:/PhoneExit Resources/Vampir/knowledge/requests/fdb6a135dce58a01c541bb724200457e674d19ee3cde768daf6f57a86dab0a6a/manifest.json' --class-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/52880dd4071122c26f8ae29066fbce297040f4dacaea5fb759afeed86ac74a0e/manifest.json' --callback-request 'F:/PhoneExit Resources/Vampir/knowledge/requests/b39f3a5af27ef2a222a8784dd99199a7c10a2c3ae12ff7e8791285781e21846d/manifest.json' --output 'F:/PhoneExit Resources/Vampir/code-clues/grid-construction-flow-d00a-next.json'
```

Отчёт code-clues/grid-construction-flow-d00a-01.json SHA256: 46ad21a2a388780f988b1ebf1019c985a065bd3db489bfe5784cdbfcda5a198c.
Следующий явный callee для prepare — 14174c9f0; отдельно проследить allocation,
CDO / archetype copying до разрешения отсутствующих значений.
