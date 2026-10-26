# Полный SightEnter: native mixed arrays и временные владельцы

EXE 1.13.16, SHA256
`d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Продолжает [контракт](HEADLESS-SIGHT-ENTER-CONTRACT-11316.md),
[portable composition](HEADLESS-SIGHT-ENTER-COMPOSITION-11316.md) и
[CharacterOther lifecycle](HEADLESS-CHARACTER-LIFECYCLE-11316.md).
На этом этапе исполнен внешний native reader `1456c5390` со всеми callbacks,
constructors, вложенными readers, copies и cleanup временных записей.
Runtime ID 301 пока не включён: handler → actor / world остаётся следующим шагом.

## Что исполняется

Пять descriptor arrays +10 / +20 / +30 / +40 / +70 и optional projectile array
+50 читаются одним archive/input. Это CharacterOther, NpcCreateData (без notify
flag), GroundEffectData, Gadget, TetherEffectData и ProjectileCircleData.
Native callbacks создают настоящие временные записи на своём стеке, читают их,
копируют в зарезервированные final slots и очищают временную запись. Python
fixtures не читают wire fields и не заменяют эти callbacks/copies/destructors.

Для CharacterOther / NPC / Gadget исполняются named deep-copy functions;
ground / tether / projectile callbacks копируют поля inline. Nested string,
appearance, stat/effect/action/move arrays, Guild / Party / owner / quest и map
сохраняют ранее проверенные source readers. NPC destructor `14579b810` вызывает
`14579b720`, тот — appearance destructor `145784e20`. ActorOwner destructor
`1457846a0` освобождает строку. Новые недостающие functions получены явно.
Move copy leaf `1456bc8d0..1456bc913` — 68 bytes, без calls, с внутренними
переходами и ret; source bytes проверены и исполняются native.

Receivers strings / arrays / maps регистрируются наблюдателем native constructor /
copy entries: реальные stack addresses и final-array slots. Повторное использование
stack address новым constructor получает отдельную generation map storage.
Буферы освобождённой временной записи заполняются DD. После возвращения outer
reader portable decoder сравнивается с final arrays: scalar fields, строки,
XYZ, nested optional presence, duplicate map replacement и arrays. UInt64 не
проходят через float. Raw heading сохраняется portable отдельно; native SSE2 yaw
и настоящие UCRT imports исполняются, canonical heading с raw byte не сравнивается.

## Проверки

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_sight_enter_whole_11316.py
```

Три теста прошли. Шесть synthetic полных тел: все пустые массивы, absent / empty
projectiles, mixed 1 / 2 records, минимальные и богатые вложения. Богатые записи
содержат Unicode, high uint64, nonfinite / signed-zero float bits, повторные map
keys и Gadget keys, optional owner / quest / appearance / params / Party.
Проверен каждый префикс богатого тела 1164 bytes. Получено 1170 recorded cases:
6 accepted и 1164 rejected; acceptance portable/native совпадает. Дополнительно
6 trailing cursor checks. Всего 1176 outer-reader запусков.

Отчёт фиксирует 1242 входа в три named copy functions, 4572 constructor entries
(включая map-value temporaries), 4352 record-destructor entries и 28566 released
tracked buffers, включая string/input temporaries. Это не количество actors.
Final values проверяются уже после native cleanup временных записей. Затем
harness ограниченно проходит final arrays, вызывает native destructor каждой
записи и освобождает outer storage. После каждого сценария tracked allocations
не остаются; неизвестный / повторный free отклоняется. Guards packet / archive /
input / allocations сохранены. Этот final iteration принадлежит harness, а не
настоящему packet destructor игры; engine/listener применение не проверялось.

Scope `sight-enter-whole`: ровно 117 явных unwind roots и до 39 source-bound
exports, точный набор и reader entry проверяются. Пропущенный callback или
подменённый reader отклоняются. Остальные scope budgets не расширены.
Контекст: [sight-enter-11316.json](../../native-contexts/sight-enter-11316.json).
Проверка знаний учитывает projection / fixtures / scripts / native context /
exports / portable modules, Capstone / Unicorn / Python и UCRT DLL.

Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/sight-enter-whole-11316/924dd853e03ec106659c4eaa65e98ebc92d0e474da4fac4ae9eaba1d9af5877a/manifest.json`.
SHA256 отчёта совпадает с каталогом. Новые exports в библиотеке ресурсов:

| Export | SHA256 details.json |
| --- | --- |
| run-967a99e555ab | 62cf18467d2c72e129e8e65bf180cdb9b68b3db8ff9f37134ac65bc57ab54d31 |
| run-b5b88725272b | 07b24d29e3e519be698a82a8a67af0fd86a307dfe75b4804f0e8307f8f062334 |

## Границы допуска

Fresh logical owners, arrays до 2 outer records и до 3 nested wire entries,
до 8 storage slots, inline bitmap; фактическое максимальное тело 2314 bytes,
fixture input bound 8192. Allocator/FString assign/free/memcpy и sparse-map
reset/clear/storage остаются bounded fixtures. Пустые previous outer arrays
очищаются только при pointer=count=0. Heap bitmap, reuse непустых объектов,
growth, allocator/OOM, native sparse-map cleanup iteration и полный packet
destructor не доказаны. Нельзя переносить эти ограничения на engine semantics.

Полный wire decoder теперь проверен вместе с outer reader. Далее установить
current registration/handler → actor / world для ID 301, связать подтверждённые
поля с изолированной моделью и initial entities, затем проверить живой поток
через прежнего владельца. Другие игроки / текущие NPC stats и движение / проекция
карты и реальные одновременные аккаунты ещё не подтверждены. Вход в игру в этом
этапе не выполнялся; тесты не отправляют игровые команды и не используют captures.
