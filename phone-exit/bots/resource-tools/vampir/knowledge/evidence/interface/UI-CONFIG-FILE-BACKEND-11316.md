# Native file backend: атрибуты, буфер пути и constructor leaf

25 октября 2026. Продолжение [native source chain](UI-CONFIG-NATIVE-SOURCE-CHAIN-11316.md).
EXE SHA256 `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Offline Unicorn replay; Windows API не вызывался, файлы / профили не менялись.

## Источники

Explicit request af8d73c3ec537ecaaf63b86b6371c233538e4f3eb291f9f8da22c779b09c4999
содержит backend / constructor / base-cache getter. Constructor 1414400f0 не
имеет unwind. После отдельной проверки его bytes / padding / следующего root
collect использует новое задание только с двумя unwind roots:
`237aad25464697110601e6330f3c4b3f26625af1d370f9cdef90b1a84bc33dba`.
Roots 1415c6140 и 14144b6b0 выгружены, очередь пуста. Ghidra:
`ghidra/request-exports/<полный SHA EXE>/run-bea8f5e7691a/details.json`, SHA256
`79d49906b18a1dbdc432d53bb16d362e3f982f19b5a0b230074e06c0afb31469`.
Псевдокод сверен с инструкциями: decompiler void / потерянный return API не
определяет bool результат. Compare / TEST / AL выход проверены по машинному коду.

## Backend 1415c6140

Входной path — RDX. Native сканирует UTF16 до NUL; null pointer даёт длину 0.
Inline buffer содержит 256 units: begin / current / end в локальном context,
byte ownership изначально 0. При длине >=256 вызывается 14157a3e0; это порог
до path-prepare helper, не обещание поведения всех длинных путей Windows.
Непустой path копируется через 141453890, current передвигается на units*2.
1415d1540 получает context и low byte DL=1; затем caller пишет NUL по current.
PE import IAT 14899a5c0 подтверждает GetFileAttributesW. После API вызывается
cleanup 14156ff70 с context. Cookie проверяется через 1487e8ce0.

Результат атрибутов сохраняется в EBX через cleanup. Native возвращает AL=0
при EAX API == 0xffffffff либо при bit 0x10, иначе AL=1. Результат API больше
не подставляется как готовый bool. Верхние биты RAX не входят в bool контракт.
Cookie fixture сохраняет фактический native RAX, а не подменяет результат.

replay-ui-config-file-backend.py предоставляет общий service handler для
самостоятельного и whole прогонов. Allocation / copy / path prepare / cleanup,
GetFileAttributesW и cookie — fixtures. Prepare fixture не меняет путь и не
доказывает его реальную нормализацию / расширение / ошибки. API outcomes
synthetic, включая невозможные пары input / attributes; это branch probes.

72 самостоятельных сценария: девять path fixtures (null / пустой / короткий /
Windows-like, длины 255 / 256 / 257 и surrogate-pair границы), восемь attributes:
-1 / 0 / 1 / 0x10 / 0x20 / 0x11 / 0x80 / 0x100010.
Проверены inline / heap выбор, copied bytes / NUL, context ABI, ownership cleanup,
один API вызов, классификация атрибутов, RIP / RSP и восемь nonvolatile GPR.

## Constructor и getter кэша

1414400f0: bytes `488d05e9115b07488901488bc1c3`, два int3 и следующий настоящий
unwind root 141440100. Это 14-byte leaf без unwind; восемь padding bytes здесь
не выдумываются. Native записывает base vtable 1489f12e0 в [RCX], возвращает RCX.
Три standalone случая проверяют output / guard bytes. В physical provider
constructor теперь настоящий; final table 148a21698 по-прежнему пишет native caller.

14144b6b0: полное тело 14144b6b0…14144b797 сохранено. Исполняется только готовая
ветвь: guard 14b2be0b8 / TLS epoch, pointer cache 14b2be0b0. Три probes возвращают
точный cache pointer, включая null как synthetic branch probe.
Whole chain использует готовый cache pointer на статический object 14b2be048,
куда fixture задаёт исходный FString. Готового returning getter fixture больше нет.
Первичная ветвь пока static only: обнуляет ряд полей object, вызывает PE import
InitializeSRWLock по 14899a4b8, устанавливает cache pointer и регистрирует cleanup
14885e9c0. Настоящая concurrency / lifecycle и происхождение base path неизвестны.

## Whole installed → native backend → API boundary

В новом режиме replay-ui-config-installed-cold.py дополнительно принимает
--file-request и --constructor-request того же SHA. Он исполняет whole установленную
цепочку вместе с backend, constructor и готовым base-cache getter.
960 полных сценариев и 960 cache повторов: пять nonempty prefixes (включая
250-character prefix для heap backend), два capacity, attributes -1 / 0 /
0x10 / 0x20, восемь command-line fixtures и три platform states из прежнего набора.

Native выполняет классификацию API attributes; ожидаемый installed result теперь
зависит от неё, а не от truthiness атрибута. В API boundary проверяется точный
нормализованный synthetic path. Проверены один attribute call, heap cleanup,
точный constructor gate и final vtables; cache repeat не делает новых service calls.
В services нет backend_query / base_manager_fixture / physical_constructor.
Остаются base FString contents, substring / string storage, path primitives,
API attributes / cookie, guard / atexit и ASCII iswspace fixtures.

Отчёты:

- `code-clues/ui-config-file-backend-d00a-02.json`, SHA256
  `e04339a104b96fa82ce37b3c44318d65b88b9fd9626dd0994ed742486de5d0c7`.
- `code-clues/ui-config-installed-file-api-d00a-01.json`, SHA256
  `abdc68b288c4db23fd932dc78bb07e1141816541969f3fc64b7dd9279df4bce9`.

Четыре tests installed-модуля прошли за 17.698 с, включая прежние режимы.
Unicorn 2.1.4 / Capstone 5.0.6 закреплены; проверяются полный SHA, unwind,
exact leaf / adjacent root, PE imports, vtables и границы исполнения.
Прежний 26-test UI check не менялся; кэш зависит от полных input SHA.

Actual source path / API outcome / config precedence и применение UI всё ещё
не установлены. Далее path primitives 14157a3e0 / 141453890 / 1415d1540 /
14156ff70 и исходный cold base path / manager initialization. Invalid lengths,
allocation errors, aliasing, fatal path и реальные потоки не проверены.
