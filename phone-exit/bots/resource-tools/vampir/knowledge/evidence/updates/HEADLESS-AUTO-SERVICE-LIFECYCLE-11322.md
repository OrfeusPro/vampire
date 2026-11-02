# Native service / backend lifecycle, 1.13.22

Семейство `service-lifecycle` / `service-lifecycle-v1` подключено к общему
обновлению и кэшу на точном SHA клиента
`03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
[Машинная запись](AUTO-SERVICE-LIFECYCLE-11322.json) содержит context / proof /
native check, источники, полную цепочку инструментов, матрицу и измерения.
Перенос на следующий SHA требует нового proof и semantic результата.
Профиль следующего входа и текущая игровая сессия не переключались.

Исполняются 12 целых функций: service publisher / assignment / deleting,
control move-release / deleting, backend constructor / base constructor /
deleting / destructor / base destructor / reset / string-ring clear. Отдельная
21-байтовая source capsule выполняет control slot 0 dispatch: проверку backend
на null и native virtual tail jump к backend deleting. Process initializer /
shutdown wrapper, writer, prepare, SDK и прежние suites не исполняются.

Размеры объектов — service 240, backend 800, control 24 байта; synthetic callback
storage — 48 байт. Прежний backend-wire object на 784 байта не расширялся.
Единственная принятая parent роль — точный опубликованный backend-wire context
с его native report; готовые 1807 / 113 / 65 сценариев не повторялись.
Typed projection проверяет полные native ranges, PE tables / globals, прямые
calls и отдельную dispatch capsule. Готовые exports переиспользованы без JVM.

Матрица — 42 семантических сценария, каждый с двумя независимыми poison patterns
(84 раунда): 12 assignment / reinit / deleting цепочек, 10 control move-release,
6 deleting flags, 6 reset / ring ownership и 8 constructor registration branches.
Publisher, assignment, native constructors, strong / weak atomic transitions и
native deleting / reset / ring cleanup работают на одних объектах в рамках
объявленного lifetime. Provider ABI проверяет точные source callsites, stack
aliases и полные диапазоны iterator output / first / last до чтения и записи.

После каждого entry сверяются Win64 nonvolatile GPR / XMM, stack, memory guards,
фактические native / provider writes и конечные владельцы live allocations.
Незаписанные source fields сохраняют allocator / stack poison. Независимый
oracle сравнивает bytes, counters, порядок вызовов и retained ownership.
Конструктор возвращает тот же backend и проверяется также внутри assignment.

Service destructor оставляет service+0x10 / +0x18 необнулёнными. Стенд фиксирует
эти значения до освобождения и не объявляет безопасными reuse / повторное
уничтожение или последующий доступ через dangling backlink. Прежний backend с
внешним strong owner переживает удаление нового service; затем его освобождает
объявленный native move-release. Synthetic provider не уменьшает native counts.
Внешние weak owners и destructed storage без bit 0 free остаются явными
конечными наблюдениями, а не скрыто уравновешиваются fixture cleanup.

Assignment сохраняет неинициализированный allocator qword callback+8 и копирует
реальные входные stack bits в callback+0x2c. Оба poison-набора ненулевые; нулевая
инициализация этих полей не приписывается клиенту. Callback allocation / token /
destruction / resize и execution остаются fixtures, как heap / vector storage /
engine members / external registration context / iterator operations.

Native base constructor оставляет local registration capacity равной нулю,
поэтому local insertion требует reserve. Global spare storage задаётся до entry;
недостижимая local-spare ветка не создаётся изменением памяти посреди native
исполнения. Во всех сценариях явно задан `cleanup_find=end`; iterator remove
прерывает проверку как unmodelled trap. Native unregistration и успешная очистка
реальных engine registration containers этим результатом не подтверждаются.

42 native сценария / 84 poison-раунда и 1082 штатных тестов прошли.
Новый service-lifecycle пакет добавил 76 tooling тестов к прежним 1006.
Наблюдались 230 объявленных top-level entries и 972 native вызова.
Запросов клиента к allocation provider: 456, к free provider: 344; native atomic transitions: 116.
Callback copies: 20; ненулевые неизвестные DWORD: 20.
Первый проход нового семейства: 398.402589 с; последний повтор: 19.771272 с.
Последний повтор использовал 3 этапа / 1 publication из кэша без native / JVM / PE rebuild.
Общий проход 34 drivers: 619.294776 с; тёплый повтор: 118.639629 с.
Тёплый общий повтор использовал 102 stages / 34 publications без native / JVM / PE rebuild; SHA 59 code/context files совпали с Git checkout.
Замеры drivers не включают prepare и глобальный аудит исторического индекса.

Первая попытка нового lifecycle стенда остановилась на `lifecycle-00`: guard
ошибочно требовал base pointer вместо встроенного ring receiver backend+0x98.
Завершённых случаев и native publication тогда не было. Failed native / acceptance
diagnostics и freeze сохранены отдельно; все 59 прежних code/context файлов
архивированы с исходными SHA. Receiver guard исправлен с проверками границ,
изменённый engine получил собственные tooling result, freeze и native proof.
Машинная запись хранит эти материалы в `prior_attempts` только как историю отказа;
они не используются как принятое доказательство нового результата.

Базовые reset / ring scalar, descriptor и retirement действия исполняет клиент.
Реальное освобождение vector storage, allocator, OS / engine effects остаются
providers. Сценарии последовательные: нет OOM / SEH / concurrent retain, scheduler,
реального socket / drain, process owner или online admission. Source invalid
parameter / неизвестная virtual цель прерывают проверку. Socket ID равен нулю.

Следующий общий блок — новая композиция готового frame backend / writer /
CRC-XOR с native resize / queue и доказанным lifecycle. Она должна использовать
новую матрицу на общих объектах; прежние standalone suites повторять не нужно.
Drain / socket failures / реальное wake scheduling, session key acquisition,
receive integrity, engine registration helpers и весь онлайн-вход сохраняют
отдельные границы. Наличие исходных links и exports не закрывает эти проверки.

Тёплый кэш сохраняет semantic результаты. Добавление driver меняет действующий
whole-file publication guard, поэтому холодный общий проход может сверять старые
publication receipts заново; это отдельно от native replay. Оптимизация guard
через новую versioned recipe остаётся открытой задачей.
