# Реальное применение фазы окружения перед проверкой квеста

EXE SHA256: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Request: `a2168a46e95ace7939654b14dc3d81bdb36ed4df691004caa85c196f6a032314`.
Новый export run-e3795e7cbff3, полный SHA закреплён в
`knowledge/native-contexts/quest-environment-update-11316.json`.
Продолжение [получения объекта guard](HEADLESS-QUEST-GUARD-OBJECT-11316.md).

## Применение, а не только запрос

Whole handler 145618B30 получает environment this в RCX, фазу в DL и FString
диагностики в R8. Он формирует диагностические строки, затем форматирует запись
со старым environment byte+30 и новым DL. После этого пишет DL в byte+30,
получает контекст через 14563DD30 и вызывает уведомление 145639100 со строкой.
Следовательно, вызов из writer 14560F9E0 применяет фазу 3 ещё до внешнего guard,
а не только предлагает выполнить изменение позже. Caller 14561BCA0 при C1=0
и фазах {2,3,4} применяет фазу 5. Результат caller по-прежнему не подтверждает
успех смены других полей или завершение действия.

Эта запись не затрагивает environment+44. Источник pending остаётся неизвестным.
Названия enum для чисел фаз не установлены.

## 48 + 9 + 16 native проверок

Phase fixture удалена из общего writer/retry/readiness replay. Вместо неё
исполняется целая 145618B30. Observation hook на входе записывает аргументы,
не меняет RIP/RAX и не подменяет выполнение. Полные source bytes и coverage
проверяются общим harness; диагностические операции выполняются с пустыми строками.

В 36 writer/retry случаях после вызова phase byte действительно равен 3,
включая missing/deny guard и сохранение старого +40. В 12 caller cases
выбранные {2,3,4} становятся 5, остальные сохраняются. Проверяются ровно одно
уведомление при вызове handler и его отсутствие без смены фазы через handler.
Прежние 9 whole-getter проверок сохраняются.

16 отдельных случаев: старая фаза 0/7, новая 0/1/2/3/5/6/7/255. Верхние биты RDX
намеренно непустые: применяется только DL. Ожидаемая копия 0x200 байт environment
отличается только байтом +30. Fixture уведомления проверяет новое значение уже
в памяти, поэтому подтверждается порядок записи до внешнего notify.
Повтор той же фазы тоже вызывает уведомление. Число 255 — stress input, а не
разрешённая игровая фаза; допустимость значений на реальном пути не установлена.

Артефакт: `code-clues/quest-environment-update-11316/6fba0b76a0e2ef6c02b9f82b10940076cf289b81c32c3e2d31bf0180d3e159f5/manifest.json`.
Tool: `replay-quest-environment-update-11316.py`;
тест: `test_vampir_quest_environment_update_11316.py`;
check: `native-quest-environment-update-11316`.

## Почему одного совпадения +40 недостаточно

Readiness 14568CAD0, проверяемый вместе с writer, сравнивает data+14 и environment+40.
Это только один predicate, не полный запуск Time. В ранее проверенном
[целом Time lifecycle](HEADLESS-QUEST-TIME-GATES-11316.md) byte environment+30
должен быть больше 5. Поэтому после writer совпадение +40 может стать true,
но фаза 3 ещё не позволяет таймеру продвигаться. Состояние полного действия
нельзя объявлять готовым только по результату первого predicate.
В этом replay полный Time tick не вызывается и сетевые действия не допускаются.

## Fixtures и оставшиеся границы

Model lookup, registration, class/fallback/context resolver и virtual+7B8 guard
остаются fixtures. Форматирование/пустые FString/append и диагностический объект
также fixtures. Они проверяют используемые шаблоны и old/new arguments; исходные
непустые строки и allocation paths не исполняются. Diagnostic sink, notification
context/sink и moved-callback submission — внешние fixtures. Callback 145606830
не выполняется; доставка уведомления движком не доказана. Поле фазы меняет
native handler, а не fixture. `network_used=false`, `action_admitted=false`.

Навигационные кандидаты: 14560C880 переносит callback в выделенный объект с
vtable14990B710; найденный bulk store+40 не связан с environment pending+44.
Whole export сохранён, в replay кандидат не включён. Метод environment slot+60
14561BD60 сохраняет callback в environment+80..BC. Slot+68 14561BE90 вызывает
phase=2 и уведомляет подписчиков; экспорт потребовал бы явного tail root за
unwind range, повтор без уточнения не запускался. Эти сведения не доказывают
отсутствия других writers pending+44.

Далее — producer pending+44, фактический virtual+7B8 и callback применения,
затем активные условия/selected task/actor position для реального offer.
Текущая сессия не перезапускалась, игровых команд в этом исследовании не было.
