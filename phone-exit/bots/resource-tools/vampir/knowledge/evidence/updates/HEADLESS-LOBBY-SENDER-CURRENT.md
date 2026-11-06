# Отправка пакетов лобби в Vampir 1.13.22

EXE SHA256 `03edad26033c85835ad8fdc1825df7aeb635e2c199055598ad926bf84b43739f`.
Использованы готовые exports `run-6204f055a2a7` и `run-c5a775460bb6`,
а также подтверждённые текущие OUTPUT, UTF-8, CRC и fallback XOR.

В восьми сценариях исполняются wrapper `0x144aaf380`, sender
`0x144ab0310` и writers Version 1, Login 3 и ServerList 103.
Виртуальные таблицы и getters ID сверены с PE. Проверены пустые и Unicode
строки, прямой и отложенный пути, переполнение sequence 65535,
отказ transport и флаг подавления отправки. Кадры, sequence и результат
совпали с переносимым codec. Ветви sender освобождают оба временных архива.

Очередь, readiness, транспорт, память и CRT заданы стендом. Сокеты и
настоящий drain очереди в этих сценариях отсутствуют.
Полные inputs, исходные границы и результат сохраняются в неизменяемом
manifest. Проверка `lobby-sender-current` подключена к `on_update`.
Готовые standalone матрицы общего frame backend переиспользованы.

[Квитанция пакета](ENTRY-PACKAGE-CURRENT-VALIDATION.json).
