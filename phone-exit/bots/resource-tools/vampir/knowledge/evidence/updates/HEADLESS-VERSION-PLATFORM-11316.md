# Version: платформа и контекст 1.13.16

Полный SHA EXE: `d00a197796b7cee30f46854b2a8579049726c2bfba542d359f41b3817ec8b960`.
Повторно использован готовый `run-09b30ec921d8`; Ghidra не запускалась.
SHA экспорта: `05567661bee229c7038ea1e621e08dd3a1c4c3d7685e9551554c222dab33c4da`.

В 116 bounded native сценариях исполнены три целые функции:

- `1445ce2e0`: selector проверяет сравнения с Android, IOS, Windows по порядку;
  получает соответственно 1, 2, 3, иначе 0. В fixtures равенство точное;
  реальная нормализация FName пока не установлена. Проверены возвраты equality
  1, 128, 255, очистка выделенной строки и пустой результат без выделения.
- `1445c4b90`: готовый указатель из `14b564798` возвращается без resolver;
  cold path передаёт type, factory `1445d8d60`, descriptor `149554460`, сохраняет
  результат. Нулевой результат resolver не кэширует успех: повтор снова вызывает его.
- `1416dd660`: таблица по `receiver + 40`, signed count по `+48`, пары по 16 байт,
  искомое 64-битное значение по `entry + 8`. Передаётся индекс первого совпадения,
  иначе `ffffffff` в `1416dd580`. Проверены пустой / отрицательный count,
  первый / последний / отсутствующий элемент, дубликаты и значение uint64 max.

Проверены неизменность входов lookup, canaries результата, nonvolatile registers
и RSP. Вызовы сверяются с конкретными call sites экспортов и байтами EXE.
Повреждённый экспорт или изменённый callee отклоняются.

## Границы и следующий шаг

Platform text, FName constructor / equality / free, type / resolver и value-at
остаются явными fixtures. Проверка не получает реальный контекст ОС, не исполняет
factory, не подтверждает текст enum и не включает эти helpers в whole Version
prepare. Следующие unknown: Windows / CPU helpers, реальные зависимости контекста,
Login prepare и result readers. Runtime profile остаётся partial.

Контекст: [version-platform-11316.json](../../native-contexts/version-platform-11316.json).
Машинный результат: [VERSION-PLATFORM-11316.json](VERSION-PLATFORM-11316.json).

```powershell
python -X utf8 phone-exit/bots/resource-tools/vampir/verify-version-platform-context.py --context phone-exit/bots/resource-tools/vampir/knowledge/native-contexts/version-platform-11316.json
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_version_platform_context.py
```

## Автоматизация следующего обновления

Проверка `native-version-platform-context` включена в game-version и update.
Кэш зависит от полного SHA, контекста, исходников harness / verifier / теста,
закреплённого runtime и сохранённого экспорта. Посторонний README её не запускает.
Для нового SHA найти selector / store / lookup от подготовителя Version, сверить
call sites, literals, cache и table layout; добавить новый контекст и выполнить
тесты. Старые адреса не переносить. Неоднозначность остаётся ручной задачей;
успех этих fixtures не разрешает активацию игрового профиля.
