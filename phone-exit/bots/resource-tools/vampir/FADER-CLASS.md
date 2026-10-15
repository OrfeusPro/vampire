# Vampir: точная связь FaderUI с native-классом

15 октября 2026. Продолжение [UI-TRANSITION.md](UI-TRANSITION.md).
Связь Windows подтверждена через superclass импорты cooked-пакета,
регистрацию класса EXE и таблицу виртуальных методов. Не только ImageFader.

## Результат

| Макет | Patch / base entry | Superclass из uasset |
|---|---|---|
| WBP_FaderUI | 759 / 8067 | /Script/NkUMG.NkFaderUI |
| WBP_MediaUI | 789 / 8097 | /Script/NkUMG.NkMediaPlayerUI |

В root export WidgetBlueprintGeneratedClass поле SuperIndex является ссылкой
на import класса. Его Outer указывает на import script-пакета. Генератор сохраняет
смещения, индексы, байты обеих записей и SHA uasset. Циклы/неизвестные ссылки,
изменённое имя или неродной script-пакет отклоняются.

EXE SHA256:
`c7552efd2125e7981945d3443cc1d70a41ac0a8a4cb42e7c77e0d40b4713dfc8`.
Функция регистрации `0x144a2cf50` содержит литералы NkFaderUI и /Script/NkUMG,
а также ссылку на инициализатор `0x144a33370`.
Инициализатор в `0x144a33391–0x144a33398` устанавливает основную vtable
`0x1495f51e0`. В ней:

- слот+0x530 → `0x144a4c440`, где настроены ImageFader и callbacks;
- слот+0x570 → `0x144a4ca20`, где очищаются очереди и state устанавливается в1.

Это связывает разобранные методы с NkFaderUI и макетом WBP_FaderUI.
MediaUI, несмотря на одноимённый элемент, имеет другой superclass.
Поле image_fader_widget_candidates прежнего отчёта остаётся историческим списком
кандидатов по имени; результат различения находится в fader-class-link.json.

## Воспроизведение и источники

```powershell
python phone-exit/bots/resource-tools/vampir/build-fader-class-link.py
python -m unittest discover -s phone-exit/bots -p test_vampir_fader_class.py
```

Нужен текущий ui-transition-code.json, ui-catalog и ui-layout-study.
Capstone закреплён в requirements-native.txt.
Отчёт: `F:/PhoneExit Resources/Vampir/code-clues/fader-class-link.json`.
В нём четыре архивных варианта; два совпадают с native-классом Fader,
два относятся к Media. Сохранены полные кодовые фрагменты, якоря регистрации,
две vtable-записи, cooked superclass chain и происхождение ресурсов.

## Ограничения

Это доказательство отношения класса/методов/ресурса в Windows. Порядок вызова
virtual override, видимость конкретного экземпляра, runtime-привязка к пикселям
и совпадение Android-ресурсов ещё не проверены. Имя слота+0x570 не присвоено
как C++ Reset из одного поведения: использовано описательное название.

Разбор helpers, вызываемых перед очисткой очередей, показал дополнительные
пути обработки дочерних элементов и ресурсов окна. Полный reset→остановка
конкретного easing-таймера пока не доказан; не считать этот вопрос закрытым.
