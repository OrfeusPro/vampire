# Иконка Phone Exit

Исходник: `phone-exit-icon.png`. Создан встроенным image_gen, без внешних логотипов.
Рабочие размеры Windows ICO/PNG и Android PNG создаются командой
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File pc/scripts/build-app-icons.ps1`.
Скрипт только масштабирует исходник и упаковывает размеры в ICO.

Запрос генерации:

> Use case: logo-brand. Create a single finished square app icon for Phone Exit, a private app connecting a Windows PC to the internet through the user's Android phone. Dark navy background #10151f filling the square edge to edge. A distinctive bold mint #62e7bc symbol combining a rounded upright smartphone outline with an outward right-pointing arrow, suggesting a secure personal internet exit. Clean polished flat geometric design, clear at 24px, centered with generous safe margins, symbol contained in middle 60 percent of square for Android adaptive masking. Subtle depth only, crisp high contrast, no tiny details, no text, no letters, no watermark, no mockup, no surrounding canvas. 1024 square.

Android использует adaptive icon с дополнительным безопасным отступом;
уведомление — отдельный одноцветный вектор с тем же мотивом телефона и стрелки.
Ярлык `Phone Exit.lnk` использует локальную ICO и запускает прежний VBS.
При переносе каталога ярлык нужно создать заново с актуальными абсолютными путями.
