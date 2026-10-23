# Внешность: native map insert / update и фильтр preset

23 октября 2026. EXE SHA256:
`98802d550890354da73cfef101bc49c1691f104beccb8b6d878594ba8952807e`.
Продолжение [пути ползунка](HEADLESS-CREATE-APPEARANCE-SLIDER.md).

## Связь адресов и поиск

`0x1464368f0` вызывает поиск `0x141c347f0` и возвращает
`map.data + index * 0x30 + 0x10`. При отсутствии ключа он вызывает вставку
`0x146436670` и возвращает такой же внутренний адрес новой записи.
Поэтому store `returned_pointer+0x10` из `0x1464568b0` действительно пишет
float в sparse slot `+0x20`, который читает внешний JSON helper.
Два FString в слоте: ключ поиска `+0`, повторённое имя параметра `+0x10`.

Поиск выбирает hash bucket, проходит цепочку slot `+0x28`, сверяет длину
FString и для непустых строк вызывает compare `0x14145f2c0`.
При обновлении найденного ключа слот повторно не выделяется.
Вставка занимает свободный слот либо добавляет новый, обновляет occupation bits,
копирует ключ и связывает hash chain. Native insert инициализирует float `0.5`,
но сразу после возвращения helper перезаписывает его переданным float.
Значение `0.5` не является доказанным default внешности или пресета.

## Исполненные сценарии

`replay-release-appearance-map.py` исполняет целые функции:

- helper `0x1464568b0`;
- lookup `0x1464368f0` и search `0x141c347f0`;
- sparse insert `0x146436670`;
- append occupation bit `0x141429760`.

26 сценариев выполняются в двух режимах: разные синтетические hash и
одинаковый hash для всех имён. Сначала добавляются семь имён групп из BoneGroup,
затем три значения обновляются. Число слотов остаётся семь; существующие
значения сохраняются, новые байты совпадают, включая signed zero.
После этого используется synthetic sparse map из 35 слотов с единственной
занятой записью Height в слоте 34 и free chain 0–33. Обновление Height сохраняет
слот 34; Chest и Pelvis занимают свободные слоты 0 и 1, не расширяя storage.
Проверены free count, occupation bits по обе стороны 31 / 32, имена обоих
FString, байты всех значений и guards owner / storage.

Предварительно выделены 64 слота, 128 бит и 64 hash buckets. Рост storage,
перестроение hash и создание free chain native-удалением не выполнялись.
Hash, compare, FString copy / allocation / free — ограниченные fixtures.
Сравниваются только точные ASCII-имена; правила регистра и Unicode engine
не установлены. Это проверка настоящих lookup / вставки / обновления при
явных предпосылках, а не всей работы контейнера с engine allocator.

## Predicate preset

`0x1464479f0` — leaf без однозначного unwind root. Ghidra оставил его в очереди;
инструмент проверяет полные десять байт и следующие шесть INT3:

```text
0f b6 01       movzx eax, byte ptr [rcx]
38 42 48       cmp byte ptr [rdx+0x48], al
0f 94 c0       sete al
c3             ret
```

64 native случая (восемь значений каждого byte) подтвердили точное равенство.
Статически getter vtable `+0x98`, `0x14644a130`, получает строку класса по
PlayerState `+0x360` и возвращает её type byte `+0x28`.
Следовательно, preset getter фильтрует row `+0x48` по выбранному типу класса.
Это не означает, что конкретный DA_PresetGunner1 выбран первым: порядок строк,
их фактические типы, ссылки и значения preset ещё нужно проверить.

```powershell
python -X utf8 -m unittest discover -s phone-exit/bots -p test_vampir_appearance_map.py
```

Report вне Git:
`F:/PhoneExit Resources/Vampir/code-clues/release-appearance-map/00768a177b755536f91fc79620bc27a6cb91c2f81301bc0bbf2182db9e9222ac/manifest.json`.
SHA256 manifest совпадает с именем каталога. Ghidra comparison:
`c7552efd2125-98802d550890/run-fd4956a37b3c`, details:

| Run | SHA256 details.json | Функции |
| --- | --- | --- |
| run-848ae1fda595 | 7b7c0ee9850d31512fa18de2b32269ee4b321438b70043a77295052ecad92d46 | Lookup |
| run-7e832ccdbecf | 201f6b0f63ad81d478002a443f0d29440cd693adcd8c026db85aa3941b88f5f6 | Search, insert, type getter |
| run-63252b970223 | 612b9d67bb0cd1864dcc0ca037cd03ba178e3d773a42abd3c31b9f4efbf58e99 | Bit append |
| run-591e487095e6 | 1218e6bdd0b07828910f6b15f37046e270804d374e1c28a891ea5b28ab9cb4c7 | Store helper |

Следом — строки текущей DT_CustomizePreset F/M, реальная ссылка выбранного
пресета и его UObject-схема, scale / min / max ползунков. Затем actual key
conversion / JSON output, целый producer и handler ID 104.
Ни авторизация, ни создание персонажа в этой проверке не выполнялись.
