**Ez egy folyamatábrát fog kirajzolni**, ahol a dobozok nyilakkal vannak összekötve, sőt, a "Saját Shellcode" dobozt ki is színeztem narancssárgára.

---

### 2. Modern Figyelmeztetések (Alerts)
A sima `**BOLD**` helyett használd a GitHub új figyelmeztető blokkjait. Nagyon jól néznek ki a `Disclaimer` vagy fontos technikai infók kiemelésére.

**Kód:**
```markdown
> [!NOTE]
> Ez a módszer csak x64 környezetben működik megfelelően.

> [!TIP]
> Használj Release módot a Tiered Compilation elkerülése érdekében.

> [!WARNING]
> A VirtualProtect helytelen használata a program összeomlását okozhatja (Access Violation).

> [!CAUTION]
> Soha ne használd ezt a technikát idegen processzen engedély nélkül!
```


```diff
  // Eredeti memóriatartalom
- 55 48 8B EC 48 83 EC
  // Patchelt tartalom (MOV EAX, 1337; RET)
+ B8 37 13 00 00 C3
```

**Eredmény:** A `-` sorok piros háttérrel, a `+` sorok zöld háttérrel jelennek meg. Nagyon látványos hex dumpok összehasonlítására!

---

### 4. Kinyitható részletek (Collapsible Sections)
Mivel a hex dumpok vagy a hosszú logok zavaróak lehetnek, rejtsd el őket egy kinyitható "harmonikába". Így tiszta marad a leírás, de az infó ott van, ha kell.

**Kód:**
```markdown
<details>
<summary><b>Kattints ide a teljes Hex Dump megtekintéséhez</b></summary>
Nyomj <kbd>F5</kbd>-öt a Debug indításához, vagy használd a <kbd>Ctrl</kbd> + <kbd>C</kbd> kombinációt.
```




| Cím (Offset) | Utasítás | Opcode | Magyarázat |
| :--- | :--- | :---: | :--- |
| `Base + 0` | `MOV EAX, 1337` | `B8 37...` | Érték beállítása |
| `Base + 5` | `RET` | `C3` | Visszatérés |



![NetVersion](https://img.shields.io/badge/.NET-8.0-purple)
![Platform](https://img.shields.io/badge/Platform-x64-lightgrey)
![Status](https://img.shields.io/badge/Status-PoC%20Working-brightgreen)