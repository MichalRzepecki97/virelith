# Virelith 0.1.0 — prototyp

Eksperymentalny lokalny skaner plików Windows: ClamAV + YARA-X + SHA-256.
**Nie jest zamiennikiem ochrony real-time i nie potwierdza bezpieczeństwa plików.**
Pierwsza wersja ma tylko regułę TESTOWĄ YARA (nie bazę reguł malware).
Nie usuwa, nie izoluje i nie uruchamia skanowanych plików.

## Przygotuj
1. Windows 11 x64, PowerShell, Python 3.12 x64 z https://www.python.org/downloads/windows/
2. VS Code + rozszerzenie Python (opcjonalnie), Git (opcjonalnie)
3. ClamAV Windows x64 z https://www.clamav.net/downloads/ i poprawnie skonfigurowany FreshClam: https://docs.clamav.net/manual/Usage/SignatureManagement.html
4. Zachowaj Microsoft Defender włączony.

## PowerShell (w katalogu Virelith)
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -c "import yara_x; print('YARA-X OK')"
```

Po zainstalowaniu ClamAV, ustaw pełną ścieżkę do clamscan.exe (lub dodaj ją do PATH). Przed skanowaniem skonfiguruj `freshclam.conf` oraz pobierz sygnatury. Przykład (jeśli binaria są w `C:\Program Files\ClamAV`):
```powershell
& "C:\Program Files\ClamAV\freshclam.exe" --version
& "C:\Program Files\ClamAV\clamscan.exe" --version
```
Po skonfigurowaniu pliku `freshclam.conf` uruchom `freshclam.exe` zgodnie z dokumentacją producenta. Nie uruchamiaj wielokrotnie w krótkich odstępach (limity serwera).

## Bezpieczny test
```powershell
'VIRELITH_TEST_MARKER_2026' | Set-Content .\sample.txt
.\.venv\Scripts\python.exe -m virelith.cli .\sample.txt --clam "C:\Program Files\ClamAV\clamscan.exe" --report .\reports\sample.json
```
Oczekiwany wynik: `detection` z reguły YARA (jest to TEST, a nie malware). Kod wyjścia 1 oznacza dopasowanie, 2 niekompletne skanowanie, 0 brak wykryć. Sprawdź JSON, żeby rozróżnić wyniki dwóch silników.

## Granice MVP
- `clamscan` uruchamiany osobno dla każdego pliku: wolne dla dużych katalogów. Następny etap: `clamd` lub skanowanie wsadowe.
- YARA wczytuje do pamięci pliki do 64 MiB, większe pomija; ClamAV skanuje je niezależnie.
- Katalogi rekurencyjnie; brak specjalnej obsługi dowiązań, wyjątków od uprawnień i limitów liczby plików.
- `incomplete` oznacza problem z silnikiem lub pominiętą analizę. Nie utożsamiaj `no_detection` z bezpieczeństwem.
- **Nie skanuj całego dysku ani katalogów produkcyjnych tym MVP.** Uruchamiaj na małym katalogu testowym.
