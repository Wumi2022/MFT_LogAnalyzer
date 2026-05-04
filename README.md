# MFT Log Analyzer

Analyse-Tool für JRTS Production Diagnosis Tester Ergebnisdateien mit DoIP/UDS-Trace-Korrelation.

## Voraussetzungen

- Python 3.10+ (getestet mit Python 3.13)
- Keine externen Abhängigkeiten – nur Python-Standardbibliothek (`tkinter`, `json`, `re`, `datetime`)

## Start

```bash
python log_analyzer.py
```

Beim Start werden automatisch die voreingestellten Dateipfade geladen, sofern die Dateien vorhanden sind (konfigurierbar über `DEFAULT_LOG` und `DEFAULT_DOIP` am Dateianfang).

## Eingabedateien

### Ergebnis-Datei (`.result` / `.json`)
JSON-Datei vom JRTS Production Diagnosis Tester mit folgendem Aufbau:

```
statResDoc.test
  ├── ptbs[]          – TestBlock-Definitionen (Nummer + Anzeigename)
  └── vecs[]          – Prüfumfänge
        └── ecus[]    – ECUs
              └── fcts[]   – Testfunktionen
                    ├── perfData.starttime   (ISO 8601 UTC)
                    ├── perfData.durationms
                    └── steps[]
```

Zeitstempel werden automatisch von UTC in Lokalzeit umgerechnet (für DoIP-Korrelation).

### Diag-Trace-Datei (`.log` / `.lg0` / `.txt`)
DoIP/UDS-Trace im Format:
```
direction = time='YYMMDD HHMMSS.micros' if='...' type='...' data='...'
```

## Oberfläche

### Filter-Panel

| Feld | Wirkung |
|---|---|
| **ECU** | Filtert nach ECU-ID (Teilstring) |
| **Funktion** | Filtert nach Funktions-ID (Teilstring) |
| **Ergebnis** | Alle / OK / NOK |
| **Textsuche** | Durchsucht `vec_id`, `ecu_id`, `ptb_name`, `fct_id`, `fct_result` |
| **Log. Link / BV/EV** | Zeigt nur ECUs, bei denen die Funktion `OPENCOMS` einen Step `DIAGKOMM` mit passendem `value` hat |

### Tab: Log-Einträge

Hierarchischer Baum mit 5 Ebenen:

```
Prüfumfang (vec)
  └── ECU
        └── TestBlock (ptb)
              └── Funktion  ← OK = grün, NOK = rot
                    └── Steps
```

Spalten: Ergebnis / Start / Dauer / Wert  
Klick auf Funktion oder Step → Detailansicht unten.

### Tab: Diag-Trace (DoIP)

Alle DoIP/UDS-Einträge der Trace-Datei.  
Farbgebung: TX = grün, RX = blau, NegResponse = rot.  
Klick auf Eintrag → Detailansicht mit berechneter Response-Zeit (TX→RX-Paar).

### Tab: Vorgang ↔ Diag

Korrelation zwischen Testergebnis und DoIP-Trace anhand der Zeitfenster (`starttime` … `starttime + durationms`).

- **Obere Tabelle**: alle Funktionen mit Zeitfenster und Anzahl DoIP-Befehle im Fenster (gelb = mind. 1 DoIP-Befehl)
- **Unterer Bereich**: DoIP-Einträge des gewählten Zeitfensters
- **Identifier-Filter**: schränkt die obere Liste auf passende TB/Funktions-Namen ein

## Datenstrukturen

### fct-Eintrag (intern)

```python
{
    'fct_key':     "vec_id/ecu_id/fct_id",  # eindeutiger Schlüssel
    'vec_id':      str,
    'ecu_id':      str,
    'ptb_no':      int,
    'ptb_name':    str,   # bevorzugt de_DE
    'fct_id':      str,
    'fct_result':  str,   # "OK", "NOK", …
    'start_dt':    datetime | None,   # Lokalzeit (naive)
    'stop_dt':     datetime | None,
    'duration_ms': int,
    'steps':       [{'id', 'seqno', 'statno', 'result', 'value'}],
    'hierarchy':   [vec_id, ecu_id, ptb_name, fct_id],
}
```
