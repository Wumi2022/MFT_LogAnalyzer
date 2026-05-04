#!/usr/bin/env python3
"""
MFT Log Analyzer
Filterbares Analyse-Tool für JRTS Production Diagnosis Tester Logs.

TB_  = Testblöcke
TM_  = Testmodule
TF_  = Testfunktionen
"""

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import re
import os
import datetime

# ─── Farben & Labels ────────────────────────────────────────────────────────
LEVEL_COLORS = {
    'N': '#d4edda',  # hellgrün  – Info
    'W': '#fff3cd',  # gelb      – Warn
    'E': '#f8d7da',  # hellrot   – Error
    'D': '#cce5ff',  # hellblau  – Debug
    'T': '#e2e3e5',  # grau      – Trace
}
LEVEL_LABELS = {
    'N': 'Info',
    'W': 'Warn',
    'E': 'Error',
    'D': 'Debug',
    'T': 'Trace',
}

# Voreingestellte Dateien (werden beim Start automatisch geladen, falls vorhanden)
DEFAULT_LOG  = r"C:\Users\AJ2EFQC\Documents\tools\MFT_LogAnalyzer\log\VP2_3\BP0PLGXAZ26032501-20260420161357.result"
DEFAULT_DOIP = r"C:\Users\AJ2EFQC\Documents\tools\MFT_LogAnalyzer\log\VP2_3\doipdata.log"

# ─── DoIP/UDS-Konstanten ────────────────────────────────────────────────────
_DOIP_DIR_RE  = re.compile(r'^(\w+)\s+=')
_DOIP_TIME_RE = re.compile(r"time='(\d{6} \d+\.\d+)'")
_DOIP_IF_RE   = re.compile(r"if='([^']*)'")
_DOIP_TYPE_RE = re.compile(r"type='([^']*)'")
_DOIP_DATA_RE = re.compile(r"data='([^']*)'")

UDS_SERVICES: dict[int, str] = {
    0x10: 'DSC',              0x11: 'ECUReset',
    0x14: 'ClearDTC',         0x19: 'ReadDTC',
    0x22: 'ReadDataById',     0x23: 'ReadMemByAddr',
    0x27: 'SecurityAccess',   0x28: 'CommControl',
    0x2A: 'ReadDataPeriodic', 0x2C: 'DynDefDataId',
    0x2E: 'WriteDataById',    0x2F: 'IOControl',
    0x31: 'RoutineControl',   0x34: 'ReqDownload',
    0x35: 'ReqUpload',        0x36: 'TransferData',
    0x37: 'ReqTransferExit',  0x3D: 'WriteMemByAddr',
    0x3E: 'TesterPresent',
    0x50: 'Resp:DSC',         0x51: 'Resp:ECUReset',
    0x54: 'Resp:ClearDTC',    0x59: 'Resp:ReadDTC',
    0x62: 'Resp:ReadDataById',0x67: 'Resp:SecAccess',
    0x6F: 'Resp:CommControl', 0x71: 'Resp:Routine',
    0x74: 'Resp:ReqDownload', 0x76: 'Resp:Transfer',
    0x77: 'Resp:ReqTransExit',0x7E: 'Resp:TesterPresent',
    0x7F: 'NegResponse',
}


# ─── Parser ─────────────────────────────────────────────────────────────────

# Zeilenformat: LEVEL YYMMDD HHMMSS.micros THREAD [Source.java : line - method] message [callchain]
_LINE_RE      = re.compile(r'^([NWEDT])\s+(\d{6})\s+(\d+\.\d+)\s+(\S+)\s+\[([^\]]+)\]\s+(.*)')
# Callchain = letztes [...] das mindestens ein #<Zahl>-Muster enthält
_CC_RE        = re.compile(r'\[([^\[\]]*#\d+[^\[\]]*)\]\s*$')
# Komponenten-Muster (Name + ID)  →  name#123  oder  name:123#
_TB_RE        = re.compile(r'(TB_\w+)[:#](\d+)')
_TM_RE        = re.compile(r'((?:D)?TM_\w+)[:#](\d+)')
_TF_RE        = re.compile(r'((?:D)?TF_\w+)[:#](\d+)')
# Generisches Callchain-Token-Muster:  Name#ID  (ID ≥ 3 Stellen)
_CC_TOKEN_RE  = re.compile(r'([\w.]+)#(\d{3,})')

def _parse_callchain_hierarchy(callchain: str) -> list[tuple[str, str]]:
    """Gibt die Callchain-Ebenen als Liste von (Name, ID) zurück.
    Reihenfolge: Root zuerst (rechtes Token = Root in JRTS-Logs).
    Beispiel: [@action:2979#Comp#12:Parent#11:Root#10:] → [('Root','10'),('Parent','11'),('Comp','12')]
    """
    if not callchain:
        return []
    tokens = _CC_TOKEN_RE.findall(callchain)
    # JRTS: letzter Token = Root → umkehren für Root-first
    tokens.reverse()
    return tokens


def _get_vorgang_key(entry: dict) -> tuple[str, str] | None:
    """Gibt (vg_nr, vg_id) für einen Log-Eintrag zurück, oder None.
    Strategie: Root-Knoten der Callchain (= letztes Name#ID-Token) → Vorgang-Identifier.
    TB_/TM_-Namen haben Vorrang.
    """
    cc = entry.get('callchain', '')
    if not cc:
        return None
    tokens = _CC_TOKEN_RE.findall(cc)   # links→rechts in callchain-String
    if not tokens:
        return None
    # Bevorzuge TB_ oder TM_ als Root (letztes matching token)
    for name, id_ in reversed(tokens):
        if name.startswith('TB_') or name.startswith('TM_') or name.startswith('DTM_'):
            return (id_, name)
    # Kein Typ-Präfix → letztes Token = Root verwenden
    root_name, root_id = tokens[-1]
    return (root_id, root_name)


def parse_log_file(filepath: str) -> list[dict]:
    """Liest die Log-Datei und gibt eine Liste von Entry-Dicts zurück."""
    entries = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
        for line_num, raw_line in enumerate(fh, 1):
            raw = raw_line.rstrip('\r\n')
            if not raw.strip():
                continue

            entry = dict(
                line_num=line_num,
                raw=raw,
                level='',
                date='',
                time='',
                thread='',
                source='',
                message='',
                callchain='',
                tb_list=[],   # [(name, id_str), ...]
                tm_list=[],
                tf_list=[],
                all_ids=set(),
                hierarchy=[],  # [(name, id), ...] Root-first
                vg_key=None,   # (vg_nr_id, vg_name) oder None
            )

            m = _LINE_RE.match(raw)
            if m:
                entry['level']  = m.group(1)
                entry['date']   = m.group(2)
                entry['time']   = m.group(3)
                entry['thread'] = m.group(4)
                entry['source'] = m.group(5)
                rest = m.group(6)

                cc_m = _CC_RE.search(rest)
                if cc_m:
                    entry['callchain'] = cc_m.group(1)
                    entry['message']   = rest[:cc_m.start()].strip()
                else:
                    entry['message'] = rest.strip()

            cc = entry['callchain']
            if cc:
                entry['tb_list'] = _TB_RE.findall(cc)
                entry['tm_list'] = _TM_RE.findall(cc)
                entry['tf_list'] = _TF_RE.findall(cc)
                for name, id_ in entry['tb_list'] + entry['tm_list'] + entry['tf_list']:
                    entry['all_ids'].add(id_)
                # Hierarchie-Ebenen (Root-first)
                entry['hierarchy'] = _parse_callchain_hierarchy(cc)
                # Vorgang-Schlüssel für diese Zeile
                vk = _get_vorgang_key(entry)
                entry['vg_key'] = vk   # (vg_nr_as_id, vg_id_name) oder None
            else:
                entry['hierarchy'] = []
                entry['vg_key'] = None

            entries.append(entry)
    return entries


def _parse_ts(date_str: str, time_str: str):
    """Parst Datum (YYMMDD) und Zeit (HHMMSS.micros) in ein datetime-Objekt."""
    try:
        parts = time_str.split('.')
        hms = parts[0]                                          # HHMMSS
        micros = int(parts[1].ljust(6, '0')[:6]) if len(parts) > 1 else 0
        dt = datetime.datetime.strptime(date_str + hms, '%y%m%d%H%M%S')
        return dt.replace(microsecond=micros)
    except Exception:
        return None


def parse_doip_file(filepath: str) -> list[dict]:
    """Liest eine DoIP/UDS-Trace-Datei und gibt eine Liste von Entry-Dicts zurück."""
    entries = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
        for line_num, raw_line in enumerate(fh, 1):
            raw = raw_line.rstrip('\r\n')
            if not raw.strip():
                continue

            dir_m  = _DOIP_DIR_RE.match(raw)
            time_m = _DOIP_TIME_RE.search(raw)
            if not dir_m or not time_m:
                continue

            direction = dir_m.group(1)          # tx / rx / open / close / start
            raw_time  = time_m.group(1)          # 'YYMMDD HHMMSS.micros'
            date_part, time_part = raw_time.split(' ', 1)

            if_m   = _DOIP_IF_RE.search(raw)
            type_m = _DOIP_TYPE_RE.search(raw)
            data_m = _DOIP_DATA_RE.search(raw)

            if_str   = if_m.group(1)   if if_m   else ''
            type_str = type_m.group(1).strip() if type_m else ''
            data_str = data_m.group(1) if data_m else ''

            # DoIP-Daten zerlegen: 02FD  TYPE  LENGTH  SRC  DST  UDS…
            src_doip = dst_doip = uds_str = uds_svc = ''
            tokens = data_str.split() if data_str else []
            if len(tokens) >= 5 and tokens[1] in ('8001', '8002'):
                src_doip = tokens[3]
                dst_doip = tokens[4]
                uds_tokens = tokens[5:]
                uds_str = ' '.join(uds_tokens)
                if uds_tokens:
                    try:
                        svc_byte = int(uds_tokens[0], 16)
                        uds_svc = UDS_SERVICES.get(svc_byte, uds_tokens[0])
                    except ValueError:
                        uds_svc = uds_tokens[0]
            elif tokens:
                uds_str = data_str          # z.B. routing activation

            dt = _parse_ts(date_part, time_part)
            entries.append(dict(
                line_num  = line_num,
                direction = direction,
                raw_time  = raw_time,
                date      = date_part,
                time      = time_part,
                timestamp = f"{date_part} {time_part}",
                datetime  = dt,
                if_str    = if_str,
                msg_type  = type_str,
                raw_data  = data_str,
                src_doip  = src_doip,
                dst_doip  = dst_doip,
                uds_str   = uds_str,
                uds_svc   = uds_svc,
                vorgang_id = '',
                vorgang_nr = '',
            ))
    return entries


def parse_result_file(filepath: str) -> list[dict]:
    """Liest eine .result-Datei (JSON) und gibt eine Liste von fct-Einträgen zurück.
    Hierarchie: statResDoc.test.vecs[] → ecus[] → fcts[] → steps[]
    Zeitstempel werden von UTC in lokale Zeit umgerechnet.
    """
    import json as _json

    with open(filepath, 'r', encoding='utf-8-sig', errors='replace') as fh:
        data = _json.load(fh)
    root = data.get('statResDoc', data)
    test = root.get('test', {})

    # ptb-Lookup: Nummer → Anzeigename (bevorzugt de_DE)
    ptb_lookup: dict[int, str] = {}
    for ptb in test.get('ptbs', []):
        no       = ptb.get('no')
        name_obj = ptb.get('name', {})
        name_str = ''
        if isinstance(name_obj, dict):
            for t in (name_obj.get('texts') or []):
                if isinstance(t, dict):
                    lt = t.get('langtext', '')
                    if t.get('langcode') == 'de_DE':
                        name_str = lt
                        break
                    if not name_str:
                        name_str = lt
            if not name_str:
                name_str = name_obj.get('textvalue', '') or str(no)
        ptb_lookup[no] = name_str or str(no)

    entries: list[dict] = []
    for vec in test.get('vecs', []):
        vec_id = str(vec.get('id', '?'))
        for ecu in vec.get('ecus', []):
            ecu_id = str(ecu.get('id', '?'))
            for fct in ecu.get('fcts', []):
                fct_id     = str(fct.get('id', '?'))
                ptb_no     = int(fct.get('ptb') or 0)
                ptb_name   = ptb_lookup.get(ptb_no, str(ptb_no))
                fct_result = str(fct.get('result', ''))

                # perfData kann Liste oder dict sein
                perf = fct.get('perfData', {})
                if isinstance(perf, list):
                    perf = perf[0] if perf else {}
                if not isinstance(perf, dict):
                    perf = {}
                starttime_str = str(perf.get('starttime', '') or '')
                duration_ms   = int(perf.get('durationms') or 0)

                start_dt = stop_dt = None
                if starttime_str:
                    try:
                        # ISO UTC → Lokalzeit (naive), damit Vergleich mit DoIP-Zeitstempeln klappt
                        dt_utc   = datetime.datetime.fromisoformat(
                            starttime_str.replace('Z', '+00:00'))
                        start_dt = dt_utc.astimezone().replace(tzinfo=None)
                        stop_dt  = start_dt + datetime.timedelta(milliseconds=duration_ms)
                    except Exception:
                        pass

                # Steps auflösen
                steps: list[dict] = []
                for step in fct.get('steps', []):
                    val_obj = step.get('value', {})
                    val_str = ''
                    if isinstance(val_obj, dict):
                        sv = val_obj.get('stringvalue', {})
                        if isinstance(sv, dict):
                            val_str = sv.get('textvalue', '') or ''
                        if not val_str:
                            val_str = str(val_obj.get('rawvalue', '') or '')
                    steps.append({
                        'id':     str(step.get('id', '')),
                        'seqno':  int(step.get('seqno') or 0),
                        'statno': int(step.get('statno') or 0),
                        'result': str(step.get('result', '')),
                        'value':  val_str,
                    })

                entries.append({
                    'fct_key':     f"{vec_id}/{ecu_id}/{fct_id}",
                    'vec_id':      vec_id,
                    'ecu_id':      ecu_id,
                    'ptb_no':      ptb_no,
                    'ptb_name':    ptb_name,
                    'fct_id':      fct_id,
                    'fct_result':  fct_result,
                    'start_dt':    start_dt,
                    'stop_dt':     stop_dt,
                    'duration_ms': duration_ms,
                    'steps':       steps,
                    'hierarchy':   [vec_id, ecu_id, ptb_name, fct_id],
                })
    return entries


# ─── GUI ────────────────────────────────────────────────────────────────────

class LogAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("MFT Log Analyzer")
        self.root.geometry("1640x940")
        self.root.minsize(1100, 640)

        self.log_entries: list[dict] = []    # result fct-Einträge (parse_result_file)
        self.filtered_entries: list[dict] = []
        self.doip_entries: list[dict] = []
        self._vd_spans: list = []          # [(iid, vg_nr, vg_id, start_dt, stop_dt, cnt, dur)]
        self._vd_doip_entries: list = []   # DoIP-Einträge des aktuell gewählten Vorgangs
        self._filter_after_id = None
        self._sort_state: dict[str, bool] = {}   # col → reverse

        self._setup_styles()
        self._build_ui()

    # ── Styles ───────────────────────────────────────────────────────────────
    def _setup_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TLabelframe.Label', font=('Segoe UI', 9, 'bold'))
        style.configure('Status.TLabel', relief=tk.SUNKEN, padding=(4, 2))
        for code, bg in LEVEL_COLORS.items():
            style.configure(f'Lv{code}.Treeview', background=bg)

    # ── UI-Aufbau ────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Dateiauswahl ────────────────────────────────────────────────────
        file_frame = ttk.Frame(self.root, padding=(6, 5))
        file_frame.pack(fill=tk.X)

        ttk.Label(file_frame, text="Ergebnis-Datei:").pack(side=tk.LEFT)
        self.file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_var, width=95).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Öffnen …",
                   command=self._open_file).pack(side=tk.LEFT)
        ttk.Button(file_frame, text="Neu laden",
                   command=self._load_file).pack(side=tk.LEFT, padx=5)

        # ── Diag-Trace-Auswahl ──────────────────────────────────────────────
        diag_frame = ttk.Frame(self.root, padding=(6, 2))
        diag_frame.pack(fill=tk.X)
        ttk.Label(diag_frame, text="Diag-Trace:", width=10).pack(side=tk.LEFT)
        self.diag_file_var = tk.StringVar()
        ttk.Entry(diag_frame, textvariable=self.diag_file_var, width=90).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(diag_frame, text="Öffnen …",
                   command=self._open_doip_file).pack(side=tk.LEFT)
        ttk.Button(diag_frame, text="Laden",
                   command=self._load_doip_file).pack(side=tk.LEFT, padx=5)
        self.doip_status_var = tk.StringVar(value="Kein Diag-Trace geladen.")
        ttk.Label(diag_frame, textvariable=self.doip_status_var,
                  foreground='gray').pack(side=tk.LEFT, padx=10)

        # ── Filter-Panel ────────────────────────────────────────────────────
        filter_lf = ttk.LabelFrame(self.root, text="Filter", padding=(8, 5))
        filter_lf.pack(fill=tk.X, padx=6, pady=(0, 3))

        # Zeile 0 – ECU + Funktion + Ergebnis-Filter
        row0 = ttk.Frame(filter_lf)
        row0.pack(fill=tk.X, pady=2)
        ttk.Label(row0, text="ECU:", width=7).pack(side=tk.LEFT)
        self.ecu_var = tk.StringVar()
        self.ecu_combo = ttk.Combobox(row0, textvariable=self.ecu_var, width=25)
        self.ecu_combo.pack(side=tk.LEFT, padx=(2, 10))
        self.ecu_var.trace_add('write', self._on_filter_change)

        ttk.Label(row0, text="Funktion:", width=9).pack(side=tk.LEFT)
        self.fct_var = tk.StringVar()
        self.fct_combo = ttk.Combobox(row0, textvariable=self.fct_var, width=35)
        self.fct_combo.pack(side=tk.LEFT, padx=(2, 10))
        self.fct_var.trace_add('write', self._on_filter_change)

        ttk.Separator(row0, orient=tk.VERTICAL).pack(
            side=tk.LEFT, fill=tk.Y, padx=10, pady=2)
        ttk.Label(row0, text="Ergebnis:").pack(side=tk.LEFT)
        self.result_filter_var = tk.StringVar(value='Alle')
        for _lbl in ('Alle', 'OK', 'NOK'):
            ttk.Radiobutton(row0, text=_lbl, variable=self.result_filter_var,
                            value=_lbl, command=self._schedule_filter).pack(
                side=tk.LEFT, padx=4)

        # Zeile 1 – Textsuche + Leeren
        row1 = ttk.Frame(filter_lf)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Textsuche:", width=9).pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.search_var, width=40).pack(
            side=tk.LEFT, padx=(2, 12))
        self.search_var.trace_add('write', self._on_filter_change)

        ttk.Label(row1, text="Log. Link / BV/EV:").pack(side=tk.LEFT, padx=(0, 4))
        self.ll_var = tk.StringVar()
        ttk.Entry(row1, textvariable=self.ll_var, width=30).pack(
            side=tk.LEFT, padx=(0, 12))
        self.ll_var.trace_add('write', self._on_filter_change)

        ttk.Button(row1, text="Filter leeren",
                   command=self._clear_filter).pack(side=tk.LEFT)

        # ── Statuszeile ─────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Keine Datei geladen.")
        ttk.Label(self.root, textvariable=self.status_var,
                  style='Status.TLabel').pack(fill=tk.X, padx=6)

        # ── Haupt-Pane (Notebook + Detail) ──────────────────────────────────
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=(3, 5))

        # Notebook für Tabs
        self.notebook = ttk.Notebook(paned)
        paned.add(self.notebook, weight=5)

        # Tab 1 – Log-Einträge
        table_frame = ttk.Frame(self.notebook)
        self.notebook.add(table_frame, text="Log-Einträge")

        cols = ('res_result', 'res_time', 'res_dur', 'res_value')
        col_cfg = {
            'res_result': ('Ergebnis',   80,  tk.CENTER, False),
            'res_time':   ('Start',      145, tk.W,      False),
            'res_dur':    ('Dauer',       90, tk.W,      False),
            'res_value':  ('Wert',       450, tk.W,      True),
        }

        self.tree = ttk.Treeview(
            table_frame, columns=cols, show='tree headings', selectmode='browse')

        for col, (heading, width, anchor, stretch) in col_cfg.items():
            self.tree.heading(col, text=heading)
            self.tree.column(
                col, width=width, anchor=anchor,
                stretch=tk.YES if stretch else tk.NO)

        vsb = ttk.Scrollbar(table_frame, orient=tk.VERTICAL,
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL,
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Farbgebung nach Ergebnis
        self.tree.tag_configure('ok',  background='#d4edda')   # grün
        self.tree.tag_configure('nok', background='#f8d7da')   # rot

        self.tree.bind('<<TreeviewSelect>>', self._on_select)

        # Tab 2 – Diag-Trace (DoIP/UDS)
        doip_frame = ttk.Frame(self.notebook)
        self.notebook.add(doip_frame, text="Diag-Trace (DoIP)")

        doip_cols = ('dt_time', 'dt_dir', 'dt_if', 'dt_type',
                     'dt_src', 'dt_dst', 'dt_svc', 'dt_data')
        doip_col_cfg = {
            'dt_time': ('Zeitstempel',   145, tk.W,      False),
            'dt_dir':  ('Richtung',       65, tk.CENTER, False),
            'dt_if':   ('Interface',      80, tk.W,      False),
            'dt_type': ('Typ',            80, tk.W,      False),
            'dt_src':  ('SRC',            55, tk.CENTER, False),
            'dt_dst':  ('DST',            55, tk.CENTER, False),
            'dt_svc':  ('UDS-Service',   160, tk.W,      False),
            'dt_data': ('Rohdaten',      600, tk.W,      True),
        }
        self.doip_tree = ttk.Treeview(
            doip_frame, columns=doip_cols, show='headings', selectmode='browse')
        for col, (heading, width, anchor, stretch) in doip_col_cfg.items():
            self.doip_tree.heading(col, text=heading)
            self.doip_tree.column(
                col, width=width, anchor=anchor,
                stretch=tk.YES if stretch else tk.NO)

        dt_vsb = ttk.Scrollbar(doip_frame, orient=tk.VERTICAL,
                               command=self.doip_tree.yview)
        dt_hsb = ttk.Scrollbar(doip_frame, orient=tk.HORIZONTAL,
                               command=self.doip_tree.xview)
        self.doip_tree.configure(yscrollcommand=dt_vsb.set,
                                 xscrollcommand=dt_hsb.set)
        self.doip_tree.grid(row=0, column=0, sticky='nsew')
        dt_vsb.grid(row=0, column=1, sticky='ns')
        dt_hsb.grid(row=1, column=0, sticky='ew')
        doip_frame.rowconfigure(0, weight=1)
        doip_frame.columnconfigure(0, weight=1)

        self.doip_tree.tag_configure('tx',  background='#dff0d8')
        self.doip_tree.tag_configure('rx',  background='#d9edf7')
        self.doip_tree.tag_configure('neg', background='#f8d7da')
        self.doip_tree.bind('<<TreeviewSelect>>', self._on_doip_select)

        # Tab 4 – Vorgang ↔ Diag
        vd_outer = ttk.Frame(self.notebook)
        self.notebook.add(vd_outer, text="Vorgang ↔ Diag")

        # Filter-Zeile
        vd_filter_frame = ttk.Frame(vd_outer, padding=(4, 3))
        vd_filter_frame.pack(fill=tk.X)
        ttk.Label(vd_filter_frame, text="Identifier-Filter:").pack(side=tk.LEFT)
        self.vd_filter_var = tk.StringVar()
        ttk.Entry(vd_filter_frame, textvariable=self.vd_filter_var, width=50).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(vd_filter_frame, text="Leeren",
                   command=lambda: self.vd_filter_var.set('')).pack(side=tk.LEFT)
        self.vd_filter_var.trace_add('write', lambda *_: self._vd_filter_changed())

        vd_paned = ttk.PanedWindow(vd_outer, orient=tk.VERTICAL)
        vd_paned.pack(fill=tk.BOTH, expand=True)

        # Obere Hälfte: Vorgänge mit DoIP-Zähler
        vd_top = ttk.Frame(vd_paned)
        vd_paned.add(vd_top, weight=2)

        vd_top_cols = ('vd_nr', 'vd_id', 'vd_start', 'vd_end', 'vd_dur', 'vd_cnt')
        vd_top_col_cfg = {
            'vd_nr':    ('ECU',          80, tk.W,      False),
            'vd_id':    ('TB / Funktion',300, tk.W,      True),
            'vd_start': ('Start',        145, tk.W,      False),
            'vd_end':   ('Ende',         145, tk.W,      False),
            'vd_dur':   ('Dauer',         90, tk.W,      False),
            'vd_cnt':   ('#DoIP',         55, tk.E,      False),
        }
        self.vd_vg_tree = ttk.Treeview(
            vd_top, columns=vd_top_cols, show='headings', selectmode='browse')
        for col, (heading, width, anchor, stretch) in vd_top_col_cfg.items():
            self.vd_vg_tree.heading(col, text=heading)
            self.vd_vg_tree.column(
                col, width=width, anchor=anchor,
                stretch=tk.YES if stretch else tk.NO)

        vd_vsb_top = ttk.Scrollbar(vd_top, orient=tk.VERTICAL,
                                   command=self.vd_vg_tree.yview)
        vd_hsb_top = ttk.Scrollbar(vd_top, orient=tk.HORIZONTAL,
                                   command=self.vd_vg_tree.xview)
        self.vd_vg_tree.configure(yscrollcommand=vd_vsb_top.set,
                                  xscrollcommand=vd_hsb_top.set)
        self.vd_vg_tree.grid(row=0, column=0, sticky='nsew')
        vd_vsb_top.grid(row=0, column=1, sticky='ns')
        vd_hsb_top.grid(row=1, column=0, sticky='ew')
        vd_top.rowconfigure(0, weight=1)
        vd_top.columnconfigure(0, weight=1)
        self.vd_vg_tree.bind('<<TreeviewSelect>>', self._on_vorgang_diag_select)
        self.vd_vg_tree.tag_configure('has_diag', background='#fff3cd')

        # Untere Hälfte: DoIP-Einträge des gewählten Vorgangs
        vd_bot = ttk.Frame(vd_paned)
        vd_paned.add(vd_bot, weight=3)

        ttk.Label(vd_bot, text="DoIP-Befehle im gewählten Vorgang:",
                  padding=(4, 2)).pack(anchor=tk.W)
        vd_bot_inner = ttk.Frame(vd_bot)
        vd_bot_inner.pack(fill=tk.BOTH, expand=True)

        vd_bot_cols = ('vd_dt_time', 'vd_dt_dir', 'vd_dt_src', 'vd_dt_dst',
                       'vd_dt_svc', 'vd_dt_data')
        vd_bot_col_cfg = {
            'vd_dt_time': ('Zeitstempel',  145, tk.W,      False),
            'vd_dt_dir':  ('Richtung',      65, tk.CENTER, False),
            'vd_dt_src':  ('SRC',           55, tk.CENTER, False),
            'vd_dt_dst':  ('DST',           55, tk.CENTER, False),
            'vd_dt_svc':  ('UDS-Service',  160, tk.W,      False),
            'vd_dt_data': ('Rohdaten',     600, tk.W,      True),
        }
        self.vd_doip_tree = ttk.Treeview(
            vd_bot_inner, columns=vd_bot_cols, show='headings', selectmode='browse')
        for col, (heading, width, anchor, stretch) in vd_bot_col_cfg.items():
            self.vd_doip_tree.heading(col, text=heading)
            self.vd_doip_tree.column(
                col, width=width, anchor=anchor,
                stretch=tk.YES if stretch else tk.NO)

        vd_vsb_bot = ttk.Scrollbar(vd_bot_inner, orient=tk.VERTICAL,
                                   command=self.vd_doip_tree.yview)
        vd_hsb_bot = ttk.Scrollbar(vd_bot_inner, orient=tk.HORIZONTAL,
                                   command=self.vd_doip_tree.xview)
        self.vd_doip_tree.configure(yscrollcommand=vd_vsb_bot.set,
                                    xscrollcommand=vd_hsb_bot.set)
        self.vd_doip_tree.grid(row=0, column=0, sticky='nsew')
        vd_vsb_bot.grid(row=0, column=1, sticky='ns')
        vd_hsb_bot.grid(row=1, column=0, sticky='ew')
        vd_bot_inner.rowconfigure(0, weight=1)
        vd_bot_inner.columnconfigure(0, weight=1)

        self.vd_doip_tree.tag_configure('tx',  background='#dff0d8')
        self.vd_doip_tree.tag_configure('rx',  background='#d9edf7')
        self.vd_doip_tree.tag_configure('neg', background='#f8d7da')
        self.vd_doip_tree.bind('<<TreeviewSelect>>', self._on_vd_doip_select)

        # Detail-Frame (gemeinsam für beide Tabs)
        detail_lf = ttk.LabelFrame(
            paned, text="Details", padding=5)
        paned.add(detail_lf, weight=1)

        self.detail_text = scrolledtext.ScrolledText(
            detail_lf, height=7, wrap=tk.WORD,
            font=('Consolas', 9), state=tk.DISABLED)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

    # ── Event-Handler ────────────────────────────────────────────────────────
    def _open_doip_file(self):
        path = filedialog.askopenfilename(
            title="Diag-Trace öffnen",
            filetypes=[
                ("Log-Dateien", "*.log *.lg0 *.txt"),
                ("Alle Dateien", "*.*"),
            ],
        )
        if path:
            self.diag_file_var.set(path)
            self._load_doip_file()

    def _load_doip_file(self):
        path = self.diag_file_var.get().strip()
        if not path:
            return
        if not os.path.isfile(path):
            messagebox.showerror("Fehler", f"Datei nicht gefunden:\n{path}")
            return

        self.doip_status_var.set("Lade Diag-Trace …")
        self.root.update_idletasks()

        try:
            self.doip_entries = parse_doip_file(path)
        except Exception as exc:
            messagebox.showerror("Ladefehler", str(exc))
            self.doip_status_var.set("Fehler beim Laden.")
            return

        self.doip_status_var.set(
            f"{len(self.doip_entries)} Einträge geladen: {os.path.basename(path)}"
        )
        self._populate_doip_tree()
        self._refresh_vorgang_diag_view()

    def _populate_doip_tree(self):
        self.doip_tree.delete(*self.doip_tree.get_children())
        for idx, e in enumerate(self.doip_entries):
            if e['uds_svc'] == 'NegResponse':
                tag = 'neg'
            elif e['direction'].lower() in ('tx', 'rx'):
                tag = e['direction'].lower()
            else:
                tag = ''
            self.doip_tree.insert('', tk.END, iid=str(idx), values=(
                e['timestamp'],
                e['direction'],
                e['if_str'],
                e['msg_type'],
                e['src_doip'],
                e['dst_doip'],
                e['uds_svc'],
                e['raw_data'],
                e['timestamp'],
                e['direction'],
                e['if_str'],
                e['msg_type'],
                e['src_doip'],
                e['dst_doip'],
                e['uds_svc'],
                e['raw_data'],
            ), tags=(tag,) if tag else ())

    def _on_doip_select(self, _event=None):
        sel = self.doip_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        e   = self.doip_entries[idx]

        direction = e['direction'].lower()
        src  = e['src_doip']  or '—'
        dst  = e['dst_doip']  or '—'
        svc  = e['uds_svc']   or '—'
        data = e['raw_data']  or '—'
        ts   = e['timestamp']

        # Response-Time: nur bei RX-Response, rückwärts passenden TX-Request suchen
        resp_time_str = '—'
        if direction == 'rx' and e['datetime'] and src and dst:
            resp_dt = e['datetime']
            for de in reversed(self.doip_entries[:idx]):
                if de['direction'].lower() != 'tx':
                    continue
                if not de['datetime'] or de['datetime'] > resp_dt:
                    continue
                if de['src_doip'] == dst and de['dst_doip'] == src:
                    delta  = resp_dt - de['datetime']
                    total_us = delta.seconds * 1_000_000 + delta.microseconds
                    ms     = total_us / 1000
                    resp_time_str = f"{ms:.3f} ms  (Request: {de['timestamp']})"
                    break

        lines = [
            f"Zeitstempel:          {ts}",
            f"Richtung:             {e['direction']}",
            f"",
            f"Sende-DoIP-Adresse:   {src}",
            f"Empfangs-DoIP-Adresse:{dst}",
            f"",
            f"UDS-Service:          {svc}",
            f"Rohdaten:             {data}",
            f"",
            f"Response-Time:        {resp_time_str}",
        ]
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Ergebnis-Datei öffnen",
            filetypes=[
                ("Ergebnis-Dateien", "*.result *.json"),
                ("Alle Dateien", "*.*"),
            ],
        )
        if path:
            self.file_var.set(path)
            self._load_file()

    def _load_file(self):
        path = self.file_var.get().strip()
        if not path:
            return
        if not os.path.isfile(path):
            messagebox.showerror("Fehler", f"Datei nicht gefunden:\n{path}")
            return

        self.status_var.set("Lade Ergebnis-Datei …")
        self.root.update_idletasks()

        try:
            self.log_entries = parse_result_file(path)
        except Exception as exc:
            messagebox.showerror("Ladefehler", str(exc))
            return

        # Comboboxen befüllen
        ecu_set: set[str] = set()
        fct_set: set[str] = set()
        for e in self.log_entries:
            ecu_set.add(e['ecu_id'])
            fct_set.add(e['fct_id'])

        self.ecu_combo['values'] = [''] + sorted(ecu_set)
        self.fct_combo['values'] = [''] + sorted(fct_set)

        self._apply_filter()
        self._refresh_vorgang_diag_view()

    # ── Filterlogik ──────────────────────────────────────────────────────────
    def _on_filter_change(self, *_):
        self._schedule_filter()

    def _schedule_filter(self):
        if self._filter_after_id is not None:
            self.root.after_cancel(self._filter_after_id)
        self._filter_after_id = self.root.after(220, self._apply_filter)

    def _apply_filter(self):
        self._filter_after_id = None

        ecu_f = self.ecu_var.get().strip().lower()
        fct_f = self.fct_var.get().strip().lower()
        res_f = self.result_filter_var.get()   # 'Alle' / 'OK' / 'NOK'
        txt_f = self.search_var.get().strip().lower()
        ll_f  = self.ll_var.get().strip().lower()

        # Pre-compute (vec_id, ecu_id)-Paare, die den Log. Link / BV/EV-Filter erfüllen:
        # Eine ECU gilt als passend, wenn ihre fct OPENCOMS einen Step DIAGKOMM hat,
        # dessen value den Suchtext enthält.
        ll_valid_keys: set[tuple[str, str]] | None = None
        if ll_f:
            ll_valid_keys = set()
            for e in self.log_entries:
                if e['fct_id'] != 'OPENCOMS':
                    continue
                for step in e['steps']:
                    if step['id'] == 'DIAGKOMM' and ll_f in step['value'].lower():
                        ll_valid_keys.add((e['vec_id'], e['ecu_id']))
                        break

        result = []
        for e in self.log_entries:
            if ecu_f and ecu_f not in e['ecu_id'].lower():
                continue
            if ll_valid_keys is not None and (e['vec_id'], e['ecu_id']) not in ll_valid_keys:
                continue
            if fct_f and fct_f not in e['fct_id'].lower():
                continue
            if res_f == 'OK' and e['fct_result'] != 'OK':
                continue
            if res_f == 'NOK' and e['fct_result'] not in ('NOK', 'FAILED', 'ERROR', 'NOTOK'):
                continue
            if txt_f:
                searchable = f"{e['vec_id']} {e['ecu_id']} {e['ptb_name']} {e['fct_id']} {e['fct_result']}".lower()
                if txt_f not in searchable:
                    continue
            result.append(e)

        self.filtered_entries = result
        self._refresh_table()

    # ── Tabelle (Ergebnis-Hierarchie) ────────────────────────────────────────
    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())

        # Aufbau: Prüfumfang (vec) → ECU → TestBlock (ptb) → Funktion (fct) → Step
        # tree-iid Konventionen:
        #   vec:   "V:{vec_id}"
        #   ecu:   "E:{vec_id}:{ecu_id}"
        #   ptb:   "P:{vec_id}:{ecu_id}:{ptb_no}"
        #   fct:   str(filtered_idx)   ← Ganzzahl → _on_select erkennt Blatt-Level
        #   step:  "s{fct_idx}_{seqno}"

        created_vecs: set[str] = set()
        created_ecus: set[str] = set()
        created_ptbs: set[str] = set()

        for idx, e in enumerate(self.filtered_entries):
            vec_id   = e['vec_id']
            ecu_id   = e['ecu_id']
            ptb_no   = e['ptb_no']
            ptb_name = e['ptb_name']

            # Prüfumfang-Knoten
            vec_iid = f"V:{vec_id}"
            if vec_iid not in created_vecs:
                created_vecs.add(vec_iid)
                self.tree.insert('', tk.END, iid=vec_iid,
                                 text=f"Prüfumfang:  {vec_id}",
                                 values=('', '', '', ''), open=True)

            # ECU-Knoten
            ecu_iid = f"E:{vec_id}:{ecu_id}"
            if ecu_iid not in created_ecus:
                created_ecus.add(ecu_iid)
                self.tree.insert(vec_iid, tk.END, iid=ecu_iid,
                                 text=f"ECU:  {ecu_id}",
                                 values=('', '', '', ''), open=True)

            # TestBlock-Knoten
            ptb_iid = f"P:{vec_id}:{ecu_id}:{ptb_no}"
            if ptb_iid not in created_ptbs:
                created_ptbs.add(ptb_iid)
                self.tree.insert(ecu_iid, tk.END, iid=ptb_iid,
                                 text=f"TB:  {ptb_name}",
                                 values=('', '', '', ''), open=True)

            # Funktion
            res = e['fct_result']
            start_str = ''
            dur_str   = ''
            if e['start_dt']:
                start_str = (f"{e['start_dt'].strftime('%y%m%d %H%M%S')}."
                             f"{e['start_dt'].microsecond // 1000:03d}")
            if e['duration_ms']:
                ms = e['duration_ms']
                dur_str = f"{ms // 60000:02d}:{(ms % 60000) // 1000:02d}.{ms % 1000:03d}"
            tag = 'ok' if res == 'OK' else ('nok' if res else '')
            self.tree.insert(ptb_iid, tk.END, iid=str(idx),
                             text=e['fct_id'],
                             values=(res, start_str, dur_str, ''),
                             tags=(tag,) if tag else (), open=False)

            # Steps
            for step in e['steps']:
                s_tag = 'ok' if step['result'] == 'OK' else ('nok' if step['result'] else '')
                self.tree.insert(str(idx), tk.END,
                                 iid=f"s{idx}_{step['seqno']}",
                                 text=step['id'],
                                 values=(step['result'], '', '', step['value']),
                                 tags=(s_tag,) if s_tag else ())

        total  = len(self.log_entries)
        shown  = len(self.filtered_entries)
        hidden = total - shown
        self.status_var.set(
            f"{shown:,} von {total:,} Funktionen angezeigt"
            + (f"  –  {hidden:,} ausgeblendet" if hidden else "")
        )

    # ── Detailansicht ─────────────────────────────────────────────────────────
    def _on_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid[0].isdigit():             # fct-Knoten
            idx = int(iid)
            if idx < len(self.filtered_entries):
                self._show_fct_detail(self.filtered_entries[idx])
        elif iid.startswith('s'):        # step-Knoten
            parts = iid[1:].split('_', 1)
            fct_idx    = int(parts[0])
            step_seqno = int(parts[1])
            if fct_idx < len(self.filtered_entries):
                fct  = self.filtered_entries[fct_idx]
                step = next((s for s in fct['steps'] if s['seqno'] == step_seqno), None)
                if step:
                    self._show_step_detail(fct, step)

    def _show_fct_detail(self, e: dict):
        start_str = (f"{e['start_dt'].strftime('%y%m%d %H%M%S')}."
                     f"{e['start_dt'].microsecond // 1000:03d}") if e['start_dt'] else '—'
        stop_str  = (f"{e['stop_dt'].strftime('%y%m%d %H%M%S')}."
                     f"{e['stop_dt'].microsecond // 1000:03d}") if e['stop_dt'] else '—'
        ms = e['duration_ms']
        dur_str = f"{ms // 60000:02d}:{(ms % 60000) // 1000:02d}.{ms % 1000:03d}"
        lines = [
            f"Prüfumfang:   {e['vec_id']}",
            f"ECU:          {e['ecu_id']}",
            f"TestBlock:    {e['ptb_name']}",
            f"Funktion:     {e['fct_id']}",
            f"Ergebnis:     {e['fct_result']}",
            '',
            f"Start:        {start_str}",
            f"Ende:         {stop_str}",
            f"Dauer:        {dur_str}",
            '',
            f"Steps:        {len(e['steps'])}",
        ]
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

    def _show_step_detail(self, fct: dict, step: dict):
        lines = [
            f"Prüfumfang:   {fct['vec_id']}",
            f"ECU:          {fct['ecu_id']}",
            f"Funktion:     {fct['fct_id']}",
            '',
            f"Step ID:      {step['id']}",
            f"Seq-Nr:       {step['seqno']}",
            f"Stat-Nr:      {step['statno']}",
            f"Ergebnis:     {step['result']}",
            f"Wert:         {step['value']}",
        ]
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

    # ── Filter leeren ────────────────────────────────────────────────────────
    def _clear_filter(self):
        self.ecu_var.set('')
        self.fct_var.set('')
        self.result_filter_var.set('Alle')
        self.search_var.set('')
        self.ll_var.set('')
        self._apply_filter()

    # ── Vorgang ↔ Diag ───────────────────────────────────────────────────────
    def _refresh_vorgang_diag_view(self):
        """Baut die Vorgang-Liste im Tab 'Vorgang ↔ Diag' neu auf.
        Verwendet die fct-Zeitspannen (perfData.starttime + durationms) aus der Ergebnis-Datei.
        """
        self.vd_vg_tree.delete(*self.vd_vg_tree.get_children())
        self.vd_doip_tree.delete(*self.vd_doip_tree.get_children())
        self._vd_spans = []

        if not self.log_entries:
            return

        for e in self.log_entries:
            start_dt = e.get('start_dt')
            stop_dt  = e.get('stop_dt')
            if not start_dt or not stop_dt:
                continue

            cnt = sum(
                1 for de in self.doip_entries
                if de['datetime'] and start_dt <= de['datetime'] <= stop_dt
            )

            ms = e['duration_ms']
            dur_str = f"{ms // 60000:02d}:{(ms % 60000) // 1000:02d}.{ms % 1000:03d}"

            # iid: fct_key mit / → __ (Treeview mag keine Slashes)
            iid   = e['fct_key'].replace('/', '__')
            vg_nr = e['ecu_id']
            vg_id = f"{e['ptb_name']} / {e['fct_id']}"
            self._vd_spans.append((iid, vg_nr, vg_id, start_dt, stop_dt, cnt, dur_str))

        self._vd_spans.sort(key=lambda s: s[3])  # nach start_dt sortieren
        self._vd_fill_vg_tree()

    def _vd_fill_vg_tree(self):
        """Füllt die obere Tabelle unter Berücksichtigung des Identifier-Filters."""
        self.vd_vg_tree.delete(*self.vd_vg_tree.get_children())
        f = self.vd_filter_var.get().strip().lower()
        for iid, vg_nr, vg_id, start_dt, stop_dt, cnt, dur_str in self._vd_spans:
            if f and f not in vg_id.lower():
                continue
            tag = ('has_diag',) if cnt > 0 else ()
            self.vd_vg_tree.insert('', tk.END, iid=iid, values=(
                vg_nr,
                vg_id,
                f"{start_dt.strftime('%y%m%d %H%M%S')}.{start_dt.microsecond // 1000:03d}",
                f"{stop_dt.strftime('%y%m%d %H%M%S')}.{stop_dt.microsecond // 1000:03d}",
                dur_str,
                cnt,
            ), tags=tag)

    def _vd_filter_changed(self):
        self._vd_fill_vg_tree()

    def _on_vd_doip_select(self, _event=None):
        """Zeigt Details des gewählten DoIP-Eintrags (im Vorgang-Diag-Tab) im Detail-Panel."""
        sel = self.vd_doip_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        entries = getattr(self, '_vd_doip_entries', [])
        if idx >= len(entries):
            return
        e = entries[idx]

        direction = e['direction'].lower()
        src  = e['src_doip'] or '—'
        dst  = e['dst_doip'] or '—'
        svc  = e['uds_svc']  or '—'
        data = e['raw_data'] or '—'

        # Response-Time: bei RX rückwärts passenden TX suchen
        resp_time_str = '—'
        if direction == 'rx' and e['datetime'] and src != '—' and dst != '—':
            resp_dt = e['datetime']
            for de in reversed(entries[:idx]):
                if de['direction'].lower() != 'tx':
                    continue
                if not de['datetime'] or de['datetime'] > resp_dt:
                    continue
                if de['src_doip'] == dst and de['dst_doip'] == src:
                    delta    = resp_dt - de['datetime']
                    total_us = delta.seconds * 1_000_000 + delta.microseconds
                    resp_time_str = f"{total_us / 1000:.3f} ms  (Request: {de['timestamp']})"
                    break

        lines = [
            f"Zeitstempel:           {e['timestamp']}",
            f"Richtung:              {e['direction']}",
            f"",
            f"Sende-DoIP-Adresse:    {src}",
            f"Empfangs-DoIP-Adresse: {dst}",
            f"",
            f"UDS-Service:           {svc}",
            f"Rohdaten:              {data}",
            f"",
            f"Response-Time:         {resp_time_str}",
        ]
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

    def _on_vorgang_diag_select(self, _event=None):
        """Füllt die untere Tabelle mit den DoIP-Einträgen des gewählten Vorgangs
        und zeigt eine Zusammenfassung im Detail-Panel."""
        sel = self.vd_vg_tree.selection()
        if not sel:
            return
        iid  = sel[0]
        span = next((s for s in self._vd_spans if s[0] == iid), None)
        if not span:
            return
        _, vg_nr, vg_id, start_dt, stop_dt, cnt, dur = span

        # Detail-Panel: fct-Zusammenfassung aus Ergebnis-Datei
        fct_key = iid.replace('__', '/')
        res_e   = next((e for e in self.log_entries if e['fct_key'] == fct_key), None)
        res_str = res_e['fct_result'] if res_e else '—'
        lines = [
            f"ECU:          {vg_nr}",
            f"Funktion:     {vg_id}",
            f"Ergebnis:     {res_str}",
            f"",
            f"Start:        {start_dt.strftime('%y%m%d %H%M%S')}.{start_dt.microsecond // 1000:03d}",
            f"Ende:         {stop_dt.strftime('%y%m%d %H%M%S')}.{stop_dt.microsecond // 1000:03d}",
            f"Dauer:        {dur}",
            f"",
            f"DoIP-Befehle: {cnt}",
        ]
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete('1.0', tk.END)
        self.detail_text.insert(tk.END, '\n'.join(lines))
        self.detail_text.config(state=tk.DISABLED)

        # Untere Tabelle befüllen
        self._vd_doip_entries = []   # parallel-Liste für IID-Zugriff
        self.vd_doip_tree.delete(*self.vd_doip_tree.get_children())
        for de in self.doip_entries:
            if not de['datetime']:
                continue
            if not (start_dt <= de['datetime'] <= stop_dt):
                continue
            direction = de['direction'].lower()
            if de['uds_svc'] == 'NegResponse':
                tag = 'neg'
            elif direction == 'tx':
                tag = 'tx'
            elif direction == 'rx':
                tag = 'rx'
            else:
                tag = ''
            entry_idx = len(self._vd_doip_entries)
            self._vd_doip_entries.append(de)
            self.vd_doip_tree.insert('', tk.END, iid=str(entry_idx), values=(
                de['timestamp'],
                de['direction'],
                de['src_doip'],
                de['dst_doip'],
                de['uds_svc'],
                de['raw_data'],
            ), tags=(tag,) if tag else ())


# ─── Einstiegspunkt ─────────────────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = LogAnalyzerApp(root)

    if os.path.isfile(DEFAULT_LOG):
        app.file_var.set(DEFAULT_LOG)
        app._load_file()

    root.mainloop()


if __name__ == '__main__':
    main()
