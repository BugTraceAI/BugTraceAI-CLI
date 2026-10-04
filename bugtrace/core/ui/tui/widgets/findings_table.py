"""Searchable findings, stable identities and severity ordering."""
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from rich.text import Text
from textual.widgets import DataTable


@dataclass
class Finding:
    id: str
    severity: str
    finding_type: str
    param: str | None
    payload: str | None
    request: str | None
    response_excerpt: str | None
    time: str
    status: str = "new"
    details: str = ""
    url: str = ""


class FindingsTable(DataTable):
    RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    COLORS = {"CRITICAL": "bold #FF3131", "HIGH": "#FF3131", "MEDIUM": "#FFC107", "LOW": "#2ECC71", "INFO": "#8A7FA8"}

    def __init__(self, **kwargs):
        super().__init__(cursor_type="row", zebra_stripes=True, **kwargs)
        self._findings = {}
        self._filter = ""
        self._severity = "all"
        self._sort_key = "severity"
        self._sort_reverse = False

    @property
    def findings(self):
        return list(self._findings.values())

    def on_mount(self):
        for label, key in (("Severity", "severity"), ("Type", "finding_type"), ("URL", "url"),
                           ("Parameter", "param"), ("Time", "time")):
            self.add_column(label, key=key)

    def add_finding(self, finding_type, details, severity, param=None, payload=None, request=None, response_excerpt=None, url=None):
        finding = Finding(uuid4().hex, (severity or "info").upper(), str(finding_type or "Finding"),
                          param, payload, request, response_excerpt, datetime.now().strftime("%H:%M:%S"),
                          details=str(details or ""), url=str(url or ""))
        self._findings[finding.id] = finding
        if self._matches(finding):
            self._add_row(finding)
            self._sort()
        return finding

    def _add_row(self, finding):
        self.add_row(Text(finding.severity, style=self.COLORS.get(finding.severity, "white")),
                     Text(finding.finding_type), Text(finding.url or "—"), Text(finding.param or "—"), finding.time, key=finding.id)

    def _matches(self, finding):
        text = " ".join(str(value or "") for value in
                        (finding.finding_type, finding.url, finding.param, finding.details, finding.payload)).lower()
        return self._filter in text and (self._severity == "all" or finding.severity.lower() == self._severity)

    def filter_findings(self, text="", severity="all"):
        self._filter, self._severity = text.lower(), severity.lower()
        selected = self.ordered_rows[self.cursor_row].key.value if self.row_count and self.cursor_row < self.row_count else None
        self.clear()
        for finding in self.findings:
            if self._matches(finding):
                self._add_row(finding)
        self._sort()
        if selected and selected in self.rows:
            self.move_cursor(row=self.get_row_index(selected))

    def _sort(self):
        if self.row_count:
            key = self._sort_key
            transform = (lambda value: self.RANK.get(str(value), 5)) if key == "severity" else str
            self.sort(key, key=transform, reverse=self._sort_reverse)

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected):
        if event.column_key.value == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key, self._sort_reverse = event.column_key.value, False
        self._sort()

    def get_finding(self, row_key):
        return self._findings.get(str(row_key))

    def reset_findings(self):
        self._findings.clear()
        self._filter, self._severity = "", "all"
        self.clear()
