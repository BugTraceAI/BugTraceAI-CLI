"""
DASTySAST constants and data definitions.

All values here are PURE data -- no side effects, no I/O.
"""
from typing import FrozenSet

# -------------------------------------------------------------------------
# Parameter hint sets for auto-candidate injection
# -------------------------------------------------------------------------

LFI_PARAM_HINTS: FrozenSet[str] = frozenset({
    "file", "path", "doc", "document", "include", "template", "page",
    "dir", "folder", "src", "download", "read", "content", "load",
    "view", "module", "resource", "filename", "filepath", "attachment",
    "img", "image", "loc", "location",
})  # PURE

FILE_EXTENSIONS: FrozenSet[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".php", ".html", ".txt",
    ".xml", ".json", ".css", ".js", ".svg", ".ico", ".csv", ".log",
    ".conf", ".ini", ".yml", ".yaml", ".md", ".bak",
})  # PURE

REDIRECT_PARAM_HINTS: FrozenSet[str] = frozenset({
    "redirect", "next", "return", "returnurl", "goto", "dest",
    "destination", "redir", "returnpath", "ref", "back", "backurl",
    "continue", "forward", "out", "target", "to",
})  # PURE

RCE_PARAM_HINTS: FrozenSet[str] = frozenset({
    "cmd", "command", "exec", "execute", "run", "ping", "query",
    "ip", "host", "hostname", "shell", "process", "action",
})  # PURE

SSRF_PARAM_HINTS: FrozenSet[str] = frozenset({
    "url", "uri", "src", "source", "link", "fetch", "request",
    "proxy", "callback", "webhook", "api", "endpoint", "server",
    "import", "load", "image_url", "icon_url", "avatar_url",
})  # PURE

# -------------------------------------------------------------------------
# Per-approach model mapping
# -------------------------------------------------------------------------

APPROACH_MODEL_MAP: dict = {
    "pentester": "ANALYSIS_PENTESTER_MODEL",
    "bug_bounty": "ANALYSIS_BUG_BOUNTY_MODEL",
    "code_auditor": "ANALYSIS_AUDITOR_MODEL",
    "red_team": "ANALYSIS_RED_TEAM_MODEL",
    "researcher": "ANALYSIS_RESEARCHER_MODEL",
}  # PURE

# -------------------------------------------------------------------------
# SQL error patterns for major databases
# -------------------------------------------------------------------------

SQL_ERRORS: list = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch", "mysql_num_rows", "mysql_query",
    "warning: mysql",
    # PostgreSQL
    "postgresql.*error", "pg_query", "pg_exec",
    "unterminated quoted string",
    # MSSQL
    "microsoft sql server", "mssql_query",
    "unclosed quotation mark",
    # Oracle
    "ora-00933", "ora-00921", "ora-01756",
    "oracle.*driver", "oracle.*error",
    # SQLite
    "sqlite3.operationalerror", "sqlite_error",
    "unrecognized token",
    # Generic
    "sql syntax.*mysql", "valid sql statement",
    "sqlstate", "odbc.*driver",
]  # PURE

# -------------------------------------------------------------------------
# Deserialization detection patterns
# -------------------------------------------------------------------------

DESER_PATTERNS: list = [
    # Python pickle
    "invalid load key", "could not find MARK", "unpickling",
    "pickle.loads", "_pickle.UnpicklingError",
    "pickle data", "_pickle.",
    # Java
    "java.io.ObjectInputStream", "ClassNotFoundException",
    "java.io.InvalidClassException", "readObject",
    # PHP
    "unserialize()", "allowed_classes",
    # .NET
    "BinaryFormatter", "ObjectStateFormatter",
    # Ruby
    "Marshal.load",
]  # PURE

# -------------------------------------------------------------------------
# JavaScript URL parameter skip list (SPA parameter discovery)
# -------------------------------------------------------------------------

JS_PARAM_SKIP: FrozenSet[str] = frozenset({
    "v", "ver", "version", "cb", "ts", "timestamp", "t", "hash",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "nonce", "lang", "locale", "charset", "encoding",
})  # PURE
