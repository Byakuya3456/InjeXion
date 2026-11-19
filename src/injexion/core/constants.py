"""
Constants, security standards mappings, and default signatures for InjeXion.
"""

from typing import Dict, List

VERSION = "2.0.0"
APP_NAME = "InjeXion"
TAGLINE = "Next-Gen Asynchronous Vulnerability Scanner & Payload Injector"

# Common ports for the async port scanner
COMMON_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# Standard CWE & CVSS mapping
VULN_METADATA = {
    "sqli_error": {
        "title": "SQL Injection (Error-Based)",
        "cwe_id": "CWE-89",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "The application handles untrusted user input directly in dynamic SQL statements, causing detailed database engine syntax error leakage.",
        "remediation": "Use parameterized queries (prepared statements) or ORM abstraction. Never concatenate user input directly into SQL strings."
    },
    "sqli_boolean": {
        "title": "SQL Injection (Boolean-Blind)",
        "cwe_id": "CWE-89",
        "cvss_score": 8.6,
        "severity": "HIGH",
        "description": "The application returns noticeably different response content or structure when injecting boolean SQL conditions (AND 1=1 vs AND 1=2).",
        "remediation": "Use parameterized queries / prepared statements for all database interactions."
    },
    "sqli_time": {
        "title": "SQL Injection (Time-Based Blind)",
        "cwe_id": "CWE-89",
        "cvss_score": 8.2,
        "severity": "HIGH",
        "description": "The application executes arbitrary database sleep/delay functions injected into parameter values.",
        "remediation": "Use parameterized queries / prepared statements."
    },
    "xss_reflected": {
        "title": "Cross-Site Scripting (Reflected)",
        "cwe_id": "CWE-79",
        "cvss_score": 7.2,
        "severity": "HIGH",
        "description": "The application reflects untrusted input directly into HTML without context-aware sanitization or encoding, allowing arbitrary script execution.",
        "remediation": "Apply context-appropriate HTML entity encoding (e.g. htmlspecialchars) and enforce a strict Content-Security-Policy (CSP)."
    },
    "lfi": {
        "title": "Local File Inclusion / Path Traversal",
        "cwe_id": "CWE-22",
        "cvss_score": 8.6,
        "severity": "HIGH",
        "description": "The application consumes file path parameters without resolving canonical paths, allowing unauthorized reading of system files.",
        "remediation": "Use hardcoded path whitelists and resolve canonical paths using realpath(), ensuring resolved files remain strictly inside intended root directories."
    },
    "missing_hsts": {
        "title": "Missing Strict-Transport-Security (HSTS)",
        "cwe_id": "CWE-319",
        "cvss_score": 4.3,
        "severity": "LOW",
        "description": "The application does not enforce HTTPS via the Strict-Transport-Security header, leaving users vulnerable to SSL stripping attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses."
    },
    "missing_csp": {
        "title": "Missing Content-Security-Policy (CSP)",
        "cwe_id": "CWE-1021",
        "cvss_score": 5.4,
        "severity": "MEDIUM",
        "description": "The application lacks a Content-Security-Policy header, weakening defense against Cross-Site Scripting and data exfiltration.",
        "remediation": "Define and deploy a Content-Security-Policy restricting script sources, object embeddings, and frame ancestors."
    },
    "missing_xframe": {
        "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
        "cwe_id": "CWE-1021",
        "cvss_score": 4.3,
        "severity": "LOW",
        "description": "The application does not set X-Frame-Options or frame-ancestors, allowing malicious sites to iframe the application for clickjacking.",
        "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors'."
    },
    "missing_xcontent": {
        "title": "Missing X-Content-Type-Options Header",
        "cwe_id": "CWE-16",
        "cvss_score": 3.7,
        "severity": "LOW",
        "description": "Missing X-Content-Type-Options: nosniff allows browsers to MIME-sniff response content away from declared Content-Type.",
        "remediation": "Set 'X-Content-Type-Options: nosniff' header across all responses."
    },
    "sensitive_directory": {
        "title": "Sensitive Directory / File Exposed",
        "cwe_id": "CWE-548",
        "cvss_score": 5.3,
        "severity": "MEDIUM",
        "description": "The application publicly exposes sensitive files, administrative interfaces, backups, or configuration directories.",
        "remediation": "Restrict access to administrative endpoints and remove backup/config files from web-accessible document roots."
    }
}

# Multi-DBMS Error Signatures for SQL Injection detection
DBMS_ERROR_PATTERNS = {
    "MySQL": [
        r"you have an error in your sql syntax;",
        r"warning: mysql_",
        r"mysql_fetch_array\(\)",
        r"valid mysql result",
        r"check the manual that corresponds to your (mysql|mariadb) server version",
        r"myodbc",
        r"unknown column '[^']+' in 'where clause'",
    ],
    "PostgreSQL": [
        r"postgresql.*error",
        r"warning:\s+pg_",
        r"pg_exec\(\)",
        r"valid postgresql result",
        r"npgsql\.",
        r"psycopg2\.",
        r"syntax error at or near",
        r"unterminated quoted string at or near",
    ],
    "MSSQL": [
        r"driver.*sql[\-\_\ ]*server",
        r"ole db.*sql server",
        r"\b(sqlserverexception|sqlservererror)\b",
        r"unclosed quotation mark after the character string",
        r"microsoft ole db provider for sql server",
        r"syntax error in string in query expression",
    ],
    "Oracle": [
        r"\bora-[0-9]{4,5}\b",
        r"oracle error",
        r"oracle.*driver",
        r"warning: oci_",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"sqlite_error",
        r"sqlite3::",
        r"unrecognized token:",
        r"near \"[^\"]+\": syntax error",
        r"sqlite error",
        r"operationalerror: near",
    ]
}

# Anchored LFI detection patterns
LFI_PATTERNS = {
    "linux": [
        r"root:.*:0:0:",
        r"daemon:.*:1:1:",
        r"bin:.*:2:2:",
        r"nobody:.*:",
        r"Linux version \d+\.\d+",
    ],
    "windows": [
        r"\[(fonts|extensions|mci extensions|files|boot loader)\]",
        r"; for 16-bit app support",
        r"\[operating systems\]",
    ]
}
