"""Unit tests for detection signature matching."""

from injexion.detectors.lfi import LFIDetector
from injexion.detectors.sqli import SQLiDetector


def test_sqli_detector_pattern_matching():
    detector = SQLiDetector()

    # MySQL match
    assert detector._match_dbms_error("Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result") == "MySQL"
    assert detector._match_dbms_error("You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version") == "MySQL"

    # PostgreSQL match
    assert detector._match_dbms_error("ERROR: syntax error at or near \"admin\"") == "PostgreSQL"
    assert detector._match_dbms_error("PostgreSQL query failed: unterminated quoted string at or near") == "PostgreSQL"

    # MSSQL match
    assert detector._match_dbms_error("Microsoft OLE DB Provider for SQL Server error '80040e14'") == "MSSQL"
    assert detector._match_dbms_error("Unclosed quotation mark after the character string '''.") == "MSSQL"

    # SQLite match
    assert detector._match_dbms_error("SQLite3::SQLException: unrecognized token: \"'\"") == "SQLite"

    # Oracle match
    assert detector._match_dbms_error("ORA-00933: SQL command not properly ended") == "Oracle"

    # Clean text should not match
    assert detector._match_dbms_error("Welcome to our homepage! Everything works smoothly.") is None
    # Generic word 'error' alone should not trigger false positives
    assert detector._match_dbms_error("An error occurred while loading your profile picture.") is None


def test_lfi_detector_regex_matching():
    detector = LFIDetector()

    # Linux /etc/passwd match
    passwd_sample = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    assert detector._matches_lfi(passwd_sample) == "Linux (/etc/passwd)"

    # Windows win.ini match
    win_ini_sample = "; for 16-bit app support\n[fonts]\n[extensions]\n"
    assert detector._matches_lfi(win_ini_sample) == "Windows (win.ini)"

    # Clean text
    clean_sample = "File not found on this server."
    assert detector._matches_lfi(clean_sample) is None

