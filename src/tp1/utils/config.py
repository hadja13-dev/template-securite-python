PORT_SCAN_THRESHOLD: int = 15

SQLI_PATTERNS: list[str] = [
    r"'\s*or\s+'?\d+'?\s*=\s*'?\d+",  # ' OR 1=1 / ' or '1'='1
    r"union\s+(all\s+)?select",
    r"'\s*;\s*drop\s+table",
    r"sleep\s*\(\s*\d+\s*\)",
    r"'\s*--",
]

FLAG_PATTERN: str = r"ESGI\{[^}]+\}"
HTTP_PORTS: set[int] = {80, 8080}
