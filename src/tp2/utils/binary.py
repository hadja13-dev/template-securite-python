import logging
from pathlib import Path

import lief

logger = logging.getLogger(__name__)
lief.logging.disable()

# API Windows révélatrices, regroupées par capacité.
SUSPICIOUS_APIS: dict[str, set[str]] = {
    "download": {
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenA",
        "InternetOpenUrlA",
        "InternetReadFile",
        "HttpSendRequestA",
    },
    "execution": {
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
        "system",
    },
    "network": {
        "WSAStartup",
        "WSASocketA",
        "WSASocketW",
        "socket",
        "connect",
        "send",
        "recv",
        "bind",
        "listen",
    },
    "keylogging": {
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetKeyState",
        "GetKeyboardState",
    },
    "injection": {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
    },
    "persistence": {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA"},
    "anti_analysis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"},
}


def get_overlay(data: bytes) -> bytes:
    binary = lief.parse(data)
    if binary is None:
        logger.info("Format non reconnu par lief, analyse du fichier entier")
        return data
    overlay = bytes(binary.overlay)
    if not overlay:
        logger.info("Pas d'overlay, analyse du fichier entier")
        return data
    logger.info("Overlay de %d octets détecté", len(overlay))
    return overlay


def parse_binary(path: str | Path) -> dict:
    result: dict = {"format": "unknown", "imports": [], "exports": [], "sections": []}
    binary = lief.parse(str(path))
    if binary is None:
        logger.info("%s n'est pas un binaire reconnu par lief", path)
        return result

    result["format"] = str(binary.format).split(".")[-1]
    result["imports"] = sorted({f.name for f in binary.imported_functions if f.name})
    result["exports"] = sorted({f.name for f in binary.exported_functions if f.name})
    result["sections"] = [
        {"name": s.name, "size": s.size, "entropy": round(s.entropy, 2)} for s in binary.sections if s.name
    ]
    logger.info(
        "%s : %s, %d imports, %d sections",
        path,
        result["format"],
        len(result["imports"]),
        len(result["sections"]),
    )
    return result


def find_suspicious_apis(strings: list[str]) -> dict[str, list[str]]:
    found_strings = set(strings)
    capabilities: dict[str, list[str]] = {}
    for capability, apis in SUSPICIOUS_APIS.items():
        matches = sorted(apis & found_strings)
        if matches:
            capabilities[capability] = matches
    return capabilities
