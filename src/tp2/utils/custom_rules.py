"""Règles YARA personnelles, embarquées dans le code (.yar refusé au dépôt)."""

CUSTOM_RULES = """
import "math"

rule Prompt_Injection_Text
{
    meta:
        description = "Texte destiné à manipuler un LLM ou un analyste"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "NOTE_TO_AI" nocase
        $c = "AI_INSTRUCTIONS" nocase
        $d = "disregard all" nocase
        $e = "mark the sample clean" nocase
    condition:
        any of them
}

rule Windows_API_In_ELF
{
    meta:
        description = "Binaire ELF contenant des noms d'API Windows (incohérent)"
    strings:
        $api1 = "URLDownloadToFile"
        $api2 = "WinExec"
        $api3 = "CreateProcessA"
        $api4 = "WSASocketA"
        $api5 = "SetWindowsHookEx"
        $api6 = "GetAsyncKeyState"
        $api7 = "VirtualAllocEx"
    condition:
        uint32(0) == 0x464C457F and any of ($api*)
}

rule High_Entropy_Tail
{
    meta:
        description = "Fin de fichier quasi aléatoire : données packées/chiffrées"
    condition:
        filesize > 65536 and math.entropy(filesize - 32768, 32768) >= 7.5
}
"""
