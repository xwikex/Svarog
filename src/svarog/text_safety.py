"""Safe rendering of untrusted text in terminal output."""


def terminal_safe(value: object) -> str:
    """Escape terminal controls and invisible Unicode formatting characters."""

    text = str(value)
    safe: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character == "\n":
            safe.append("\\n")
        elif character == "\r":
            safe.append("\\r")
        elif character == "\t":
            safe.append("\\t")
        elif codepoint < 32 or 127 <= codepoint <= 159:
            safe.append(f"\\x{codepoint:02x}")
        elif not character.isprintable():
            if codepoint <= 0xFFFF:
                safe.append(f"\\u{codepoint:04x}")
            else:
                safe.append(f"\\U{codepoint:08x}")
        else:
            safe.append(character)
    return "".join(safe)
