import json
import re

INPUT_JSON = "file_sigs.json"
OUTPUT_YARA = "file_sigs.yar"

existing_rule_names = set()


def sanitize_rule_name(name):
    if not name or name.lower() in ["null", "(null)"]:
        name = "Unknown"
    name = name.strip()
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name)
    if name[0].isdigit():
        name = "_" + name

    # Ensure uniqueness
    original_name = name
    counter = 1
    while name in existing_rule_names:
        name = f"{original_name}_{counter}"
        counter += 1

    existing_rule_names.add(name)
    return name


def is_valid_hex(s):
    """
    True if s is a valid hex string (ignores spaces), False otherwise
    """
    if not s or s.lower() in ["null", "(null)", "n/a"]:
        return False
    s = s.replace(" ", "")
    return all(c in "0123456789abcdefABCDEF" for c in s)


def normalize_hex(hex_string):
    """
    Convert any header/trailer hex string into valid YARA hex
    Handles:
    - Uneven digits (pads with 0)
    - Multi-byte tokens (FFD8 -> FF D8)
    - Skips invalid entries like (null)
    """
    if not is_valid_hex(hex_string):
        return None

    hex_string = hex_string.strip()
    # Split by spaces
    tokens = hex_string.split()
    normalized = []

    for t in tokens:
        t = t.strip()
        if len(t) == 0:
            continue
        # Multi-byte token like FFD8
        if len(t) > 2:
            if len(t) % 2 != 0:
                t = "0" + t
            bytes_split = [t[i:i+2] for i in range(0, len(t), 2)]
            normalized.extend(bytes_split)
            continue
        # Single digit padding
        if len(t) == 1:
            t = "0" + t
        normalized.append(t.upper())

    if not normalized:
        return None

    return "{ " + " ".join(normalized) + " }"


def generate_yara_rule(entry):
    description = entry.get("File description", "Unknown")
    header = entry.get("Header (hex)")
    trailer = entry.get("Trailer (hex)")
    offset = entry.get("Header offset", "0")
    extensions = entry.get("File extension")
    file_class = entry.get("FileClass")

    rule_name = sanitize_rule_name(description)

    yara = []
    yara.append(f"rule {rule_name}")
    yara.append("{")
    yara.append("    meta:")
    yara.append(f'        description = "{description}"')
    if file_class and file_class.lower() not in ["null", "(null)"]:
        yara.append(f'        file_class = "{file_class}"')
    if extensions and extensions.lower() not in ["null", "(null)"]:
        yara.append(f'        extensions = "{extensions}"')

    yara.append("")
    yara.append("    strings:")

    header_hex = normalize_hex(header)
    trailer_hex = normalize_hex(trailer)

    if header_hex:
        yara.append(f"        $header = {header_hex}")
    if trailer_hex:
        yara.append(f"        $trailer = {trailer_hex}")

    yara.append("")
    yara.append("    condition:")

    condition_parts = []
    if header_hex:
        condition_parts.append(f"$header at {offset}")
    if trailer_hex:
        condition_parts.append("$trailer")
    if not condition_parts:
        condition_parts.append("true")  # fallback

    yara.append("        " + " and ".join(condition_parts))
    yara.append("}")
    yara.append("")

    return "\n".join(yara)


def main():
    with open(INPUT_JSON, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules = []
    for sig in data.get("filesigs", []):
        rules.append(generate_yara_rule(sig))

    with open(OUTPUT_YARA, "w", encoding="utf-8") as f:
        f.write("// Generated from Gary Kessler File Signature Table\n\n")
        f.write("\n".join(rules))

    print(f"[+] Generated {len(rules)} YARA rules -> {OUTPUT_YARA}")


if __name__ == "__main__":
    main()
