import sys
import os
import re

# The function below is a small helper that handles windows-specifc encodings for text files (e.g. BOM-handling), originally made to handle parsing of .INF files.
def text_from_raw_win(raw):
    if raw[:3] == b'\xef\xbb\xbf':
        text = raw[3:].decode('utf-8')
    elif raw[:2] == b'\xff\xfe':
        text = raw[2:].decode('utf-16-le')
    elif raw[:2] == b'\xfe\xff':
        text = raw[2:].decode('utf-16-be')
    elif b'\x00' in raw[:200]:
        text = raw.decode('utf-16-le', errors='replace')
    else:
        text = raw.decode('utf-8', errors='replace')
    return text

def extract_hardware_ids(inf_path):
    """Extract hardware IDs from a Windows INF file.

    Args:
        inf_path: Path to the .inf file.

    Returns:
        Sorted list of unique hardware IDs found in the file.
    """
#Pattern: Hardware IDs are always in the Models sections, which are referenced from the [Manufacturer] section. Each manufacturer line has the format description=SectionBase[, decoration1, ...], and the actual model sections are named
#SectionBase.decoration (e.g., Kvaser.ntamd64). Within each model section, lines have the format description=install-section, HW-ID [, compatible-ID ...].

#Bus types observed across these files:
#- USB\VID_xxxx&PID_xxxx
#- PCI\VEN_xxxx&DEV_xxxx
#- ACPI\xxxx
#- HDAUDIO\FUNC_xx&VEN_xxxx&DEV_xxxx
#- PCMCIA\...
#- root\...
#- Custom buses (BIXOLON\..., VCOMSERVER\...)
    # Read raw bytes and detect encoding
    with open(inf_path, 'rb') as f:
        raw = f.read()
        text = text_from_raw_win(raw)

    # Parse into {section_name_lower: [lines]}
    sections = {}
    current_section = None
    current_lines = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        # Strip comment: first ';' not inside double quotes
        in_quote = False
        for i, ch in enumerate(line):
            if ch == '"':
                in_quote = not in_quote
            elif ch == ';' and not in_quote:
                line = line[:i].strip()
                break

        if not line:
            continue

        # Section header
        m = re.match(r'^\[(.+)\]$', line)
        if m:
            if current_section is not None:
                sections[current_section] = current_lines
            current_section = m.group(1).strip().lower()
            current_lines = []
        elif current_section is not None:
            current_lines.append(line)

    if current_section is not None:
        sections[current_section] = current_lines

    # Find [Manufacturer] section
    mfg_lines = sections.get('manufacturer', [])
    if not mfg_lines:
        return []

    # Collect model section names from manufacturer entries.
    # Format: %desc%=SectionBase[, NT-decoration1[, NT-decoration2 ...]]
    # Actual model sections are SectionBase.decoration or just SectionBase.
    model_sections = []
    for line in mfg_lines:
        if '=' not in line:
            continue
        right = line.split('=', 1)[1]
        parts = [p.strip() for p in right.split(',')]
        base = parts[0]
        decorations = [p for p in parts[1:] if p.strip()]

        for dec in decorations:
            model_sections.append(f"{base}.{dec.strip()}")
        model_sections.append(base)  # undecorated fallback

    # Extract hardware IDs from each model section
    hw_ids = set()

    for sec_name in model_sections:
        sec_lines = sections.get(sec_name.lower(), [])
        for line in sec_lines:
            if '=' not in line:
                continue
            right = line.split('=', 1)[1]
            parts = [p.strip() for p in right.split(',')]
            # parts[0] = install-section-name
            # parts[1:] = hardware-id [, compatible-id ...]
            for hw_id in parts[1:]:
                if hw_id:
                    hw_ids.add(hw_id)

    return sorted(hw_ids, key=str.lower)

if __name__ == "__main__":
    if len(sys.argv) != 2 or os.path.lexists(sys.argv[1]) == False:
        print("Usage: extract_hwid_from_inf.py <PATH_TO_INF>")
        exit()
    print(extract_hardware_ids(sys.argv[1]))