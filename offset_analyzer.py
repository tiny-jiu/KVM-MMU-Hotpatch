#!/usr/bin/env python3
"""Locate candidate KVM MMU patch offsets in an ELF kernel module."""

import struct
import sys


def find_pattern(data, pattern, start=0):
    """Return the first offset at which a byte pattern occurs."""
    for index in range(start, len(data) - len(pattern)):
        if data[index:index + len(pattern)] == pattern:
            return index
    return -1


def hexdump(data, offset=0, length=400):
    """Print a compact hexadecimal and ASCII view of the data."""
    for index in range(0, min(length, len(data) - offset), 16):
        address = offset + index
        chunk = data[address:address + 16]
        hex_string = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_string = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        print(f"  {address:08x}: {hex_string:<48} {ascii_string}")


def find_function_offset(data, function_name):
    """Look up a function in the ELF symbol table."""
    if data.find(function_name.encode() + b"\x00") < 0:
        return None
    if data[:4] != b"\x7fELF":
        print("Warning: this is not a standard ELF file.")
        return None

    section_offset = struct.unpack_from("<Q", data, 0x28)[0]
    section_entry_size = struct.unpack_from("<H", data, 0x3A)[0]
    section_count = struct.unpack_from("<H", data, 0x3C)[0]
    section_name_index = struct.unpack_from("<H", data, 0x3E)[0]
    names_header = section_offset + section_name_index * section_entry_size
    names_offset = struct.unpack_from("<Q", data, names_header + 0x18)[0]

    for index in range(section_count):
        header = section_offset + index * section_entry_size
        name_index = struct.unpack_from("<I", data, header)[0]
        section_type = struct.unpack_from("<I", data, header + 4)[0]
        name = data[names_offset + name_index:].split(b"\x00")[0]
        if name != b".symtab" or section_type != 2:
            continue

        symbol_offset = struct.unpack_from("<Q", data, header + 0x18)[0]
        symbol_size = struct.unpack_from("<Q", data, header + 0x20)[0]
        symbol_entry_size = struct.unpack_from("<Q", data, header + 0x38)[0]
        string_offset = None

        for string_index in range(section_count):
            string_header = section_offset + string_index * section_entry_size
            string_name_index = struct.unpack_from("<I", data, string_header)[0]
            string_name = data[names_offset + string_name_index:].split(b"\x00")[0]
            if string_name == b".strtab":
                string_offset = struct.unpack_from("<Q", data, string_header + 0x18)[0]
                break

        if string_offset is None:
            continue

        for position in range(0, symbol_size, symbol_entry_size):
            entry = symbol_offset + position
            symbol_name_index = struct.unpack_from("<I", data, entry)[0]
            symbol_value = struct.unpack_from("<Q", data, entry + 8)[0]
            symbol_name = data[string_offset + symbol_name_index:].split(b"\x00")[0]
            if symbol_name == function_name.encode():
                return symbol_value
    return None


def analyze_kvm(data, function_name="kvm_mmu_get_page"):
    """Print candidate comparisons and jumps near the target function."""
    print("=" * 60)
    print("KVM MMU patch offset analyzer")
    print(f"Target function: {function_name}")
    print("=" * 60)

    function_offset = find_function_offset(data, function_name)
    if function_offset is None:
        print(f"Could not find {function_name}.")
        print("Make sure the module contains symbols and has been decompressed.")
        return

    print(f"Function offset: 0x{function_offset:x}")
    hexdump(data, function_offset, 400)
    patterns = [
        (b"\x49\x39\x47\x28", "cmp %rax, 0x28(%r15)"),
        (b"\x4d\x39\x57\x28", "cmp %r10, 0x28(%r15)"),
        (b"\x4c\x39\x47\x28", "cmp %r8, 0x28(%r15)"),
        (b"\x48\x39\x43\x28", "cmp %rax, 0x28(%rbx)"),
    ]

    print("Candidate comparison instructions:")
    for pattern, description in patterns:
        position = find_pattern(data, pattern, function_offset)
        if position < 0 or position >= function_offset + 400:
            continue
        jump = data[position + 4:position + 10]
        print(f"  Offset 0x{position - function_offset:x}: {description}")
        print(f"  Following bytes: {' '.join(f'{byte:02x}' for byte in jump)}")
        if jump[0] == 0x0F and jump[1] in (0x84, 0x85):
            relative = struct.unpack_from("<i", jump, 2)[0]
            target = position + 6 + relative
            kind = "je" if jump[1] == 0x84 else "jne"
            print(f"  {kind} target offset: 0x{target - function_offset:x}")
            if jump[1] == 0x84:
                print(f"  Candidate patch offset: 0x{position - function_offset + 4:x}")
        print()


def main():
    """Parse arguments and analyze the supplied module."""
    if len(sys.argv) != 2:
        print("Usage: python offset_analyzer.py /path/to/kvm.ko")
        sys.exit(1)
    try:
        with open(sys.argv[1], "rb") as module_file:
            data = module_file.read()
    except OSError as error:
        print(f"Unable to read the module: {error}")
        sys.exit(1)
    print(f"File: {sys.argv[1]}")
    print(f"Size: {len(data)} bytes")
    analyze_kvm(data)


if __name__ == "__main__":
    main()
