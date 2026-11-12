#!/usr/bin/env python3
"""在 ELF 内核模块中查找候选 KVM MMU 补丁偏移。"""

import struct
import sys


def find_pattern(data, pattern, start=0):
    """返回字节模式第一次出现的位置。"""
    for index in range(start, len(data) - len(pattern)):
        if data[index:index + len(pattern)] == pattern:
            return index
    return -1


def hexdump(data, offset=0, length=400):
    """以紧凑的十六进制和 ASCII 形式输出数据。"""
    for index in range(0, min(length, len(data) - offset), 16):
        address = offset + index
        chunk = data[address:address + 16]
        hex_string = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_string = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        print(f"  {address:08x}: {hex_string:<48} {ascii_string}")


def find_function_offset(data, function_name):
    """在 ELF 符号表中查找函数。"""
    if data.find(function_name.encode() + b"\x00") < 0:
        return None
    if data[:4] != b"\x7fELF":
        print("警告：这不是标准 ELF 文件。")
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
    """输出目标函数附近的候选比较指令和跳转指令。"""
    print("=" * 60)
    print("KVM MMU 补丁偏移分析工具")
    print(f"目标函数：{function_name}")
    print("=" * 60)

    function_offset = find_function_offset(data, function_name)
    if function_offset is None:
        print(f"找不到 {function_name}。")
        print("请确认模块保留符号表，并且已经解压。")
        return

    print(f"函数偏移：0x{function_offset:x}")
    hexdump(data, function_offset, 400)
    patterns = [
        (b"\x49\x39\x47\x28", "cmp %rax, 0x28(%r15)"),
        (b"\x4d\x39\x57\x28", "cmp %r10, 0x28(%r15)"),
        (b"\x4c\x39\x47\x28", "cmp %r8, 0x28(%r15)"),
        (b"\x48\x39\x43\x28", "cmp %rax, 0x28(%rbx)"),
    ]

    print("候选比较指令：")
    for pattern, description in patterns:
        position = find_pattern(data, pattern, function_offset)
        if position < 0 or position >= function_offset + 400:
            continue
        jump = data[position + 4:position + 10]
        print(f"  偏移 0x{position - function_offset:x}：{description}")
        print(f"  后续字节：{' '.join(f'{byte:02x}' for byte in jump)}")
        if jump[0] == 0x0F and jump[1] in (0x84, 0x85):
            relative = struct.unpack_from("<i", jump, 2)[0]
            target = position + 6 + relative
            kind = "je" if jump[1] == 0x84 else "jne"
            print(f"  {kind} 目标偏移：0x{target - function_offset:x}")
            if jump[1] == 0x84:
                print(f"  候选补丁偏移：0x{position - function_offset + 4:x}")
        print()


def main():
    """解析命令行参数并分析指定模块。"""
    if len(sys.argv) != 2:
        print("用法：python offset_analyzer.py ./kvm.ko")
        sys.exit(1)
    try:
        with open(sys.argv[1], "rb") as module_file:
            data = module_file.read()
    except OSError as error:
        print(f"无法读取模块：{error}")
        sys.exit(1)
    print(f"文件：{sys.argv[1]}")
    print(f"大小：{len(data)} 字节")
    analyze_kvm(data)


if __name__ == "__main__":
    main()
