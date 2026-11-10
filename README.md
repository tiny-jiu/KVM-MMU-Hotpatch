# KVM MMU Hotpatch

A runtime hotpatch for the KVM shadow MMU issue tracked as CVE-2026-53359, together with a small ELF offset analysis helper.

This project changes kernel instructions in memory. Use it only on systems you own, and test it away from production first.

## The idea

The affected `kvm_mmu_get_page()` path can reuse a shadow page after comparing only the global frame number. Without checking the MMU role, a page with an incompatible role may be selected.

The upstream fix adds the missing role comparison. This hotpatch takes a different approach: it replaces the relevant conditional jump with a six-byte NOP, forcing the code down the path that allocates a new page instead of reusing the old one.

That avoids a host reboot, but it also means shadow pages are no longer reused in the affected path and memory use can increase.

## Runtime implementation

The module:

1. Resolves `kvm_mmu_get_page` and `text_poke` with `kallsyms_lookup_name`.
2. Saves the original six bytes.
3. Uses `stop_machine` while patching the instruction.
4. Restores the original bytes when the module is unloaded.

## Requirements

- Linux 4.18 or newer
- Kernel headers and build tools
- An x86 host with the relevant KVM module
- A kernel build matching the supplied patch offset

## Build and load

```bash
make
sudo insmod KVM-XJ.ko
dmesg | grep KVM-XJ
```

Unload the module to restore the original instruction:

```bash
sudo rmmod KVM_XJ
```

## Analyze another kernel

Compiler options and kernel builds can move the instruction. Do not assume that the default offset fits every kernel.

```bash
python offset_analyzer.py /path/to/kvm.ko
```

The helper reads ELF symbols, locates `kvm_mmu_get_page`, and prints candidate comparison and jump instructions. Update the C module only after verifying the disassembly for your exact kernel.

## Tested offsets

| Kernel | Jump offset | Status |
| --- | --- | --- |
| 4.18.0-496.el8.x86_64 | `0x108` | Tested |
| 4.18.0-358.el8.x86_64 | `0xe8` | Tested |

A wrong offset can crash the host. Verify it before loading the module.
