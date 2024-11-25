# Zig translate-btf

Traditionally, we generate Zig code as follow:

```
      libbpf dump               zig translate-c
BTF ------------------->  C -----------------------> Zig
```

But now with this:

```
         btf_translator
BTF  -----------------------> Zig
```

without intermedia C code.

The motivation for this change:

- Current `zig translate-c` implementation has some limitations, e.g. bitfields are not supported properly (ziglang/zig#1499).
- Clean up dependency on `zig translate-c` as Zig does want to move it to a dedicated package (ziglang/zig#20630)

## Usage

- `btf_translator`: Dump current kernel's BTF to stdout.
- You could select the BTF to dump with `-vmlinux/path/to/your/vmliux_image`.
- You could also dump to a file with `-o/path/to/output_file`.
- By default, syscalls will not be dumped unless `-syscalls` option is specified.