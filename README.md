# zbpf
Writing eBPF in Zig.

## Prerequisite

- Make sure the linux kernel is built with `CONFIG_DEBUG_INFO_BTF=y`.
- The only runtime library is `libc` (this is not even necessary if you build with musl-libc).

## How to use

- Download the [lastest Zig](https://ziglang.org/download/).
- Clone this repostory.
- Build with `zig build -Dbpf=/path/to/your/bpf/prog.zig -Dmain=/path/to/your/main.zig`.

For cross-compiling, you could specify the target with `-Dtarget=<target>`,
the list of all supported targets could be retrieved by `zig targets`.

Moreover, you could specify the target kernel with `-Dvmlinux=/path/to/vmlinux`
to extract BTF from it, otherwise, current kernel's BTF will be used.

That's all! The generated binary is located at `./zig-out/bin/zbpf`,
feel free to run it on your target machine.

## Samples

For each supported feature, we have the corresponding unit test.
You could find them under `samples/` (BPF side) and `src/tests` (Host side).
Build it with `zig build test -Dtest=<name>` and run it with `sudo zig-out/bin/test`.

Name | BPF side | Host side
--- | --- | ---
trace_printk | [source](samples/trace_printk.zig) | [source](src/tests/trace_printk.zig)
array | [source](samples/array.zig) | [source](src/tests/array.zig)
hash | [source](samples/hash.zig) | [source](src/tests/hash.zig)
perf_event | [source](samples/perf_event.zig) | [source](src/tests/perf_event.zig)
ringbuf | [source](samples/ringbuf.zig) | [source](src/tests/ringbuf.zig)
tracepoint | [source](samples/tracepoint.zig) | [source](src/tests/tracepoint.zig)
iterator | [source](samples/iterator.zig) | [source](src/tests/iterator.zig)
fentry | [source](samples/fentry.zig) | [source](src/tests/fentry.zig)
kprobe | [source](samples/kprobe.zig) | [source](src/tests/kprobe.zig)
kmulprobe | [source](samples/kmulprobe.zig) | [source](src/tests/kmulprobe.zig)

**Have fun!**
