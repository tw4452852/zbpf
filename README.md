# zbpf
Write bpf in Zig.

## Prerequisite

- Make sure `CONFIG_DEBUG_INFO_BTF=y`.
- The only runtime libraries (beyond `libc`) is `libelf` and `zlib`,
you'll also need development versions of them (for API headers) to compile.

## How to use

- Download the [lastest Zig](https://ziglang.org/download/).
- Clone this repostory.
- Build with `zig build -Dbpf=/path/to/your/bpf/prog.zig -Dmain=/path/to/your/main.zig`

That's all! The generated binary is located at `./zig-out/bin/zbpf`.

## Samples

For each supported feature, we have the corresponding unit test.
You could find them under `samples/` (BPF side) and `src/tests` (Host side).
You could build it with `zig build test -Dtest=<name>` and run it with `sudo zig-out/bin/test`.

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

**Have fun!**