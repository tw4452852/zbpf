# zbpf
Writing eBPF in Zig. Thanks to Zig's comptime and BTF, we can equip eBPF with strong type system both at comptime and runtime!

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

## Tools/trace

`trace` is a tool built on top of `zbpf` framework to trace kernel functions and syscalls.
It's heavily inspired by [retsnoop](https://github.com/anakryiko/retsnoop).
One improvement I made (which is also what I feel when using retsnoop) is that `trace` support
show parameters according its type (thanks to the Zig type system).
This is very helpful when debugging linux kernel.
For more details, you could check the implementation: [BPF side](https://github.com/tw4452852/zbpf/blob/main/src/trace.bpf.zig)
and [Host side](https://github.com/tw4452852/zbpf/blob/main/src/trace.zig).

You could specify the kernel functions you want to trace with: `zbpf build trace -Dkprobe=<kernel_function_name> -Dkprobe=...`
And for system calls: `zbpf build trace -Dsyscall=<syscall_name> -Dsyscall=...`.
You could even mix them.

And here's a quick demo:

[![asciicast](https://asciinema.org/a/620205.svg)](https://asciinema.org/a/620205)

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
xdp ping | [source](samples/xdp_ping.zig) | [source](src/tests/xdp_ping.zig)

**Have fun!**
