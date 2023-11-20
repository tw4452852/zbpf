# zbpf
Writing eBPF in Zig. Thanks to Zig's comptime and BTF, we can equip eBPF with strong type system both at comptime and runtime!

## Notable advantages when writing eBPF program with `zbpf`

### Different available methods based on the type of program's context

Suppose you want to trace the kernel function [path_listxattr](https://github.com/torvalds/linux/blob/7475e51b87969e01a6812eac713a1c8310372e8a/fs/xattr.c#L856-L857),
and here's its prototype:

```
static ssize_t path_listxattr(const char __user *pathname, char __user *list,
			      size_t size, unsigned int lookup_flags)
```
As you can see, it has 4 input parameters and return type is `ssize_t`.
With `ctx = bpf.Kprobe{.name = "path_listxattr"}.Ctx()`, you could retrieve
the input parameter with `ctx.arg0()`, `ctx.arg1()`, `ctx.arg2()` and `ctx.arg3()` respectively,
and return value with `ctx.ret()`.
the type will be consistent with the above prototype. If you try to access a non-existing
parameter, e.g. `ctx.arg4()`, you will get a compilation error.

This also applies to `syscall` with `bpf.Ksyscall`, `tracepoint` with `bpf.Tracepoint` and
`fentry` with `bpf.Fentry`.

### No more tedious error handling

When writing in C, you always have to check the error conditions
(the return value of the helper function, pointer validation, ...)
With `zbpf`, you won't care about the these cases, we handle it under the hood for you,
just focus on the business logic.

The following are some examples:

- `bpf.Map` takes care BPF map's `update` and `delete` error.
- `bpf.PerfEventArray` handles event output failure.
- `bpf.RingBuffer` also handles space reservation.
- `bpf.Xdp` validates the pointer for you.

If some error happens, you could get all the information (file, line number, return value ...)
you need to debug in the kernel trace buffer:

```
~> sudo bpftool prog tracelog
test-11717   [005] d..21 10990692.273976: bpf_trace_printk: error occur at src/bpf/map.zig:110 return -2
```

## How to use

## Prerequisite

- Make sure the linux kernel is built with `CONFIG_DEBUG_INFO_BTF=y`.
- The only runtime library is `libc` (this is not even necessary if you build with musl-libc).

## Build

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
exit | [source](samples/exit.zig) | [source](src/tests/exit.zig)
panic | [source](samples/panic.zig) | [source](src/tests/panic.zig)
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
