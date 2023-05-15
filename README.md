# zbpf
Write bpf in Zig

## How to use

- Download the [lastest Zig](https://ziglang.org/download/).
- Clone this repostory.
- Build with `zig build -Dbpf=/path/to/your/bpf/prog.zig -Dmain=/path/to/your/main.zig`

That's all! The generated binary is located at `./zig-out/bin/zbpf`.

## Samples

For each supported feature, we have the corresponding unit test to cover it.
You could find them under `samples/` (BPF side) and `src/tests` (host side).
For example, for array map feature, they are `samples/array.zig` and `src/tests/array.zig`.
You could build it with `zig build test -Dtest=xxx` and run it with `sudo zig-out/bin/test`.

Have fun!

## Support

### Map type

- [x] Array
- [x] Hashmap
- [x] Perf event array
- [x] Ring buffer

### Program type

- [x] tracepoint
- [x] fentry/fexit
- [x] xdp
- [x] iterator
