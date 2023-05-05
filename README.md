# zbpf
Write bpf in Zig

## How to use

- Download the [lastest Zig](https://ziglang.org/download/).
- Clone this repostory.
- Build with `zig build -Dbpf=/path/to/your/bpf/prog.zig -Dmain=/path/to/your/main.zig`

That's all! The generated binary is located at `./zig-out/bin/zbpf`.

There are some bpf program samples under `samples` directory for reference,
and for userspace program, you could check tests under `src/tests`.

Have fun!



