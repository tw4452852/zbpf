#!/bin/bash

zig build trace -Dsyscall=unlinkat -Dkprobe=do_unlinkat -Dkprobe=do_rmdir
sudo ./zig-out/bin/trace --timeout 2 > ./trace_output.txt &
sleep 1
touch test.file
mkdir test.dir
rm -fr test.file test.dir
sleep 1

cat ./trace_output.txt
grep -q "kprobe do_unlinkat" ./trace_output.txt || exit 1
grep -q "kprobe do_rmdir" ./trace_output.txt || exit 1
grep -q "syscall unlinkat" ./trace_output.txt || exit 1

