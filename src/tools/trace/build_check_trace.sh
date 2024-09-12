#!/bin/bash
set -e

zig build trace -Dsyscall=unlinkat -Dkprobe=do_unlinkat -Dkprobe=do_rmdir
sudo ./zig-out/bin/trace --timeout 2 > ./trace_output.txt &
sleep 1
touch test.file
mkdir test.dir
rm -fr test.file test.dir
sleep 1

cat ./trace_output.txt
grep -q "kprobe do_unlinkat enter" ./trace_output.txt
grep -q "kprobe do_unlinkat exit" ./trace_output.txt
grep -q "kprobe do_rmdir enter" ./trace_output.txt
grep -q "kprobe do_rmdir exit" ./trace_output.txt
grep -q "syscall unlinkat enter" ./trace_output.txt
grep -q "syscall unlinkat exit" ./trace_output.txt
rm -f ./trace_output.txt

