#!/bin/bash
set -e

zig build trace -Dsyscall=unlinkat:arg1,ret -Dkprobe=do_unlinkat:arg0,arg1,arg1.name,ret -Dkprobe=do_rmdir:arg0,ret,stack
sudo ./zig-out/bin/trace --timeout 2 1>./trace_output.txt 2>&1 &
until grep -q Tracing ./trace_output.txt; do sleep .1; done
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
grep -q "arg1: test.file" ./trace_output.txt
grep -q "arg1: test.dir" ./trace_output.txt
rm -f ./trace_output.txt

