#!/bin/bash
set -e

zig build trace \
  -Dsyscall=unlinkat:arg1,ret \
  -Dkprobe=do_unlinkat:arg0,arg1,arg1.name,ret \
  -Dkprobe=do_rmdir:arg0,ret,stack \
  -Duprobe=/proc/self/exe[testing_call+0]:arg0,arg1,ret,stack

sudo ./zig-out/bin/trace --timeout 2 --testing >./trace_output.txt 2>&1 &
counter=0
until grep -q Tracing ./trace_output.txt; do
  sleep .1;
  if [ "$counter" == 100 ]; then
    echo "Timeout!"
    cat ./trace_output.txt
    exit 1
  fi
  counter=$((counter+1))
done
touch test.file
mkdir test.dir
rm -fr test.file test.dir
sleep 1

cat ./trace_output.txt >&2
grep -q "kprobe do_unlinkat enter" ./trace_output.txt
grep -q "kprobe do_unlinkat exit" ./trace_output.txt
grep -q "kprobe do_rmdir enter" ./trace_output.txt
grep -q "kprobe do_rmdir exit" ./trace_output.txt
grep -q "syscall unlinkat enter" ./trace_output.txt
grep -q "syscall unlinkat exit" ./trace_output.txt
grep -q "arg1: test.file" ./trace_output.txt
grep -q "arg1: test.dir" ./trace_output.txt
grep -qF "uprobe /proc/self/exe[testing_call+0] enter" ./trace_output.txt
grep -qF "uprobe /proc/self/exe[testing_call+0] exit" ./trace_output.txt
grep -q "arg0: 1" ./trace_output.txt
grep -q "arg1: 2" ./trace_output.txt
grep -q "ret: 3" ./trace_output.txt
grep -qF "do_rmdir+0" ./trace_output.txt

rm -f ./trace_output.txt

