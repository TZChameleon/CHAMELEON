#!/bin/sh

COUNT=1000
truncate -s 0 SharedMemory.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _7
cat tmp.txt >> SharedMemory.txt
done
