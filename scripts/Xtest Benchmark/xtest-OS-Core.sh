#!/bin/sh

COUNT=1000
truncate -s 0 Core.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _10
cat tmp.txt >> Core.txt
done
