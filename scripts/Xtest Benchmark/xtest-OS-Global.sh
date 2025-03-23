#!/bin/sh

COUNT=1000
truncate -s 0 Global.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _5
cat tmp.txt >> Global.txt
done
