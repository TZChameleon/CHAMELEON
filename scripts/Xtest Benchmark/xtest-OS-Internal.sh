#!/bin/sh

COUNT=1000
truncate -s 0 Internal.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _41
cat tmp.txt >> Internal.txt
done
