#!/bin/sh

COUNT=1000
truncate -s 0 Storage.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _60
cat tmp.txt >> Storage.txt
done
