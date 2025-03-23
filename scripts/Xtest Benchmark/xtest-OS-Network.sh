#!/bin/sh

COUNT=1000
truncate -s 0 Network.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _20
cat tmp.txt >> Network.txt
done
