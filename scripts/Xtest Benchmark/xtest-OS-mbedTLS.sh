#!/bin/sh

COUNT=1000
truncate -s 0 mbedTLS.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _81
cat tmp.txt >> mbedTLS.txt
done
