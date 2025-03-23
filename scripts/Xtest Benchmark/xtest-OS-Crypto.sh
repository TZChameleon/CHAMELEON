#!/bin/sh

COUNT=1000
truncate -s 0 Crypto.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _40
cat tmp.txt >> Crypto.txt
done
