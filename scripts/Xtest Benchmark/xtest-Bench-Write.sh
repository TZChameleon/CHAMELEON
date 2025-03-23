#!/bin/sh

COUNT=1000
truncate -s 0 Bench1001-Write.txt
for i in $(seq 1 ${COUNT})
do
xtest -t benchmark 1001 | tee -a Bench1001-Write.txt
done
