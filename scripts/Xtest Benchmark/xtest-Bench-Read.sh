#!/bin/sh

COUNT=1000
truncate -s 0 Bench1002-Read.txt
for i in $(seq 1 ${COUNT})
do
xtest -t benchmark 1002 | tee -a Bench1002-Read.txt
done
