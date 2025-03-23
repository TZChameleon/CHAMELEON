#!/bin/sh

COUNT=1000
truncate -s 0 Bench1003-Rewrite.txt
for i in $(seq 1 ${COUNT})
do
xtest -t benchmark 1003 | tee -a Bench1003-Rewrite.txt
done
