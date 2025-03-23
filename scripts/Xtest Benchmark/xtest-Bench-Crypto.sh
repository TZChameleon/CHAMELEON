#!/bin/sh

COUNT=1000
truncate -s 0 Bench20-Crypto.txt
for i in $(seq 1 ${COUNT})
do
xtest -t benchmark _20 | tee -a Bench20-Crypto.txt
done
