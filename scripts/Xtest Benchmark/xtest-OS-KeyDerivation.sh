#!/bin/sh

COUNT=1000
truncate -s 0 KeyDerivation.txt
for i in $(seq 1 ${COUNT})
do
time -f "time: %E" -o tmp.txt xtest _80
cat tmp.txt >> KeyDerivation.txt
done
