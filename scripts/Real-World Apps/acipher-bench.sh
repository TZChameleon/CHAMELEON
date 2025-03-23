#!/bin/sh

COUNT=1000
EXAMPLE_NAME="acipher"
OUTPUT_FILENAME="${EXAMPLE_NAME}-cost-time.txt"
CMD="optee_example_${EXAMPLE_NAME} 1024 THIS_IS_A_TEST_STRING"
truncate -s 0 ${OUTPUT_FILENAME}
for i in $(seq 1 ${COUNT})
do
    TMP_FILE="/tmp/${EXAMPLE_NAME}-${i}.txt"
    time -f "time: %E" -o ${TMP_FILE} ${CMD}
    cat ${TMP_FILE} >> ${OUTPUT_FILENAME}
done
