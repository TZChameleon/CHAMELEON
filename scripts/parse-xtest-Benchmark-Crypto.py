#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
import statistics
import numpy as np
from global_things import *

categories = ["SHA1", "SHA226", "ECB", "CBC"]

original_filenames = f"{LOG_PATH}/{ORIG_PATH}/Bench20-Crypto.txt"
el1_filename = f"{LOG_PATH}/{EL1_PATH}/Bench20-Crypto.txt"
el3_filename = f"{LOG_PATH}/{EL3_PATH}/Bench20-Crypto.txt"

def extract_results_from_crypto(filename):
    fd = open(filename, "r")

    line = fd.readline()
    countmean = 0
    a = []
    b = []
    c = []
    d = []

    while line:
        pattern = re.compile(r"(?<=mean=)\d+\.?\d*")
        number = pattern.findall(line)
        if number:
            countmean = countmean + 1
            if (countmean % 4 == 1):
                a = a + list(map(float, number))
            if (countmean % 4 == 2):
                b = b + list(map(float, number))
            if (countmean % 4 == 3):
                c = c + list(map(float, number))
            if (countmean % 4 == 0):
                d = d + list(map(float, number))
        line = fd.readline()
    fd.close()

    a = remove_extremes(a)
    b = remove_extremes(b)
    c = remove_extremes(c)
    d = remove_extremes(d)

    averagea = statistics.mean(a)
    averageb = statistics.mean(b)
    averagec = statistics.mean(c)
    averaged = statistics.mean(d)

    return [averagea, averageb, averagec, averaged]

averages_original = extract_results_from_crypto(original_filenames)
averages_el1 = extract_results_from_crypto(el1_filename)
averages_el3 = extract_results_from_crypto(el3_filename)
rate_averages_original = [0 for _ in range(len(averages_original))]
rate_averages_el1 = [0 for _ in range(len(averages_el1))]
rate_averages_el3 = [0 for _ in range(len(averages_el3))]
for i in range(len(averages_original)):
    rate_averages_original[i] = averages_original[i] / averages_original[i] * 100
    rate_averages_el1[i] = averages_el1[i] / averages_original[i] * 100
    rate_averages_el3[i] = averages_el3[i] / averages_original[i] * 100
print("averages_original", averages_original)
print("averages_el1", averages_el1)
print("averages_el3", averages_el3)

calculate_increased_rate(categories, averages_el1, averages_original)
calculate_increased_rate(categories, averages_el3, averages_original)

