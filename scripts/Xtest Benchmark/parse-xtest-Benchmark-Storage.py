#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True

import re
import statistics
import numpy as np
from global_things import *

DATA_IDX = 1

categories = ["WRITE", "READ", "REWRITE"]

original_filenames = [
    f"{LOG_PATH}/{ORIG_PATH}/Bench1001-Write.txt", 
    f"{LOG_PATH}/{ORIG_PATH}/Bench1002-Read.txt", 
    f"{LOG_PATH}/{ORIG_PATH}/Bench1003-Rewrite.txt", 
]
el1_filenames = [
    f"{LOG_PATH}/{EL1_PATH}/Bench1001-Write.txt", 
    f"{LOG_PATH}/{EL1_PATH}/Bench1002-Read.txt", 
    f"{LOG_PATH}/{EL1_PATH}/Bench1003-Rewrite.txt", 
]
el3_filenames = [
    f"{LOG_PATH}/{EL3_PATH}/Bench1001-Write.txt", 
    f"{LOG_PATH}/{EL3_PATH}/Bench1002-Read.txt", 
    f"{LOG_PATH}/{EL3_PATH}/Bench1003-Rewrite.txt", 
]

def extract_results_from_storage(filename):
    fd = open(filename, "r")

    line = fd.readline()
    a = []
    b = []
    c = []
    d = []
    e = []
    f = []
    g = []
    h = []

    while line:
        if " 256" in line:
            tmp = line.split("|")[DATA_IDX]
            a = a + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if " 512" in line:
            tmp = line.split("|")[DATA_IDX]
            b = b + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if "1024" in line:
            tmp = line.split("|")[DATA_IDX]
            c = c + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if "2048" in line:
            tmp = line.split("|")[DATA_IDX]
            d = d + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if "4096" in line:
            tmp = line.split("|")[DATA_IDX]
            e = e + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if "16384" in line:
            tmp = line.split("|")[DATA_IDX]
            f = f + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if "524288" in line:
            tmp = line.split("|")[DATA_IDX]
            g = g + list(map(float, re.findall(r"\d+\.?\d*", tmp)))
        if "1048576" in line:
            tmp = line.split("|")[DATA_IDX]
            h = h + list(map(float, re.findall(r"\d+\.?\d*", tmp))) 
        line = fd.readline()
    fd.close()

    a = remove_extremes(a)
    b = remove_extremes(b)
    c = remove_extremes(c)
    d = remove_extremes(d)
    e = remove_extremes(e)
    f = remove_extremes(f)
    g = remove_extremes(g)
    h = remove_extremes(h)

    averagea = statistics.mean(a)
    averageb = statistics.mean(b)
    averagec = statistics.mean(c)
    averaged = statistics.mean(d)
    averagee = statistics.mean(e)
    averagef = statistics.mean(f)
    averageg = statistics.mean(g)
    averageh = statistics.mean(h)

    return [averagea, averageb, averagec, averaged, averagee, averagef, averageg, averageh]

# 计算每组归一化后的平均值
averages_original = []
averages_el1 = []
averages_el3 = []
for i in range(len(original_filenames)):
    original_list = extract_results_from_storage(original_filenames[i])
    el1_list = extract_results_from_storage(el1_filenames[i])
    el3_list = extract_results_from_storage(el3_filenames[i])
    averages_original.append(sum(original_list) / len(original_list))
    averages_el1.append(sum(el1_list) / len(el1_list))
    averages_el3.append(sum(el3_list) / len(el3_list))
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

