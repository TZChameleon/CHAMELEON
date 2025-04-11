COUNT = 1000
BIAS = 50
FREQUENCY = 1920000

LOG_PATH = "../../evaluation/"
ORIG_PATH = "original"
EL1_PATH = "el1"
EL3_PATH = "el3"

def remove_extremes(lst):
    if len(lst) <= BIAS:
        return lst

    if 0 == BIAS:
        return lst

    filtered = sorted(lst)[BIAS:-BIAS]

    return filtered

def calculate_increased_rate(categories, averages_new, averages_original):
    averages_increased = []
    for i in range(len(categories)):
        increased = (averages_new[i] - averages_original[i]) / averages_original[i] * 100
        averages_increased.append(increased)
        print(categories[i], "increased", increased, "%")
    print("[+] TOTAL increased", sum(averages_increased) / len(averages_increased), "%")
