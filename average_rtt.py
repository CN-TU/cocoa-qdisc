#!/usr/bin/env python3
import statistics
import sys

all_lines = sys.stdin.readlines()
# print("all_lines", all_lines)
all_lines = [float(line.split("\t")[-1]) for line in all_lines]

# print("all_lines", all_lines)
print("mean rtt")
print(statistics.mean(all_lines))
