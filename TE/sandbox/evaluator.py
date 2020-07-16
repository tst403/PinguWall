#!/usr/bin/python

import sys
import numpy as np
import matplotlib.pyplot as plt

#act = lambda x: 0 if x <= 0.8 else 1 if x >= 1 else min(1,160*(x-0.8)**3.1)
act = lambda x: 0 if x <= 0.8 else 1

if len(sys.argv) != 3:
    sys.exit(1)


def r2(arr1, arr2):
    cor_mat = np.corrcoef(arr1, arr2)
    cor_xy = cor_mat[0,1]
    return cor_xy**2


unit = 10

with open(sys.argv[1]) as f:
    arr1 = [int(x) for x in f.read().split()]

with open(sys.argv[2]) as f:
    arr2 = [int(x) for x in f.read().split()]

# Find smallest length
small = min(len(arr1), len(arr2))
big  = max(len(arr1), len(arr2))
base = small / unit

def chunks(lst, n):
    n=int(n)
    for i in range(0, len(lst), n):
        yield np.array(lst[i:i + n])

# Divide into small / 100 pices

arr1_s = list(chunks(arr1, base))
arr2_s = list(chunks(arr2, base))

arrValue = 0
arrSegmentMax = 0
sectionCounter = 0
shiftCurrent = 0
shiftMax = 0
count = 0


for arr in arr1_s:
    # Get MAX
    sliceMax = 0
    for arrComp in arr2_s:
        # Get MAX
        shiftMax = 0
        for x in range(int(base)):
            for y in range(int(base)):
                arrShift = np.roll(arr, x)
                arrCompShift = np.roll(arrComp, y)

                if len(arrShift) != len(arrCompShift):
                    min_len = min(len(arrShift), len(arrCompShift))
                    arrShift = arrShift[:min_len]
                    arrCompShift = arrCompShift[:min_len]

                shiftCurrent = r2(arrShift, arrCompShift)
                sliceMax = max(sliceMax, shiftCurrent)

    arrValue += sliceMax
    count += 1

print(100 * (float(arrValue) / count))

