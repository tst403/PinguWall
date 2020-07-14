#!/usr/bin/python3

import matplotlib.pyplot as plt
import sys

def get_nums(filename):
    with open(filename, 'r') as f:
        data = f.read()
        data = [int(x) for x in data.split('\n')]
    return data

nums1 = sys.argv[1]
nums2 = sys.argv[2]

nums1 = get_nums(nums1)
nums2 = get_nums(nums2)

plt.plot(nums1)
plt.plot(nums2)

plt.show()