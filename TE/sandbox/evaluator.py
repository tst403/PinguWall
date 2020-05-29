#!/usr/bin/python

import sys

if len(sys.argv) == 2:
    with open(sys.argv[1]) as f:
        nums = [int(x) for x in f.read().split()]

    print(nums)
