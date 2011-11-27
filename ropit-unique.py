#!/usr/bin/python3

import sys
import re

if len(sys.argv) < 2:
    print("Usage: %s filename" % sys.argv[0])
    exit(1)

(program, filename) = sys.argv

# get file content
content = ""
with open(filename, "r") as fp:
    content = fp.read()

# get lines
lines = content.splitlines()
print("There are %d lines to parse" % len(lines))

# construct our dictionnary ^^
print("Construct gadget list")
pattern = '((.*(i|l)?ret(d|f|q)?)(\s*(\w+|\d+)*))\s+#.*'
gadgets = dict()
for line in lines:
    gadget = [field.strip() for field in line.split(" : ")]
    # print(gadget)
    if len(gadget) != 2:
        print("bad line: '%s'" % line)
        continue
    # construct dictionnary
    (addr, gadget) = gadget
    gadget = re.sub(pattern, "\\1", gadget).strip()
    if gadget not in gadgets.keys():
        gadgets[gadget] = []

    addr = int(addr, 16)
    if addr not in gadgets[gadget]:
        gadgets[gadget].append(addr)

totalGadget = totalAddr = 0
print("\nShowing constructed list")
for gadget, addrs in gadgets.items():
    print("%s :" % gadget)
    addrs.sort()
    showed = 0
    print("    ", end='')
    for addr in addrs:
        print("0x%08x" % addr, end='')
        showed += 1
        if (showed % 8) == 0:
            print("\n    ", end='')
        else:
            print(", ", end="")
    print("")
    totalAddr += len(addrs)
totalGadget = len(gadgets.keys())

print("\nWe parsed %d lines and got:" % len(lines))
print("There are %d unique gadgets for %d unique addresses" % (totalGadget, totalAddr))
