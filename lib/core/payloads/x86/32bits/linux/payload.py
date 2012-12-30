from random import Random

class Rop():
    rand = Random()
    def __init__(self):
        rand = Random()
    def gen_present(self):
        pass

    def gen_ropstack(self):
        pass

    def gen_needed(self):
        pass

    def show_ropstack(gadgets, ropstack):
        for addr in ropstack:
            comment = ""
            # search for comment of addr in gadgets
            for gadget, addrs in gadgets.items():
                # found comment :)
                if addr in addrs:
                    comment = gadget
                    break

            # print out comment
            if isinstance(addr, str):
                print("%16s # %s" % (addr, comment))
                continue
            elif isinstance(addr, dict):
                for name, addr in gadgets['.data'].items():
                    if name == addr:
                        print("%6s0x%08x # %s" % ("", addr, name))
            # numbers
            else:
                print("%6s0x%08x # %s" % ("", addr, comment))
    
    def isAligned(addr, align = 4):
        return not (addr % align)

    # search for an addr
    def get_addr(base, limit, align = 4):
        addr = 0
        Rop.rand = Random()
        # get addr as long as we have unaligned addr
        while True:
            # get random address
            addr = Rop.rand.randrange(base, base + limit)
            # ensure alignment
            if Rop.isAligned(addr, align) and addr < base+limit:
                break
        return addr

    # BUGGY
    # addrSizeList : list of needed area size
    def get_memarea(base, limit, addrSizeList, align = 4):
        # check parameters type
        if not isinstance(addrSizeList, list):
            raise TypeError('Expected list')

        # sort lists
        addrSizeList.sort()

        # get all addrs
        addrsFree = []
        for addr in range(base, base+limit):
            addrsFree.append(addr)

        # total size
        sizeTotal = 0
        for size in addrSizeList:
            sizeTotal += size

        # check if we got enough room
        if sizeTotal >= limit:
            return list()

        # random base and limit
        print("base: %d" % base)
        print("limit: %d" % limit)
        print("max: %d" % (base+limit))
        rbase = Rop.get_addr(base, limit)
        print("rbase: %d" % rbase)
        rlimit = limit - (rbase - base)
        print("rlimit: %d" % rlimit)
        rmax = rbase + rlimit
        print("rmax = %d" % rmax)

        # get list of addrs
        addrs = list()
        for size in addrSizeList:
            searchSpace = True
            # random address
            while searchSpace:
                raddr = Rop.get_addr(rbase, rlimit)
                searchSpace = (raddr not in addrsFree) and (raddr + size > rmax)
                print("raddr: %d" % raddr)
                if not searchSpace:
                    addrsFree.remove(raddr)
                    addrs.append(raddr)
                    addrs.sort()

        return addrs

    # get a bunch of addresses
    def get_addrs(base, limit, nAddr, align = 4):
        addrs = list()

        while (len(addrs) < nAddr):
            addr = Rop.get_addr(base, limit, align)
            if addr not in addrs:
                addrs.append(addr)
        addrs.sort()

        return addrs
