#!/usr/bin/env python3
import usb.core
import struct
import sys
import argparse
import time

parser = argparse.ArgumentParser(description='A little Linux kernel/initrd uploader for pongoOS.')

parser.add_argument('-k', '--kernel', dest='kernel', help='path to kernel image')
parser.add_argument('-d', '--dtbpack', dest='dtbpack', help='path to dtbpack')
parser.add_argument('-r', '--initrd', dest='initrd', help='path to initial ramdisk')
parser.add_argument('-c', '--cmdline', dest='cmdline', help='custom kernel command line')

args = parser.parse_args()

if args.kernel is None:
    print(f"error: No kernel specified! Run `{sys.argv[0]} --help` for usage.")
    exit(1)

if args.dtbpack is None:
    print(f"error: No dtbpack specified! Run `{sys.argv[0]} --help` for usage.")
    exit(1)

dev = usb.core.find(idVendor=0x05ac, idProduct=0x4141)
if dev is None:
    print("Waiting for device...")

    while dev is None:
        dev = usb.core.find(idVendor=0x05ac, idProduct=0x4141)
        if dev is not None:
            dev.set_configuration()
            break
        time.sleep(2)
else:
    dev.set_configuration()

kernel = open(args.kernel, "rb").read()
fdt = open(args.dtbpack, "rb").read()

if args.cmdline is not None:
    dev.ctrl_transfer(0x21, 4, 0, 0, 0)
    dev.ctrl_transfer(0x21, 3, 0, 0, f"linux_cmdline {args.cmdline}\n")

if args.initrd is not None:
    print("Loading initial ramdisk...")
    initrd = open(args.initrd, "rb").read()
    initrd_size = len(initrd)
    dev.ctrl_transfer(0x21, 2, 0, 0, 0)
    dev.ctrl_transfer(0x21, 1, 0, 0, struct.pack('I', initrd_size))

    dev.write(2, initrd, 1000000)
    dev.ctrl_transfer(0x21, 4, 0, 0, 0)
    dev.ctrl_transfer(0x21, 3, 0, 0, "ramdisk\n")
    print("Initial ramdisk loaded successfully.")

print("Loading device tree...")
dev.ctrl_transfer(0x21, 2, 0, 0, 0)
dev.ctrl_transfer(0x21, 1, 0, 0, 0)
dev.write(2, fdt)

dev.ctrl_transfer(0x21, 4, 0, 0, 0)
dev.ctrl_transfer(0x21, 3, 0, 0, "fdt\n")
print("Device tree loaded successfully.")

print("Loading kernel...")
kernel_size = len(kernel)
dev.ctrl_transfer(0x21, 2, 0, 0, 0)
dev.ctrl_transfer(0x21, 1, 0, 0, struct.pack('I', kernel_size))

dev.write(2, kernel, 1000000)
print("Kernel loaded successfully.")

dev.ctrl_transfer(0x21, 4, 0, 0, 0)

print("Booting...")
try:
    dev.ctrl_transfer(0x21, 3, 0, 0, "bootl\n")
except:
    # if the device disconnects without acknowledging it usually means it succeeded
    print("Success.")
