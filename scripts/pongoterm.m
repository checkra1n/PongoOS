#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>             // exit
#include <string.h>             // strlen, strerror
#include <mach/mach.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>
#include <IOKit/IOCFPlugIn.h>

#define LOG(fmt, ...) do { fprintf(stderr, "\x1b[1;96m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)
#define ERR(fmt, ...) do { fprintf(stderr, "\x1b[1;91m" fmt "\x1b[0m\n", ##__VA_ARGS__); } while(0)

typedef struct
{
    volatile uint64_t regID;
    IOUSBDeviceInterface245 **dev;
    IOUSBInterfaceInterface245 **intf;
    pthread_t th;
} stuff_t;

static uint8_t gBlockIO = 1;

static IOReturn USBControlTransfer(IOUSBInterfaceInterface245 **intf, uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint32_t wLength, void *data, uint32_t *wLenDone)
{
    IOUSBDevRequest request =
    {
        .bmRequestType = bmRequestType,
        .bRequest = bRequest,
        .wValue = wValue,
        .wIndex = wIndex,
        .wLength = wLength,
        .pData = data,
    };
    IOReturn ret = (*intf)->ControlRequest(intf, 0, &request);
    if(wLenDone) *wLenDone = request.wLenDone;
    return ret;
}

static void* io_main(void *arg)
{
    stuff_t *stuff = arg;
    int r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    if(r != 0)
    {
        ERR("pthread_setcancelstate: %s", strerror(r));
        exit(-1);
    }
    LOG("[Connected]");
    IOReturn ret = KERN_SUCCESS;
    while(1)
    {
        char buf[0x1000] = {};
        uint8_t in_progress = 1;
        while(in_progress)
        {
            ret = USBControlTransfer(stuff->intf, 0xa1, 2, 0, 0, (uint32_t)sizeof(in_progress), &in_progress, NULL);
            if(ret == KERN_SUCCESS)
            {
                uint32_t outlen = 0;
                ret = USBControlTransfer(stuff->intf, 0xa1, 1, 0, 0, (uint32_t)sizeof(buf), buf, &outlen);
                if(ret == KERN_SUCCESS)
                {
                    while(outlen > 0)
                    {
                        ssize_t s = write(1, buf, outlen);
                        if(s < 0)
                        {
                            ERR("write: %s", strerror(errno));
                            exit(-1);
                        }
                        outlen -= s;
                    }
                }
            }
            if(ret != KERN_SUCCESS)
            {
                goto bad;
            }
        }
        ret = USBControlTransfer(stuff->intf, 0x21, 4, 0xffff, 0, 0, NULL, NULL);
        if(ret != KERN_SUCCESS)
        {
            goto bad;
        }
        r = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        if(r != 0)
        {
            ERR("pthread_setcancelstate: %s", strerror(r));
            exit(-1);
        }
        size_t len = 0;
        while(1)
        {
            char ch;
            ssize_t s = read(0, &ch, 1);
            if(s == 0)
            {
                break;
            }
            if(s < 0)
            {
                if(errno == EINTR)
                {
                    return NULL;
                }
                ERR("read: %s", strerror(errno));
                exit(-1);
            }
            if(len < 512)
            {
                buf[len] = ch;
            }
            ++len;
            if(ch == '\n')
            {
                break;
            }
        }
        r = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        if(r != 0)
        {
            ERR("pthread_setcancelstate: %s", strerror(r));
            exit(-1);
        }
        if(len == 0)
        {
            exit(0);
        }
        if(len > 512)
        {
            ERR("Discarding command of >512 chars");
            continue;
        }
        if(gBlockIO)
        {
            ret = USBControlTransfer(stuff->intf, 0x21, 4, 1, 0, 0, NULL, NULL);
        }
        if(ret == KERN_SUCCESS)
        {
            ret = USBControlTransfer(stuff->intf, 0x21, 3, 0, 0, (uint32_t)len, buf, NULL);
        }
        if(ret != KERN_SUCCESS)
        {
            goto bad;
        }
    }
bad:;
    if(ret == kIOReturnNotResponding)
    {
        return NULL;
    }
    ERR("USBControlTransfer: %s", mach_error_string(ret));
    exit(-1);
}

static void FoundDevice(void *refCon, io_iterator_t it)
{
    stuff_t *stuff = refCon;
    if(stuff->regID)
    {
        return;
    }
    io_service_t usbDev = MACH_PORT_NULL;
    while((usbDev = IOIteratorNext(it)))
    {
        uint64_t regID;
        kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
        if(ret != KERN_SUCCESS)
        {
            ERR("IORegistryEntryGetRegistryEntryID: %s", mach_error_string(ret));
            goto next;
        }
        SInt32 score = 0;
        IOCFPlugInInterface **plugin = NULL;
        ret = IOCreatePlugInInterfaceForService(usbDev, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
        if(ret != KERN_SUCCESS)
        {
            ERR("IOCreatePlugInInterfaceForService(usbDev): %s", mach_error_string(ret));
            goto next;
        }
        HRESULT result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID), (LPVOID*)&stuff->dev);
        (*plugin)->Release(plugin);
        if(result != 0)
        {
            ERR("QueryInterface(dev): 0x%x", result);
            goto next;
        }
        ret = (*stuff->dev)->USBDeviceOpenSeize(stuff->dev);
        if(ret != KERN_SUCCESS)
        {
            ERR("USBDeviceOpenSeize: %s", mach_error_string(ret));
        }
        else
        {
            IOUSBFindInterfaceRequest request =
            {
                .bInterfaceClass = kIOUSBFindInterfaceDontCare,
                .bInterfaceSubClass = kIOUSBFindInterfaceDontCare,
                .bInterfaceProtocol = kIOUSBFindInterfaceDontCare,
                .bAlternateSetting = kIOUSBFindInterfaceDontCare,
            };
            io_iterator_t iter = MACH_PORT_NULL;
            ret = (*stuff->dev)->CreateInterfaceIterator(stuff->dev, &request, &iter);
            if(ret != KERN_SUCCESS)
            {
                ERR("CreateInterfaceIterator: %s", mach_error_string(ret));
            }
            else
            {
                io_service_t usbIntf = MACH_PORT_NULL;
                while((usbIntf = IOIteratorNext(iter)))
                {
                    ret = IOCreatePlugInInterfaceForService(usbIntf, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID, &plugin, &score);
                    IOObjectRelease(usbIntf);
                    if(ret != KERN_SUCCESS)
                    {
                        ERR("IOCreatePlugInInterfaceForService(usbIntf): %s", mach_error_string(ret));
                        continue;
                    }
                    result = (*plugin)->QueryInterface(plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID), (LPVOID*)&stuff->intf);
                    (*plugin)->Release(plugin);
                    if(result != 0)
                    {
                        ERR("QueryInterface(intf): 0x%x", result);
                        continue;
                    }
                    ret = (*stuff->intf)->USBInterfaceOpen(stuff->intf);
                    if(ret != KERN_SUCCESS)
                    {
                        ERR("USBInterfaceOpen: %s", mach_error_string(ret));
                    }
                    else
                    {
                        int r = pthread_create(&stuff->th, NULL, &io_main, stuff);
                        if(r != 0)
                        {
                            ERR("pthread_create: %s", strerror(r));
                            exit(-1);
                        }
                        stuff->regID = regID;
                        while((usbIntf = IOIteratorNext(iter))) IOObjectRelease(usbIntf);
                        IOObjectRelease(iter);
                        while((usbDev = IOIteratorNext(it))) IOObjectRelease(usbDev);
                        IOObjectRelease(usbDev);
                        return;
                    }
                    (*stuff->intf)->Release(stuff->intf);
                    stuff->intf = NULL;
                }
                IOObjectRelease(iter);
            }
        }

    next:;
        if(stuff->dev)
        {
            (*stuff->dev)->Release(stuff->dev);
            stuff->dev = NULL;
        }
        IOObjectRelease(usbDev);
    }
}

static void LostDevice(void *refCon, io_iterator_t it)
{
    stuff_t *stuff = refCon;
    io_service_t usbDev = MACH_PORT_NULL;
    while((usbDev = IOIteratorNext(it)))
    {
        uint64_t regID;
        kern_return_t ret = IORegistryEntryGetRegistryEntryID(usbDev, &regID);
        IOObjectRelease(usbDev);
        if(ret == KERN_SUCCESS && stuff->regID == regID)
        {
            LOG("[Disconnected]");
            int r = pthread_cancel(stuff->th);
            if(r != 0)
            {
                ERR("pthread_cancel: %s", strerror(r));
                exit(-1);
            }
            r = pthread_join(stuff->th, NULL);
            if(r != 0)
            {
                ERR("pthread_join: %s", strerror(r));
                exit(-1);
            }
            stuff->regID = 0;
            (*stuff->intf)->USBInterfaceClose(stuff->intf);
            (*stuff->intf)->Release(stuff->intf);
            (*stuff->dev)->Release(stuff->dev);
        }
    }
}

int main(int argc, const char **argv)
{
    if(argc > 2)
    {
        ERR("Usage: %s [-n]", argv[0]);
        return -1;
    }
    if(argc == 2)
    {
        if(strcmp(argv[1], "-n") == 0)
        {
            gBlockIO = 0;
        }
        else
        {
            ERR("Bad arg: %s", argv[1]);
            return -1;
        }
    }

    kern_return_t ret;
    stuff_t stuff = {};
    io_iterator_t found, lost;
    NSDictionary *dict =
    @{
        @"IOProviderClass": @"IOUSBDevice",
        @"idVendor":  @0x05ac,
        @"idProduct": @0x4141,
    };
    CFDictionaryRef cfdict = (__bridge CFDictionaryRef)dict;
    IONotificationPortRef notifyPort = IONotificationPortCreate(kIOMasterPortDefault);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(notifyPort), kCFRunLoopDefaultMode);

    CFRetain(cfdict);
    ret = IOServiceAddMatchingNotification(notifyPort, kIOFirstMatchNotification, cfdict, &FoundDevice, &stuff, &found);
    if(ret != KERN_SUCCESS)
    {
        ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
        return -1;
    }
    FoundDevice(&stuff, found);

    CFRetain(cfdict);
    ret = IOServiceAddMatchingNotification(notifyPort, kIOTerminatedNotification, cfdict, &LostDevice, &stuff, &lost);
    if(ret != KERN_SUCCESS)
    {
        ERR("IOServiceAddMatchingNotification: %s", mach_error_string(ret));
        return -1;
    }
    LostDevice(&stuff, lost);
    CFRunLoopRun();
    return -1;
}
