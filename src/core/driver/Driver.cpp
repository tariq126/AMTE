#include <ntddk.h>
#include <wdf.h>
#ifndef NDIS61
#define NDIS61 1
#endif
#include <ndis.h>
#include <fwpsk.h>
#include "Ioctls.h"
#include "RingBuffer.h"

PVOID g_SharedMemoryKernelBase = NULL;
PMDL g_SharedMemoryMdl = NULL;

PKEVENT g_PacketEvent = NULL;
HANDLE g_PacketEventHandle = NULL;

PVOID g_SharedMemoryUserBase = NULL;
extern UINT32 calloutIds[4];

const ULONG SHARED_MEMORY_SIZE = 1024 * 1024 * 16; 

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" EVT_WDF_DRIVER_UNLOAD DriverUnload;

extern NTSTATUS RegisterWfpCallouts(PDEVICE_OBJECT deviceObject);
extern NTSTATUS RegisterBfeFilters();
extern void UnregisterBfeFilters();
extern void BlockEngine_Init();

PVOID MapSharedMemoryToUserSpace() {
    if (!g_SharedMemoryMdl) return NULL;
    PVOID userBase = NULL;
    __try {
        userBase = MmMapLockedPagesSpecifyCache(
            g_SharedMemoryMdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute
        );
        g_SharedMemoryUserBase = userBase;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        userBase = NULL;
    }
    return userBase;
}

NTSTATUS InitializeSharedMemory() {
    PHYSICAL_ADDRESS lowAddress, highAddress, skipBytes;
    lowAddress.QuadPart = 0; highAddress.QuadPart = -1; skipBytes.QuadPart = 0;

    g_SharedMemoryMdl = MmAllocatePagesForMdl(lowAddress, highAddress, skipBytes, SHARED_MEMORY_SIZE);
    if (!g_SharedMemoryMdl) return STATUS_INSUFFICIENT_RESOURCES;

    g_SharedMemoryKernelBase = MmGetSystemAddressForMdlSafe(g_SharedMemoryMdl, NormalPagePriority | MdlMappingNoExecute);
    if (!g_SharedMemoryKernelBase) {
        MmFreePagesFromMdl(g_SharedMemoryMdl);
        IoFreeMdl(g_SharedMemoryMdl);
        g_SharedMemoryMdl = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RingBuffer_Init(g_SharedMemoryKernelBase, SHARED_MEMORY_SIZE);
    return STATUS_SUCCESS;
}

NTSTATUS InitializePacketEvent() {
    UNICODE_STRING eventName;
    RtlInitUnicodeString(&eventName, L"\\BaseNamedObjects\\SecAIPacketEvent");

    g_PacketEvent = IoCreateNotificationEvent(&eventName, &g_PacketEventHandle);
    if (!g_PacketEvent) return STATUS_UNSUCCESSFUL;
    
    KeClearEvent(g_PacketEvent);
    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);

    // STEP 1: Remove BFE filters so no new ClassifyFn calls are dispatched
    UnregisterBfeFilters();

    // STEP 2: Unregister WFP callouts and WAIT for all in-flight ClassifyFn
    //         calls to fully drain. This MUST happen before freeing shared
    //         memory, otherwise a racing ClassifyFn will write to freed
    //         memory -> BSOD (bug check 0xD1 or 0x50).
    for (int i = 0; i < 4; i++) {
        if (calloutIds[i] != 0) {
            FwpsCalloutUnregisterById0(calloutIds[i]);
            calloutIds[i] = 0;
        }
    }

    // STEP 3: Now safe to free shared memory -- no callout can touch it
    if (g_SharedMemoryMdl) {
        MmFreePagesFromMdl(g_SharedMemoryMdl);
        IoFreeMdl(g_SharedMemoryMdl);
        g_SharedMemoryMdl = NULL;
        g_SharedMemoryKernelBase = NULL;
    }

    // STEP 4: Close event handle
    if (g_PacketEventHandle) {
        ZwClose(g_PacketEventHandle);
        g_PacketEventHandle = NULL;
        g_PacketEvent = NULL;
    }
}

VOID EvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength, _In_ ULONG IoControlCode) {
    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(InputBufferLength);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    switch (IoControlCode) {
        case IOCTL_START_CAPTURE: {
            if (OutputBufferLength < sizeof(PVOID)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PVOID userBase = MapSharedMemoryToUserSpace();
            if (userBase) {
                PVOID outBuffer = NULL;
                status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PVOID), &outBuffer, NULL);
                if (NT_SUCCESS(status)) {
                    *(PVOID*)outBuffer = userBase;
                    information = sizeof(PVOID);
                    status = STATUS_SUCCESS;
                }
            } else {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        case IOCTL_STOP_CAPTURE: { // FIX: Use the actual calculated macro
            if (g_SharedMemoryUserBase && g_SharedMemoryMdl) {
                MmUnmapLockedPages(g_SharedMemoryUserBase, g_SharedMemoryMdl);
                g_SharedMemoryUserBase = NULL;
            }
            status = STATUS_SUCCESS;
            information = 0;
            break;
        }
        case IOCTL_ADD_BLOCK_RULE: {
            status = STATUS_SUCCESS;
            information = 0;
            break;
        }
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    WdfRequestCompleteWithInformation(Request, status, information);
}

NTSTATUS InitializeControlDevice(WDFDRIVER Driver) {
    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
    if (!deviceInit) return STATUS_INSUFFICIENT_RESOURCES;

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    UNICODE_STRING deviceName, symLinkName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\SecAIDriver");
    WdfDeviceInitAssignName(deviceInit, &deviceName);

    WDFDEVICE device;
    NTSTATUS status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;

    WDFQUEUE queue;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\SecAIDriver");
    WdfDeviceCreateSymbolicLink(device, &symLinkName);
    
    WdfControlFinishInitializing(device);

    PDEVICE_OBJECT wdmDevice = WdfDeviceWdmGetDeviceObject(device);
    status = RegisterWfpCallouts(wdmDevice);
    if (NT_SUCCESS(status)) {
        RegisterBfeFilters();
    }

    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;

    BlockEngine_Init(); 

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.EvtDriverUnload = DriverUnload;

    status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) return status;

    WDFDRIVER driver = WdfGetDriver();

    // 1. Initialize Memory and Events FIRST
    status = InitializeSharedMemory();
    if (!NT_SUCCESS(status)) return status;

    status = InitializePacketEvent();
    if (!NT_SUCCESS(status)) return status;

    // 2. FINALLY, Turn on the network tap
    status = InitializeControlDevice(driver);
    if (!NT_SUCCESS(status)) return status;

    return STATUS_SUCCESS;
}