#include <ntddk.h>
#include <wdf.h>
#ifndef NDIS61
#define NDIS61 1
#endif
#include <ndis.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#pragma comment(lib, "ndis.lib")
#pragma comment(lib, "fwpkclnt.lib")
#include "../PacketRecord.h"
#include "RingBuffer.h"
#include "BlockEngine.h"

#pragma warning(push)
#pragma warning(disable: 4201) 

extern PVOID g_SharedMemoryKernelBase;
extern PKEVENT g_PacketEvent;

volatile LONG g_BatchCount = 0;
LARGE_INTEGER g_LastBatchRunTime = {0};

UINT32 calloutIds[4] = {0};
HANDLE g_EngineHandle = NULL; 
KSPIN_LOCK g_RingBufferLock;

EXTERN_C const GUID DECLSPEC_SELECTANY SEC_AI_CALLOUT_IN_V4  = { 0x11111111, 0x1111, 0x1111, { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } };
EXTERN_C const GUID DECLSPEC_SELECTANY SEC_AI_CALLOUT_OUT_V4 = { 0x22222222, 0x2222, 0x2222, { 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22 } };
EXTERN_C const GUID DECLSPEC_SELECTANY SEC_AI_CALLOUT_IN_V6  = { 0x33333333, 0x3333, 0x3333, { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 } };
EXTERN_C const GUID DECLSPEC_SELECTANY SEC_AI_CALLOUT_OUT_V6 = { 0x44444444, 0x4444, 0x4444, { 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44 } };

extern "C" void NTAPI ClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
);

#pragma alloc_text (NONPAGE, ClassifyFn)

UINT32 GetTcpMss(PNET_BUFFER_LIST nbl) {
    NDIS_TCP_LARGE_SEND_OFFLOAD_NET_BUFFER_LIST_INFO lsoInfo;
    lsoInfo.Value = NET_BUFFER_LIST_INFO(nbl, TcpLargeSendNetBufferListInfo);
    if (lsoInfo.Value != 0) {
        if (lsoInfo.LsoV2Transmit.Type == 1) return lsoInfo.LsoV2Transmit.MSS;
        else return lsoInfo.LsoV1Transmit.MSS;
    }
    return 0;
}

NTSTATUS NTAPI NotifyFn(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    FWPS_FILTER0* filter) {
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

void NTAPI ClassifyFn(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut
) {
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    bool canWriteAction = false;
    if (classifyOut) {
        if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) {
            canWriteAction = true;
            classifyOut->actionType = FWP_ACTION_PERMIT; 
        }
    }

    if (!layerData || !g_SharedMemoryKernelBase) return;

    PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return;

    PacketRecordV1 pkt = {0};
    LARGE_INTEGER ts;
    KeQuerySystemTime(&ts);
    pkt.mono_ts_ns = ts.QuadPart * 100; 
    pkt.schema_version = 1;

    UINT32 packetLength = NET_BUFFER_DATA_LENGTH(nb);
    UINT32 mss = GetTcpMss(nbl);
    pkt.wire_len = (mss > 0 && mss < packetLength) ? mss : packetLength;
    pkt.captured_len = pkt.wire_len;

    UCHAR safeBuffer[64];
    PVOID pData = NdisGetDataBuffer(nb, sizeof(safeBuffer), safeBuffer, 1, 0);
    if (pData) {
        PUCHAR buffer = (PUCHAR)pData;
        pkt.tcp_flags = buffer[13];
    }

    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4 || 
        inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V6) {
        pkt.direction = 1; 
    } else {
        pkt.direction = 0; 
    }
    
    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4 || 
        inFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4) {
        pkt.ip_version = 4;
    } else {
        pkt.ip_version = 6;
    }

    SharedMemoryHeader* header = (SharedMemoryHeader*)g_SharedMemoryKernelBase;
    PacketRecordV1* records = (PacketRecordV1*)(header + 1);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingBufferLock, &oldIrql);
    RingBuffer_Push(header, records, &pkt);
    KeReleaseSpinLock(&g_RingBufferLock, oldIrql);

    if (ShouldBlockPacket(&pkt)) {
        if (canWriteAction) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
    }

    LONG currentCount = InterlockedIncrement(&g_BatchCount);
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
    
    LONGLONG elapsed = currentTime.QuadPart - g_LastBatchRunTime.QuadPart;
    
    if (currentCount >= 1024 || elapsed >= 50000) {
        if (g_PacketEvent) KeSetEvent(g_PacketEvent, 0, FALSE); 
        InterlockedExchange(&g_BatchCount, 0);
        InterlockedExchange64(&g_LastBatchRunTime.QuadPart, currentTime.QuadPart); 
    }
}

NTSTATUS RegisterWfpCallouts(PDEVICE_OBJECT deviceObject) {
    KeInitializeSpinLock(&g_RingBufferLock);

    FWPS_CALLOUT0 callout = {0};
    callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN0)ClassifyFn;
    callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN0)NotifyFn;
    callout.flowDeleteFn = NULL;

    NTSTATUS status;
    callout.calloutKey = SEC_AI_CALLOUT_IN_V4;
    status = FwpsCalloutRegister0(deviceObject, &callout, &calloutIds[0]);

    callout.calloutKey = SEC_AI_CALLOUT_OUT_V4;
    status = FwpsCalloutRegister0(deviceObject, &callout, &calloutIds[1]);

    callout.calloutKey = SEC_AI_CALLOUT_IN_V6;
    status = FwpsCalloutRegister0(deviceObject, &callout, &calloutIds[2]);

    callout.calloutKey = SEC_AI_CALLOUT_OUT_V6;
    status = FwpsCalloutRegister0(deviceObject, &callout, &calloutIds[3]);

    return status;
}

NTSTATUS RegisterBfeFilters() {
    FWPM_SESSION0 session = {0};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC; 
    
    NTSTATUS status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_EngineHandle);
    if (!NT_SUCCESS(status)) return status;

    FwpmTransactionBegin0(g_EngineHandle, 0);

    FWPM_CALLOUT0 mCallout = {0};
    FWPM_FILTER0 filter = {0};

    mCallout.calloutKey = SEC_AI_CALLOUT_IN_V4;
    mCallout.displayData.name = (wchar_t*)L"SecAI_IN_V4";
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; 
    filter.action.calloutKey = SEC_AI_CALLOUT_IN_V4;
    filter.weight.type = FWP_EMPTY;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, NULL);

    mCallout.calloutKey = SEC_AI_CALLOUT_OUT_V4;
    mCallout.displayData.name = (wchar_t*)L"SecAI_OUT_V4";
    mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    FwpmCalloutAdd0(g_EngineHandle, &mCallout, NULL, NULL);

    filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = SEC_AI_CALLOUT_OUT_V4;
    filter.weight.type = FWP_EMPTY;
    FwpmFilterAdd0(g_EngineHandle, &filter, NULL, NULL);

    FwpmTransactionCommit0(g_EngineHandle);
    return STATUS_SUCCESS;
}

void UnregisterBfeFilters() {
    if (g_EngineHandle) {
        FwpmEngineClose0(g_EngineHandle); 
        g_EngineHandle = NULL;
    }
}
#pragma warning(pop)