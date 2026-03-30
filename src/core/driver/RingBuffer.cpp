#include "RingBuffer.h"

void RingBuffer_Init(PVOID baseAddress, ULONG totalSizeBytes) {
    if (!baseAddress) return;

    RtlZeroMemory(baseAddress, totalSizeBytes);

    SharedMemoryHeader* header = (SharedMemoryHeader*)baseAddress;
    header->capacity = (totalSizeBytes - sizeof(SharedMemoryHeader)) / sizeof(PacketRecordV1);
    header->head = 0;
    header->tail = 0;
}

bool RingBuffer_Push(SharedMemoryHeader* header, PacketRecordV1* buffer_start, const PacketRecordV1* pkt) {
    if (!header || !buffer_start || !pkt || header->capacity == 0) return false;

    UINT64 head = header->head;
    UINT64 tail = header->tail;
    UINT64 next_head = (head + 1) % header->capacity;

    if (next_head == tail) {
        InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&header->dropped_packets));
        return false;
    }

    buffer_start[head] = *pkt;
    KeMemoryBarrier();
    header->head = next_head;

    return true;
}
