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

    // BUG FIX: Never trust indices from user-mode memory!
    // Force the indices to wrap around within the bounds of your array's capacity.
    UINT64 safe_head = header->head % header->capacity;
    UINT64 safe_tail = header->tail % header->capacity;
    
    UINT64 next_head = (safe_head + 1) % header->capacity;

    if (next_head == safe_tail) {
        InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&header->dropped_packets));
        return false;
    }

    // Now it is mathematically impossible to write out of bounds
    buffer_start[safe_head] = *pkt;
    KeMemoryBarrier();
    
    // Update the index safely
    header->head = next_head;

    return true;
}
