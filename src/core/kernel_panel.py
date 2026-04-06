import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import numpy as np

# 1. Import header_dtype and packet_dtype from data_contracts.py.
from data_contracts import header_dtype, packet_dtype

kernel32 = ctypes.windll.kernel32

# Event setup & Map constants
SYNCHRONIZE = 0x00100000

SEC_AI_DEVICE_TYPE = 40000
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0

def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method

IOCTL_START_CAPTURE = CTL_CODE(SEC_AI_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_ADD_BLOCK_RULE = CTL_CODE(SEC_AI_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

# 4. Define a @dataclass BlockRuleV1
@dataclass
class BlockRuleV1:
    ip_version: int
    proto: int
    src_ip: bytes
    dst_ip: bytes
    src_port: int
    dst_port: int
    ttl_ms: int

# Ctypes analog to directly map over IOCTL inputs
class BlockRuleStruct(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ip_version", ctypes.c_uint8),
        ("proto", ctypes.c_uint8),
        ("src_ip", ctypes.c_uint8 * 16),
        ("dst_ip", ctypes.c_uint8 * 16),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("_pad0", ctypes.c_uint8 * 2),     # ADDED PADDING
        ("ttl_ms", ctypes.c_uint64),
        ("timestamp_added", ctypes.c_uint64),
        ("is_active", ctypes.c_long),
        ("_pad1", ctypes.c_uint8 * 4)      # ADDED PADDING
    ]

_driver_handle = None
_packet_event = None
_shared_memory_view = None
_raw_buffer = None  # CRITICAL FIX 3.3: Keep the ctypes buffer alive — prevents GC from freeing the shared memory mapping

def kp_init_driver():
    """Initializes the connection to the kernel driver and maps the event/shared memory."""
    global _driver_handle, _packet_event, _shared_memory_view, _raw_buffer
    
    _driver_handle = kernel32.CreateFileW(
        r"\\.\SecAIDriver",
        0xC0000000, # GENERIC_READ | GENERIC_WRITE
        0,
        None,
        3, # OPEN_EXISTING
        0x80, # FILE_ATTRIBUTE_NORMAL
        None
    )
    if _driver_handle == wintypes.HANDLE(-1).value:
        raise Exception("Failed to open driver handle.")

    # 1. Use ctypes to map the named event SecAIPacketEvent.
    # Note: \BaseNamedObjects namespace naturally maps to Global for user-land processes
    _packet_event = kernel32.OpenEventW(
        SYNCHRONIZE,
        False,
        r"Global\SecAIPacketEvent"
    )
    if not _packet_event:
        raise Exception("Failed to open SecAIPacketEvent. Is driver running?")
        
    # 1. Use ctypes to map the shared memory pointer returned by Driver's IOCTL Memory mapping process
    out_ptr = ctypes.c_uint64()
    bytes_returned = wintypes.DWORD()
    success = kernel32.DeviceIoControl(
        _driver_handle,
        IOCTL_START_CAPTURE,
        None,
        0,
        ctypes.byref(out_ptr),
        ctypes.sizeof(out_ptr),
        ctypes.byref(bytes_returned),
        None
    )
    if success and out_ptr.value:
        SHARED_MEMORY_SIZE = 1024 * 1024 * 16
        buffer_type = ctypes.c_uint8 * SHARED_MEMORY_SIZE
        # CRITICAL FIX 3.3: Store in the module-level global so Python's GC never collects it.
        # If this were a local variable it would be freed when kp_init_driver() returns,
        # leaving _shared_memory_view as a dangling memoryview that reads zeros.
        _raw_buffer = buffer_type.from_address(out_ptr.value)
        _shared_memory_view = memoryview(_raw_buffer)
    else:
        raise Exception("Driver failed to map Shared Memory into Process Space.")


# 4. Implement kp_add_block_rule(rule: BlockRuleV1) to send rules via DeviceIoControl
def kp_add_block_rule(rule: BlockRuleV1):
    if not _driver_handle:
        raise Exception("Driver not initialized. Call kp_init_driver() first.")
    
    struct = BlockRuleStruct()
    struct.ip_version = rule.ip_version
    struct.proto = rule.proto
    
    for i in range(16):
        struct.src_ip[i] = rule.src_ip[i] if i < len(rule.src_ip) else 0
        struct.dst_ip[i] = rule.dst_ip[i] if i < len(rule.dst_ip) else 0
        
    struct.src_port = rule.src_port
    struct.dst_port = rule.dst_port
    struct.ttl_ms = rule.ttl_ms
    struct.timestamp_added = 0
    struct.is_active = 0
    
    bytes_returned = wintypes.DWORD()
    success = kernel32.DeviceIoControl(
        _driver_handle,
        IOCTL_ADD_BLOCK_RULE,
        ctypes.byref(struct),
        ctypes.sizeof(struct),
        None,
        0,
        ctypes.byref(bytes_returned),
        None
    )
    return bool(success)

# 2. Implement kp_read_batch(shared_mem_buffer).
def kp_read_batch(shared_mem_buffer):
    """
    Reads a batch of packets exclusively from the Ring Buffer SPSC stream lock-free.
    Avoids copying until parsing exactly the `count` subset.
    """
    if not shared_mem_buffer:
        return np.array([], dtype=packet_dtype)

    mview = memoryview(shared_mem_buffer)
    header_view = mview[:192]
    header_arr = np.frombuffer(header_view, dtype=header_dtype)
    
    # 3. RING BUFFER LOGIC: Read the SharedMemoryHeader to get head and tail.
    head = int(header_arr['head'][0])
    
    # CRITICAL FIX 2.3: Issue a full memory barrier BEFORE reading tail.
    # Without this, the CPU can reorder the head/tail reads, making head==tail
    # look true on multi-core even when the kernel has already pushed packets.
    # InterlockedOr(0) is a no-op atomically, but forces an mfence-equivalent.
    dummy = ctypes.c_long(0)
    kernel32.InterlockedOr(ctypes.byref(dummy), 0)
    
    tail = int(header_arr['tail'][0])
    capacity = int(header_arr['capacity'][0])
    
    if capacity == 0 or head == tail:
        return np.array([], dtype=packet_dtype)
    
    # 3. Compute count = head - tail (handle wrap-around).
    if head >= tail:
        count = head - tail
    else:
        count = capacity - tail + head
        
    packet_array_offset = 192
    packet_size = 64
    data_view = mview[packet_array_offset:]
    
    # 3. Use memoryview and np.frombuffer to read exactly count items from the PacketRecordV1 array.
    if head >= tail:
        start_byte = tail * packet_size
        end_byte = head * packet_size
        raw_bytes = data_view[start_byte:end_byte]
        records = np.frombuffer(raw_bytes, dtype=packet_dtype)
        packets = np.copy(records) # Copy to avoid asynchronous kernel overwrite corruption while iterating
    else:
        start_byte_1 = tail * packet_size
        end_byte_1 = capacity * packet_size
        raw_bytes_1 = data_view[start_byte_1:end_byte_1]
        records_1 = np.frombuffer(raw_bytes_1, dtype=packet_dtype)
        
        start_byte_2 = 0
        end_byte_2 = head * packet_size
        raw_bytes_2 = data_view[start_byte_2:end_byte_2]
        records_2 = np.frombuffer(raw_bytes_2, dtype=packet_dtype)
        
        # np.concatenate natively incurs a copy, preventing raw memory overlap
        packets = np.concatenate([records_1, records_2])
    
    # Force a full hardware Memory Barrier (mfence equivalent) after reading, before writing tail.
    kernel32.InterlockedOr(ctypes.byref(dummy), 0)
    
    # CRITICAL FIX 2.1: np.frombuffer() always returns a READ-ONLY array.
    # Writing to header_arr['tail'] directly would raise ValueError at runtime.
    # Instead, we write directly through the underlying ctypes buffer at the
    # exact byte offset of the 'tail' field (offset 72, per data_contracts.py).
    ctypes.c_uint64.from_buffer(_raw_buffer, 72).value = head
    
    return packets

def kp_close_driver():
    """Safely closes driver handles, triggering driver-side memory unmapping."""
    global _driver_handle, _packet_event
    
    if _packet_event:
        kernel32.CloseHandle(_packet_event)
        _packet_event = None
        
    if _driver_handle:
        # Closing this handle triggers EvtFileCleanup in the C++ Driver
        kernel32.CloseHandle(_driver_handle)
        _driver_handle = None