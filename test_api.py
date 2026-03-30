import time
import sys
import os

# Tell Python where your API lives
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src', 'core'))
import kernel_panel as kp

def test_packet_streaming():
    print("\n[--- TEST 1: KERNEL TO PYTHON STREAMING ---]")
    print("[*] Listening for network traffic for 5 seconds... (Go open a website!)")
    
    start_time = time.time()
    total_caught = 0
    
    # Run a 5-second test capture
    while time.time() - start_time < 5.0:
        import numpy as np
        mview = memoryview(kp._shared_memory_view)
        header_view = mview[:192]
        from data_contracts import header_dtype
        header_arr = np.frombuffer(header_view, dtype=header_dtype)
        if total_caught == 0 and int(time.time() * 10) % 10 == 0:
             print(f"    [DEBUG] Head: {header_arr['head'][0]}, Tail: {header_arr['tail'][0]}, Capacity: {header_arr['capacity'][0]}, Dropped/Hits: {header_arr['dropped_packets'][0]}")

        batch = kp.kp_read_batch(kp._shared_memory_view)
        if batch is not None and len(batch) > 0:
            total_caught += len(batch)
            sample_len = batch[0]['wire_len']
            print(f"  -> [+] Python received batch: {len(batch):<4} packets | Sample size: {sample_len} bytes")
        time.sleep(0.01)
        
    print(f"[=] STREAM TEST COMPLETE: Python successfully received {total_caught} total packets in 5s.")

def test_security_blocking():
    print("\n[--- TEST 2: PYTHON TO KERNEL COMMANDS (BLOCKING) ---]")
    print("[*] Constructing a BlockRuleV1 command to block TCP Port 6666 for 10 seconds...")
    
    try:
        # Create a dummy block rule using your exact data class
        rule = kp.BlockRuleV1(
            ip_version=4,
            proto=6,            # TCP
            src_ip=b'\x00'*16,  # 0.0.0.0 (Any)
            dst_ip=b'\x00'*16,  # 0.0.0.0 (Any)
            src_port=0,         # Any source port
            dst_port=6666,      # Block target port 6666
            ttl_ms=10000        # Tell kernel to keep this rule for 10 seconds
        )
        
        # Fire the command from Python into the Kernel
        success = kp.kp_add_block_rule(rule)
        
        if success:
            print("[+] SUCCESS: Python successfully injected the block rule into the Kernel!")
            print("[+] The C++ BlockEngine should now be dropping traffic on Port 6666.")
        else:
            print("[-] FAILED: Kernel rejected the IOCTL command.")
            
    except Exception as e:
        print(f"[-] ERROR testing block rule: {e}")

def main():
    print("[*] Starting AMTE SecAI Python API Test Suite...")
    
    try:
        # Initialize the Python-to-Kernel bridge
        kp.kp_init_driver()
        print("[+] Python Bridge Connected! Shared Memory mapped.\n")
        
        # 1. Test Data Ingestion (Read)
        test_packet_streaming()
        
        # 2. Test Active Response (Write)
        test_security_blocking()
        
    except Exception as e:
        print(f"[!] Critical API Error: {e}")
    finally:
        print("\n[*] API Test Suite Finished.")

if __name__ == "__main__":
    main()