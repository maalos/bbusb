import usb.core
import usb.util
import struct
import zlib
import time
from typing import List, Tuple, Optional, Callable, Union

# Constants
MAX_PACKET = 0x10000
BOOT_MODES = [
    b'RIM REINIT',
    b'RIM-BootLoader', 
    b'RIM-RAMLoader',
    b'RIM UPL',
    b'RIM-BootNUKE'
]

# Command constants
CMD_PING = 0xF000
CMD_READ_METRICS = 0xF001
CMD_EXIT = 0xF002
CMD_FRESHNESS_SEAL = 0xF003
CMD_WRITE_RAM = 0xF004
CMD_EXECUTE_RAM = 0xF005
CMD_PASSWORD = 0xF006
CMD_CHANGE_BPS = 0xF007
CMD_DEVICE_NUKE = 0xF008
CMD_WRITE_RAM_SETUP = 0xF009
CMD_WRITE_RAM_VERIFY = 0xF00A
CMD_READ_MODEL_CODE = 0xF00B
CMD_X1 = 0xF00C
CMD_X2 = 0xF00D


class USBError(Exception):
    """Custom exception for USB errors"""
    pass


def wait_for_device_with_id(vendor_id: int, product_id: int, timeout_ms: int) -> bool:
    """Wait for a device with specific vendor and product ID to appear"""
    start_time = time.time() * 1000
    
    while (time.time() * 1000 - start_time) < timeout_ms:
        devices = usb.core.find(find_all=True, idVendor=vendor_id, idProduct=product_id)
        if devices:
            return True
        time.sleep(0.1)
    
    return False


class BBUSB:
    """BlackBerry USB Communication Class"""
    
    def __init__(self):
        self.device = None
        self.id = 0
        self.packet_num = [0, 0, 0]  # Array for packet numbers
        self.mode = 0xFF
    
    def __del__(self):
        self.close()
    
    def try_open(self, product_ids: List[int], timeout_ms: int = 5000) -> bool:
        """
        Try to open USB device with specified product IDs within timeout period.

        Args:
            product_ids: List of product IDs to search for
            timeout_ms: Timeout in milliseconds (default: 5000)

        Returns:
            bool: True if device successfully opened, False otherwise
        """
        self.id = 0
        t = 0

        # Close existing device if open
        if self.device is not None:
            try:
                usb.util.dispose_resources(self.device)
            except:
                pass
            self.device = None

        while t < timeout_ms:
            try:
                # Find all USB devices
                devices = usb.core.find(find_all=True)

                for device in devices:
                    # Check if vendor ID matches 0x0FCA
                    if device.idVendor == 0x0FCA:
                        # Check if product ID matches any in the list
                        for pid in product_ids:
                            if device.idProduct == pid:
                                try:
                                    self.id = device.idProduct
                                    self.device = device

                                    # Get current configuration
                                    try:
                                        cfg = device.get_active_configuration()
                                        current_config = cfg.bConfigurationValue
                                    except:
                                        current_config = 0

                                    # Detach kernel drivers if active
                                    try:
                                        if device.is_kernel_driver_active(0):
                                            device.detach_kernel_driver(0)
                                    except:
                                        pass  # Ignore errors

                                    try:
                                        if device.is_kernel_driver_active(1):
                                            device.detach_kernel_driver(1)
                                    except:
                                        pass  # Ignore errors

                                    # Set configuration to 1 if not already set
                                    if current_config != 1:
                                        try:
                                            device.set_configuration(1)
                                        except:
                                            continue  # Try next device

                                    # Claim interface 0 (required)
                                    try:
                                        usb.util.claim_interface(device, 0)
                                    except:
                                        continue  # Try next device

                                    # Claim interface 1 (optional - ignore errors)
                                    try:
                                        usb.util.claim_interface(device, 1)
                                    except:
                                        pass  # Interface 1 is optional

                                    # Initialize packet numbers and mode
                                    self.packet_num = [0, 0, 0]
                                    self.mode = 0xFF

                                    return True  # Successfully opened

                                except Exception as e:
                                    # Device couldn't be opened - clean up
                                    if self.device is not None:
                                        try:
                                            usb.util.dispose_resources(
                                                self.device)
                                        except:
                                            pass
                                        self.device = None
                                    continue  # Try next device

            except Exception as e:
                # Error enumerating devices, continue trying
                pass

            # Wait 100ms before next attempt
            time.sleep(0.1)
            t += 100

        # Nothing found within timeout
        return False

    
    def open(self, product_ids: List[int], timeout_ms: int = 5000):
        """Open device with specified product IDs, raise exception if not found"""
        if not self.try_open(product_ids, timeout_ms):
            raise USBError("Device with required ProductID(s) not found or could not be opened")
    
    def close(self):
        """Close the USB device"""
        if self.device:
            try:
                usb.util.release_interface(self.device, 0)
                usb.util.release_interface(self.device, 1)
                usb.util.dispose_resources(self.device)
            except:
                pass
            self.device = None
        self.id = 0
    
    def read_data(self) -> Tuple[int, bytes]:
        """Read data from the device"""
        if not self.device:
            raise USBError("Device not opened")
        
        # Select endpoint based on device ID
        if self.id == 1 or self.id == 0x8001:
            endpoint = 0x82
        else:
            endpoint = 0x81
        
        try:
            data = self.device.read(endpoint, MAX_PACKET, timeout=1000)
            
            if len(data) >= 4:
                channel = struct.unpack('<H', data[0:2])[0]
                payload = bytes(data[4:])
                return channel, payload
            else:
                return 0, b''
                
        except usb.core.USBTimeoutError:
            raise USBError("Timeout reading from device")
        except Exception as e:
            raise USBError(f"Can't read from device: {e}")
    
    def send_data(self, channel: int, data: bytes) -> int:
        """Send data to the device"""
        if not self.device:
            raise USBError("Device not opened")
        
        data_size = len(data)
        size = data_size + 4
        
        if size == 0:
            raise Exception("Zero-length packet")
        
        # Create packet with header
        pkt = bytearray(size)
        struct.pack_into('<H', pkt, 0, channel)  # Channel
        struct.pack_into('<H', pkt, 2, size)     # Size
        
        if data_size > 0:
            pkt[4:] = data
        
        # Select endpoint based on device ID
        if self.id == 1 or self.id == 0x8001:
            endpoint = 0x02
        else:
            endpoint = 0x01
        
        try:
            transferred = self.device.write(endpoint, pkt, timeout=1000)
            return transferred
        except Exception as e:
            raise USBError(f"USB transfer failed: {e}")
    
    def channel0(self, cmd: int, data: bytes) -> Tuple[int, bytes]:
        """Channel 0 communication"""
        size = len(data)
        pkt = bytearray(size + 4)
        pkt[0] = cmd
        pkt[1] = self.mode
        struct.pack_into('>H', pkt, 2, self.packet_num[0])  # Big-endian
        
        if size > 0:
            pkt[4:] = data
        
        self.send_data(0, pkt)
        channel, response = self.read_data()
        
        if len(response) >= 4:
            cmd = response[0]
            self.mode = response[1]
            result = response[4:] if len(response) > 4 else b''
        else:
            result = b''
        
        self.packet_num[0] += 1
        return cmd, result
    
    def channel1(self, data: bytes) -> bytes:
        """Channel 1 communication"""
        data_size = len(data)
        size = data_size + 10
        pkt = bytearray(size)
        
        # Copy input data to offset 10
        pkt[10:] = data
        
        # Set packet size at offset 4 (little-endian)
        struct.pack_into('<I', pkt, 4, size)
        
        # Set packet number at offset 8 (little-endian)
        struct.pack_into('<H', pkt, 8, self.packet_num[1])
        self.packet_num[1] += 1
        
        # Calculate CRC32 of everything from offset 4 to end
        crc = zlib.crc32(pkt[4:]) & 0xFFFFFFFF
        struct.pack_into('<I', pkt, 0, crc)
        
        # Send packet and read response
        self.send_data(1, pkt)
        channel, pkt = self.read_data()
        
        # Extract response payload, skip first 10 bytes
        result = pkt[10:] if len(pkt) > 10 else b''
        
        # Read and discard second response
        self.read_data()
        
        return result
    
    def channel2(self, cmd: int, data: bytes) -> Tuple[int, bytes]:
        """Channel 2 communication"""
        data_size = len(data)
        size = data_size + 8
        pkt = bytearray(size)
        
        struct.pack_into('<H', pkt, 0, size)  # Size
        struct.pack_into('<H', pkt, 2, cmd)   # Command
        
        if data_size > 0:
            pkt[4:4+data_size] = data
        
        # Calculate CRC32 and append
        crc = zlib.crc32(pkt[0:data_size+4]) & 0xFFFFFFFF
        struct.pack_into('<I', pkt, data_size + 4, crc)
        
        self.send_data(2, pkt)
        channel, response = self.read_data()
        
        if channel == 2 and len(response) >= 8:
            resp_cmd = struct.unpack('<H', response[2:4])[0]
            payload_size = len(response) - 8
            
            if payload_size > 0:
                # Verify CRC
                crc1 = zlib.crc32(response[0:payload_size+4]) & 0xFFFFFFFF
                crc2 = struct.unpack('<I', response[payload_size+4:payload_size+8])[0]
                
                if crc1 == crc2:
                    result = response[4:4+payload_size]
                else:
                    result = b''
            else:
                result = b''
            
            self.read_data()  # Discard second response
            return resp_cmd, result
        
        return 0, b''
    
    def ping0(self):
        """Send ping on channel 0"""
        cmd = 1
        self.channel0(cmd, bytes([0x14, 0x05, 0x83, 0x19, 0x00, 0x00, 0x00, 0x00]))
    
    def switch_channel(self):
        """Switch communication channel"""
        self.send_data(1, bytes([6, 6]))
        self.read_data()
        self.read_data()
        self.packet_num[1] = 0
    
    def reboot(self):
        """Reboot the device"""
        cmd = 3
        self.channel0(cmd, b'')
        self.packet_num[0] = 0
    
    def set_mode(self, mode: int) -> bool:
        """Set device mode"""
        if mode >= len(BOOT_MODES):
            return False
        
        cmd = 7
        data = bytearray(17)
        boot_mode = BOOT_MODES[mode]
        data[0:len(boot_mode)] = boot_mode
        data[16] = 1
        
        resp_cmd, _ = self.channel0(cmd, data)
        return resp_cmd == 8
    
    def password_info(self) -> bytes:
        """Get password information"""
        cmd = 0xA
        resp_cmd, result = self.channel0(cmd, b'')
        self.read_data()  # Discard additional response
        return result
    
    def get_metrics(self) -> bytes:
        """Get device metrics"""
        data = struct.pack('<H', CMD_READ_METRICS)
        return self.channel1(data)
    
    def get_model_id(self) -> int:
        """Get device model ID"""
        data = struct.pack('<H', CMD_READ_MODEL_CODE)
        response = self.channel1(data)
        
        if len(response) < 14:
            raise Exception(f'Unexpected response size: {len(response)} bytes')
        
        return struct.unpack('<I', response[10:14])[0]
    
    def send_loader(self, addr: int, loader: bytes, callback: Optional[Callable[[int, int], None]] = None):
        """Send loader to device"""
        CHUNK_SIZE = 2044 - 10 - 10  # 2024 bytes
        
        # Setup write
        data = bytearray(10)
        struct.pack_into('<H', data, 0, CMD_WRITE_RAM_SETUP)
        struct.pack_into('<I', data, 2, addr)
        struct.pack_into('<I', data, 6, len(loader))
        self.channel1(data)
        
        # Send data in chunks
        bytes_sent = 0
        total_size = len(loader)
        
        while bytes_sent < total_size:
            chunk_size = min(CHUNK_SIZE, total_size - bytes_sent)
            pkt = bytearray(chunk_size + 10)
            
            struct.pack_into('<H', pkt, 0, CMD_WRITE_RAM)
            struct.pack_into('<I', pkt, 2, addr + bytes_sent)
            struct.pack_into('<I', pkt, 6, chunk_size)
            pkt[10:] = loader[bytes_sent:bytes_sent + chunk_size]
            
            self.channel1(pkt)
            bytes_sent += chunk_size
            
            if callback:
                callback(bytes_sent, total_size)
        
        if callback:
            callback(total_size, total_size)
        
        # Verify
        verify_data = struct.pack('<H', CMD_WRITE_RAM_VERIFY)
        self.channel1(verify_data)
    
    def run_loader(self, addr: int):
        """Execute loader at specified address"""
        data = bytearray(6)
        struct.pack_into('<H', data, 0, CMD_EXECUTE_RAM)
        struct.pack_into('<I', data, 2, addr)
        self.channel1(data)
        self.read_data()  # Read response


if __name__ == "__main__":
    bb = BBUSB()
    

    max_attempts = 50
    for attempt in range(max_attempts):
        if bb.try_open([1]):
            break
        time.sleep(0.1)
    else:
        raise Exception("No device")        
    bb.ping0()
    bb.set_mode(1)
    model_id = bb.get_model_id()
    print(f"Model ID: 0x{model_id:08X}")
    bb.close()

