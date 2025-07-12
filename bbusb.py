#!/usr/bin/env python3

"""
/etc/udev/rules.d/99-usb.rules
SUBSYSTEM=="usb", ATTR{idVendor}=="0fca", ATTR{idProduct}=="0001", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0fca", ATTR{idProduct}=="8017", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="0fca", ATTR{idProduct}=="8001", MODE="0666", GROUP="plugdev"



sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -a -G plugdev $USER
"""

import usb.core, usb.util, struct, zlib, time, re, os, sys, stat
from typing import List, Tuple, Optional, Callable

# Constants
MAX_PACKET = 0x10000
MAX_FLASH_BLOCK = 0x3FF4
BOOT_MODES = [
    b'RIM REINIT',
    b'RIM-BootLoader', 
    b'RIM-RAMLoader',
    b'RIM UPL',
    b'RIM-BootNUKE'
]

# Bootrom commands
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

# Ramloader commands
CMD_BUGDISP_LOG = 0xB0
CMD_FLASH_REGIONS_INFO = 0xB4
CMD_DEVICE_PIN = 0xE7
CMD_SEND_BLOCK = 0xF7
CMD_COMPLETE = 0x40C0
CMD_GRS_WIPE = 0xC8
CMD_REBOOT = 0x80EF
CMD_BLOCKED_OS = 0xEC
CMD_SIGNATURE_TRAILER = 0x40F9

class BBUSB:
    def __init__(self):
        self.device = None
        self.id = 0
        self.packet_num = [0, 0, 0]
        self.mode = 0xFF
    
    def __del__(self):
        self.close()
    
    def open(self, product_ids: List[int], timeout_ms: int = 5000) -> bool:
        """Try to open USB device with specified product IDs within timeout period."""
        t = 0

        if self.device is not None:
            try:
                usb.util.dispose_resources(self.device)
            except:
                pass
            self.device = None

        while t < timeout_ms:
            try:
                devices = usb.core.find(find_all=True)

                for device in devices:
                    if device.idVendor != 0x0FCA or device.idProduct not in product_ids: continue
                    try:
                        self.id = device.idProduct
                        self.device = device

                        try:
                            cfg = device.get_active_configuration()
                            current_config = cfg.bConfigurationValue
                        except:
                            current_config = 0
                        
                        try:
                            if device.is_kernel_driver_active(0):
                                device.detach_kernel_driver(0)
                        except:
                            pass
                        
                        try:
                            if device.is_kernel_driver_active(1):
                                device.detach_kernel_driver(1)
                        except:
                            pass
                        
                        if current_config != 1:
                            try:
                                device.set_configuration(1)
                            except:
                                continue
                        
                        try:
                            usb.util.claim_interface(device, 0)
                        except:
                            continue
                        
                        try:
                            usb.util.claim_interface(device, 1)
                        except:
                            pass
                        
                        return True
                        
                    except Exception as e:
                        if self.device is not None:
                            try:
                                usb.util.dispose_resources(
                                    self.device)
                            except:
                                pass
                            self.device = None
                        continue
                                    
            except Exception as e:
                pass

            time.sleep(0.1)
            t += 100

        return False
    
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
    
    def read_data(self, timeout=1000) -> Tuple[int, bytes]:
        """Read data from the device"""
        if not self.device:
            raise Exception("Device not opened")
        
        if self.id == 1 or self.id == 0x8001:
            endpoint = 0x82
        else:
            endpoint = 0x81
        
        try:
            data = self.device.read(endpoint, MAX_PACKET, timeout=timeout)
            
            if len(data) >= 4:
                channel = struct.unpack('<H', data[0:2])[0]
                payload = bytes(data[4:])
                return channel, payload
            else:
                return 0, b''
                
        except usb.core.USBTimeoutError:
            raise Exception("Timeout reading from device")
        except Exception as e:
            raise Exception(f"Can't read from device: {e}")
    
    def send_data(self, channel: int, data: bytes, timeout=1000) -> int:
        """Send data to the device"""
        if not self.device:
            raise Exception("Device not opened")
        
        data_size = len(data)
        size = data_size + 4
        
        if size == 0:
            raise Exception("Zero-length packet")
        
        pkt = bytearray(size)
        struct.pack_into('<H', pkt, 0, channel)
        struct.pack_into('<H', pkt, 2, size)
        
        if data_size > 0:
            pkt[4:] = data
        
        if self.id == 1 or self.id == 0x8001:
            endpoint = 0x02
        else:
            endpoint = 0x01
        
        try:
            transferred = self.device.write(endpoint, pkt, timeout=timeout)
            return transferred
        except Exception as e:
            raise Exception(f"USB transfer failed: {e}")
    
    def channel0(self, cmd: int, data: bytes, timeout=1000) -> Tuple[int, bytes]:
        """Channel 0 communication"""
        size = len(data)
        pkt = bytearray(size + 4)
        pkt[0] = cmd
        pkt[1] = self.mode
        struct.pack_into('>H', pkt, 2, self.packet_num[0])
        
        if size > 0:
            pkt[4:] = data
        
        self.send_data(0, pkt, timeout=timeout)
        channel, response = self.read_data(timeout=timeout)
        
        if len(response) >= 4:
            cmd = response[0]
            self.mode = response[1]
            result = response[4:] if len(response) > 4 else b''
        else:
            result = b''
        
        self.packet_num[0] += 1
        return cmd, result
    
    def channel1(self, data: bytes, timeout=1000) -> bytes:
        """Channel 1 communication"""
        data_size = len(data)
        size = data_size + 10
        pkt = bytearray(size)
        
        pkt[10:] = data
        
        struct.pack_into('<I', pkt, 4, size)
        
        struct.pack_into('<H', pkt, 8, self.packet_num[1])
        self.packet_num[1] += 1
        
        crc = zlib.crc32(pkt[4:]) & 0xFFFFFFFF
        struct.pack_into('<I', pkt, 0, crc)
        
        self.send_data(1, pkt, timeout=timeout)
        _, pkt = self.read_data(timeout=timeout)
        
        result = pkt[10:] if len(pkt) > 10 else b''
        
        self.read_data(timeout=timeout)
        
        return result
    
    def channel2(self, cmd: int, data: bytes, timeout=1000) -> Tuple[int, bytes]:
        """Channel 2 communication"""
        data_size = len(data)
        size = data_size + 8
        pkt = bytearray(size)
        
        struct.pack_into('<H', pkt, 0, size)
        struct.pack_into('<H', pkt, 2, cmd)
        
        if data_size > 0:
            pkt[4:4+data_size] = data
        
        crc = zlib.crc32(pkt[0:data_size+4]) & 0xFFFFFFFF
        struct.pack_into('<I', pkt, data_size + 4, crc)
        
        self.send_data(2, pkt, timeout=timeout)
        channel, response = self.read_data(timeout=timeout)
        
        if channel == 2 and len(response) >= 8:
            resp_cmd = struct.unpack('<H', response[2:4])[0]
            payload_size = len(response) - 8
            
            if payload_size > 0:
                crc1 = zlib.crc32(response[0:payload_size+4]) & 0xFFFFFFFF
                crc2 = struct.unpack('<I', response[payload_size+4:payload_size+8])[0]
                
                if crc1 == crc2:
                    result = response[4:4+payload_size]
                else:
                    result = b''
            else:
                result = b''
            
            self.read_data(timeout=timeout)
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
        _, result = self.channel0(cmd, b'')
        self.read_data()
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
        CHUNK_SIZE = 2024
        
        data = bytearray(10)
        struct.pack_into('<H', data, 0, CMD_WRITE_RAM_SETUP)
        struct.pack_into('<I', data, 2, addr)
        struct.pack_into('<I', data, 6, len(loader))
        self.channel1(data)
        
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
        
        verify_data = struct.pack('<H', CMD_WRITE_RAM_VERIFY)
        self.channel1(verify_data)
    
    def run_loader(self, addr: int):
        """Execute loader at specified address"""
        data = bytearray(6)
        struct.pack_into('<H', data, 0, CMD_EXECUTE_RAM)
        struct.pack_into('<I', data, 2, addr)
        self.channel1(data)
        self.read_data()
    
    def bugdisp_log(self) -> bytes:
        """Retrieves the Bugdisp Log from the device."""
        result_data = b''
        while True:
            cmd, data = self.channel2(CMD_BUGDISP_LOG, bytes([0]*8))
            if cmd == 0xB5:
                result_data += data
            elif cmd == 0xD0:
                break
            else:
                print(f"Warning: Unexpected command {cmd:02X} during BugdispLog retrieval. Stopping.")
                break
        return result_data

    def flash_regions_info(self) -> bytes:
        """Retrieves Flash Regions Info."""
        _, data = self.channel2(CMD_FLASH_REGIONS_INFO, b'')
        return data

    def blocked_os(self) -> bytes:
        """Retrieves Blocked OS CFP (Controlled File Protocol) information."""
        cmd, data = self.channel2(CMD_BLOCKED_OS, b'')
        if cmd == 0xFD:
            return data
        else:
            return b''

    def device_pin(self) -> int:
        """Retrieves the Device PIN."""
        cmd, buff = self.channel2(CMD_DEVICE_PIN, b'')
        if cmd == 0xD1 and len(buff) >= 4:
            return struct.unpack('<I', buff[0:4])[0]
        else:
            return 0

    def send_block(self, data: bytes) -> bool:
        """Sends a data block to the device."""
        cmd, _ = self.channel2(CMD_SEND_BLOCK, data)
        return cmd == 0xDF

    def complete(self) -> bool:
        """Sends the 'Complete' command."""
        cmd, _ = self.channel2(CMD_COMPLETE, b'')
        return cmd == 0x4006

    def grs_wipe(self) -> bool:
        """Initiates a GRS (General Reset System) Wipe."""
        dummy_buff = bytes([0] * MAX_FLASH_BLOCK)
        cmd, _ = self.channel2(CMD_GRS_WIPE, dummy_buff)
        return cmd == 0xD8

    def send_signature(self, data: bytes) -> bool:
        """Sends a signature block."""
        cmd, _ = self.channel2(CMD_SIGNATURE_TRAILER, data)
        return cmd == 0x4006

    def reboot_loader(self) -> bool:
        """Reboots the device in ramloader"""
        cmd, _ = self.channel2(CMD_REBOOT, b'', timeout=50)
        return cmd == 0x80C7

def find_loader(targetId, directory='loaders'):
    pattern = re.compile(r'^loader_([0-9A-Fa-f]{8})-.*\.bin$')
    
    for filename in os.listdir(directory):
        match = pattern.match(filename)
        if not match or match.group(1).upper() != targetId.upper(): continue
        
        filePath = os.path.join(directory, filename)
        with open(filePath, 'rb') as f:
            return f.read()
    
    return None


def restart_program():
    script_path = os.path.abspath(sys.argv[0])
    st = os.stat(script_path)
    os.chmod(script_path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.execv(script_path, sys.argv)

def hexlog(bytearr: bytearray):
    print(str(bytearr.hex()))

if __name__ == "__main__":
    bb = BBUSB()    

    max_attempts = 600
    for _ in range(max_attempts):
        if bb.open([0x0001, 0x8001]): break
        
        time.sleep(1)
    else:
        raise Exception("No device")        
    
    match bb.id:
        case 0x0001:
            print("Connected to device in bootrom")
            bb.ping0()
            bb.set_mode(1)
            bb.password_info()
            model_id = bb.get_model_id()
            print(f"Model ID: 0x{model_id:08X}")

            ramloader = find_loader(f"{model_id:08X}")
            if ramloader:
                print("Sending ramloader")
                bb.send_loader(0x80200000, ramloader)
                print("Sent ramloader, executing...")
                bb.run_loader(0x80200000)
                time.sleep(1)
                restart_program()

        case 0x8001:
            print("Connected to device in ramloader")

            try: # test if we can set mode (ramloader just loaded)
                bb.set_mode(2)
                bb.password_info()
                bb.bugdisp_log()
            except: # we can't, force reboot
                pass
                print("Ramloader timeout, forcing reboot")
                while True: # like really force it
                    try:
                        bb.reboot_loader()
                    except:
                        time.sleep(1)
                        restart_program()


            # C4 - READVERIFY   00 dword(addr) dword(size) byte(val)
            addr = 0x80200d08
            size = 1
            val = 0

            while val < 256:
                cmd, data = bb.channel2(0xC4, bytes([0x00]) + addr.to_bytes(4, 'little') + size.to_bytes(4, 'little') + bytes([val]))
                #if data != bytes([0x01, 0x00, 0x00, 0x00]):
                print(f"{cmd} {hex(addr)}: {data} {hex(val)}")
                    # break
                val += 1
        case _:
            print("Connected to device in unknown mode")


    bb.close()