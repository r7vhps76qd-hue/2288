"""
Агент для ПК2 с шифрованием
Собирает данные, шифрует и отправляет на главный сервер (ПК1)
"""
import socket
import json
import os
import time
import hashlib
import base64
import psutil
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SystemAgent:
    def __init__(self, server_ip='192.168.1.100', server_port=9090):
        """
        Инициализация агента
        
        Args:
            server_ip (str): IP адрес главного сервера (ПК1)
            server_port (int): Порт сервера
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.agent_id = f"agent_{socket.gethostname()}"
        self.running = True
        
        # Ключ шифрования (генерируется или загружается)
        self.encryption_key = self._load_or_generate_key()
        
        # Папки
        self.temp_dir = "./temp"
        self.secure_temp_dir = "./secure_temp"
        os.makedirs(self.temp_dir, exist_ok=True)
        os.makedirs(self.secure_temp_dir, exist_ok=True)
        
        print("=" * 60)
        print("🤖 АГЕНТ АВТОНОМНОЙ СИСТЕМЫ УПРАВЛЕНИЯ")
        print("=" * 60)
        print(f"🆔 ID агента: {self.agent_id}")
        print(f"📡 Сервер: {self.server_ip}:{self.server_port}")
        print(f"🔐 Шифрование: {'✅ ВКЛ' if self.encryption_key else '❌ ВЫКЛ'}")
        print("=" * 60)
    
    def _load_or_generate_key(self):
        """Загрузка или генерация ключа шифрования"""
        key_file = "./encryption_key.key"
        
        try:
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key = f.read()
                print(f"✅ Ключ шифрования загружен из файла")
                return key
            else:
                # Генерируем новый ключ
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                print(f"✅ Сгенерирован новый ключ шифрования")
                return key
        except Exception as e:
            print(f"❌ Ошибка работы с ключом шифрования: {e}")
            return None
    
    def encrypt_data(self, data):
        """Шифрование данных"""
        if not self.encryption_key:
            print("⚠️ Шифрование отключено, отправляю в открытом виде")
            return data, None
        
        try:
            cipher = Fernet(self.encryption_key)
            encrypted = cipher.encrypt(data)
            
            # Добавляем метку что данные зашифрованы
            header = b"ENCRYPTED::"
            result = header + encrypted
            
            return result, self.encryption_key
        except Exception as e:
            print(f"❌ Ошибка шифрования: {e}")
            return data, None
    
    def decrypt_data(self, encrypted_data):
        """Расшифровка данных"""
        if not self.encryption_key:
            return encrypted_data
        
        try:
            if encrypted_data.startswith(b"ENCRYPTED::"):
                cipher = Fernet(self.encryption_key)
                decrypted = cipher.decrypt(encrypted_data[10:])  # Убираем заголовок
                return decrypted
            else:
                return encrypted_data
        except Exception as e:
            print(f"❌ Ошибка расшифровки: {e}")
            return encrypted_data
    
    def secure_send_file(self, file_path, file_type="TELEGRAM"):
        """
        Безопасная отправка файла с шифрованием
        
        Args:
            file_path (str): Путь к файлу
            file_type (str): Тип файла
        """
        if not os.path.exists(file_path):
            print(f"❌ Файл не найден: {file_path}")
            return False
        
        try:
            # Читаем файл
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            print(f"🔒 Шифрую файл: {os.path.basename(file_path)}")
            
            # Шифруем данные
            encrypted_data, key = self.encrypt_data(file_data)
            
            # Готовим метаданные
            metadata = {
                'filename': os.path.basename(file_path),
                'original_size': len(file_data),
                'encrypted_size': len(encrypted_data),
                'encrypted': key is not None,
                'hash': hashlib.sha256(file_data).hexdigest(),
                'timestamp': datetime.now().isoformat(),
                'agent_id': self.agent_id
            }
            
            # Создаем пакет: метаданные + данные
            packet = {
                'metadata': metadata,
                'data': base64.b64encode(encrypted_data).decode('utf-8')
            }
            
            packet_json = json.dumps(packet)
            packet_size = len(packet_json)
            
            print(f"📦 Подготовлен пакет: {packet_size} байт")
            print(f"   📁 Исходный размер: {len(file_data)} байт")
            print(f"   🔐 Зашифрованный: {len(encrypted_data)} байт")
            print(f"   📊 Коэффициент: {(len(encrypted_data)/len(file_data)):.2f}")
            
            # Подключаемся к серверу
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.server_ip, self.server_port))
            
            # Отправляем заголовок
            sock.send("SECURE_FILE".ljust(10).encode('utf-8'))
            
            # Отправляем размер пакета
            sock.send(f"{packet_size:<20}".encode('utf-8'))
            
            # Отправляем сам пакет
            total_sent = 0
            chunk_size = 4096
            
            while total_sent < packet_size:
                chunk = packet_json[total_sent:total_sent + chunk_size].encode('utf-8')
                sock.send(chunk)
                total_sent += len(chunk)
                
                percent = (total_sent / packet_size) * 100
                print(f"  📤 Отправлено: {percent:.1f}% ({total_sent}/{packet_size})", end='\r')
            
            print()
            
            # Получаем ответ
            sock.settimeout(5)
            response = sock.recv(4096).decode('utf-8')
            response_data = json.loads(response)
            
            sock.close()
            
            if response_data.get('status') == 'success':
                print(f"✅ Файл отправлен успешно!")
                print(f"   📝 {response_data.get('message')}")
                
                # Безопасное удаление исходного файла
                if response_data.get('verified', False):
                    self.secure_delete(file_path)
                    print(f"🗑️ Исходный файл безопасно удален")
                
                return True
            else:
                print(f"❌ Ошибка на сервере: {response_data.get('message')}")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка отправки файла: {e}")
            return False
    
    def secure_delete(self, file_path, passes=3):
        """
        Безопасное удаление файла
        
        Args:
            file_path: Путь к файлу
            passes: Количество проходов перезаписи
        """
        try:
            if not os.path.exists(file_path):
                return
            
            file_size = os.path.getsize(file_path)
            
            # Перезаписываем случайными данными
            with open(file_path, 'wb') as f:
                for i in range(passes):
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                    print(f"  🧹 Проход {i+1}/{passes}", end='\r')
            
            # Удаляем файл
            os.remove(file_path)
            print(f"\n✅ Файл безопасно удален: {file_path}")
            
        except Exception as e:
            print(f"⚠️ Не удалось безопасно удалить файл: {e}")
            # Пробуем обычное удаление
            try:
                os.remove(file_path)
            except:
                pass
    
    def test_connection(self):
        """Проверка подключения к серверу"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.server_ip, self.server_port))
            sock.close()
            return True
        except Exception as e:
            print(f"❌ Нет подключения к серверу: {e}")
            return False
    
    def collect_system_metrics(self):
        """Сбор метрик системы"""
        try:
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id,
                "hostname": socket.gethostname(),
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_total": psutil.virtual_memory().total,
                "memory_used": psutil.virtual_memory().used,
                "disk_usage": psutil.disk_usage('/').percent,
                "boot_time": psutil.boot_time(),
                "processes": len(psutil.pids()),
                "network_io": {
                    "bytes_sent": psutil.net_io_counters().bytes_sent,
                    "bytes_recv": psutil.net_io_counters().bytes_recv
                }
            }
            return metrics
        except Exception as e:
            print(f"❌ Ошибка сбора метрик: {e}")
            return {}
    
    def send_metrics(self):
        """Отправка метрик на сервер"""
        try:
            metrics = self.collect_system_metrics()
            if not metrics:
                return False
            
            # Создаем соединение
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.server_ip, self.server_port))
            
            # Отправляем заголовок
            sock.send("METRICS    ".encode('utf-8'))
            
            # Отправляем метрики как JSON
            metrics_json = json.dumps(metrics)
            sock.send(metrics_json.encode('utf-8'))
            
            sock.close()
            
            print(f"📊 Метрики отправлены: CPU={metrics['cpu_percent']}%, RAM={metrics['memory_percent']}%")
            return True
            
        except Exception as e:
            print(f"❌ Ошибка отправки метрик: {e}")
            return False
    
    def create_test_file(self):
        """Создание тестового файла для отправки"""
        test_content = f"""
        Тестовый архив Telegram
        Создан: {datetime.now()}
        Агент: {self.agent_id}
        Сервер: {self.server_ip}:{self.server_port}
        
        Это тестовый файл для проверки связи между ПК2 и ПК1.
        В реальной системе здесь будут архивы Telegram чатов.
        
        Конфиденциальная информация:
        - Логин: test_user
        - Пароль: не_хранить_в_открытом_виде
        - Токен: secret_token_12345
        """
        
        test_file = f"{self.temp_dir}/test_telegram_archive.txt"
        with open(test_file, "w", encoding="utf-8") as f:
            f.write(test_content)
        
        print(f"📝 Создан тестовый файл: {test_file}")
        return test_file
    
    def telegram_menu(self):
        """Меню управления Telegram архиватором"""
        try:
            from telegram_archiver import get_telegram_credentials, sync_download_channel
        except ImportError:
            print("❌ Модуль telegram_archiver не найден")
            print("👉 Убедись что файл telegram_archiver.py в той же папке")
            input("Нажми Enter чтобы продолжить...")
            return
        
        print("\n" + "=" * 60)
        print("📱 TELEGRAM АРХИВАТОР")
        print("=" * 60)
        
        # Получаем учетные данные
        api_id, api_hash = get_telegram_credentials()
        
        if not api_id or not api_hash:
            print("❌ Учетные данные Telegram не получены")
            input("Нажми Enter чтобы продолжить...")
            return
        
        while True:
            print("\nВыберите действие:")
            print("  [1] 📥 Скачать канал")
            print("  [2] 📤 Отправить архив на сервер (с шифрованием)")
            print("  [3] 📤 Отправить архив БЕЗ шифрования")
            print("  [4] 🔐 Показать/сменить ключ шифрования")
            print("  [B] ↩️ Назад")
            
            choice = input("> ").lower()
            
            if choice == 'b':
                break
            elif choice == '1':
                channel = input("Введите ссылку на канал (например @durov): ").strip()
                limit = input("Сколько сообщений скачать? (по умолчанию 100): ").strip()
                limit = int(limit) if limit.isdigit() else 100
                
                if channel:
                    print(f"🚀 Начинаю скачивание: {channel}")
                    archive_path = sync_download_channel(api_id, api_hash, channel, limit)
                    
                    if archive_path:
                        print(f"✅ Архив создан: {archive_path}")
                        
                        # Спросим, отправить ли на сервер
                        send = input("Отправить архив на сервер ПК1? (y/n): ").lower()
                        if send == 'y':
                            use_encryption = input("Использовать шифрование? (y/n): ").lower()
                            if use_encryption == 'y':
                                if self.secure_send_file(archive_path, "TELEGRAM"):
                                    print("✅ Архив отправлен на сервер с шифрованием!")
                                else:
                                    print("❌ Ошибка отправки архива")
                            else:
                                # Старый метод без шифрования
                                self._send_file_old(archive_path, "TELEGRAM")
                    else:
                        print("❌ Не удалось скачать канал")
                
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '2':
                import glob
                archives = glob.glob("./telegram_archives/*.zip")
                
                if archives:
                    print("📁 Найденные архивы:")
                    for i, archive in enumerate(archives, 1):
                        size = os.path.getsize(archive) // 1024
                        print(f"  [{i}] {os.path.basename(archive)} ({size} KB)")
                    
                    file_num = input("Выберите номер файла: ").strip()
                    if file_num.isdigit() and 1 <= int(file_num) <= len(archives):
                        archive_path = archives[int(file_num)-1]
                        self.secure_send_file(archive_path, "TELEGRAM")
                    else:
                        print("❌ Неверный выбор")
                else:
                    print("📭 Архивы не найдены")
                
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '3':
                import glob
                archives = glob.glob("./telegram_archives/*.zip")
                
                if archives:
                    print("📁 Найденные архивы:")
                    for i, archive in enumerate(archives, 1):
                        size = os.path.getsize(archive) // 1024
                        print(f"  [{i}] {os.path.basename(archive)} ({size} KB)")
                    
                    file_num = input("Выберите номер файла: ").strip()
                    if file_num.isdigit() and 1 <= int(file_num) <= len(archives):
                        archive_path = archives[int(file_num)-1]
                        self._send_file_old(archive_path, "TELEGRAM")
                    else:
                        print("❌ Неверный выбор")
                else:
                    print("📭 Архивы не найдены")
                
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '4':
                print(f"\n🔑 Текущий ключ шифрования: {'ЕСТЬ' if self.encryption_key else 'НЕТ'}")
                if self.encryption_key:
                    print(f"   Хэш ключа: {hashlib.sha256(self.encryption_key).hexdigest()[:16]}...")
                
                change = input("Сгенерировать новый ключ? (y/n): ").lower()
                if change == 'y':
                    key = Fernet.generate_key()
                    with open("./encryption_key.key", 'wb') as f:
                        f.write(key)
                    self.encryption_key = key
                    print("✅ Новый ключ сгенерирован и сохранен")
                
                input("\nНажми Enter чтобы продолжить...")
    
    def _send_file_old(self, file_path, file_type):
        """Старый метод отправки файла без шифрования (для обратной совместимости)"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_size = len(file_data)
            filename = os.path.basename(file_path)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.server_ip, self.server_port))
            
            header = f"{file_type:<10}"
            sock.send(header.encode('utf-8'))
            
            size_header = f"{file_size:<20}"
            sock.send(size_header.encode('utf-8'))
            
            name_header = f"{filename:<100}"
            sock.send(name_header.encode('utf-8'))
            
            total_sent = 0
            chunk_size = 4096
            
            while total_sent < file_size:
                chunk = file_data[total_sent:total_sent + chunk_size]
                sock.send(chunk)
                total_sent += len(chunk)
                
                percent = (total_sent / file_size) * 100
                print(f"  📤 Отправлено: {percent:.1f}% ({total_sent}/{file_size})", end='\r')
            
            print()
            
            sock.settimeout(5)
            response = sock.recv(4096).decode('utf-8')
            response_data = json.loads(response)
            
            sock.close()
            
            if response_data.get('status') == 'success':
                print(f"✅ Файл отправлен (без шифрования)")
                return True
            else:
                print(f"❌ Ошибка: {response_data.get('message')}")
                return False
                
        except Exception as e:
            print(f"❌ Ошибка отправки файла: {e}")
            return False
    
    def run_menu(self):
        """Запуск меню управления агентом"""
        while self.running:
            print("\n" + "=" * 60)
            print("          🎮 МЕНЮ УПРАВЛЕНИЯ АГЕНТОМ")
            print("=" * 60)
            print(f"Сервер: {self.server_ip}:{self.server_port}")
            print(f"Агент: {self.agent_id}")
            print(f"Шифрование: {'🟢 ВКЛ' if self.encryption_key else '🔴 ВЫКЛ'}")
            print("-" * 60)
            
            # Проверка связи
            if self.test_connection():
                print("📡 Связь с сервером: 🟢 ОК")
            else:
                print("📡 Связь с сервером: 🔴 НЕТ")
            
            print("-" * 60)
            print("Выберите действие:")
            print("  [1] 📊 Отправить метрики системы")
            print("  [2] 📁 Отправить тестовый файл (с шифрованием)")
            print("  [3] 📁 Отправить свой файл (с шифрованием)")
            print("  [4] 🔄 Автоматическая отправка метрик")
            print("  [5] 🛠️  Создать тестовый файл")
            print("  [6] ℹ️  Информация о системе")
            print("  [7] 📱 Telegram архиватор (основное)")
            print("  [8] 🔐 Настройки безопасности")
            print("  [Q] 🚪 Выход")
            print("=" * 60)
            
            choice = input("> ").lower()
            
            if choice == 'q':
                self.running = False
                print("🛑 Останавливаю агент...")
                break
            elif choice == '1':
                self.send_metrics()
                input("Нажми Enter чтобы продолжить...")
            elif choice == '2':
                test_file = self.create_test_file()
                self.secure_send_file(test_file, "TELEGRAM")
                input("Нажми Enter чтобы продолжить...")
            elif choice == '3':
                filepath = input("Введите путь к файлу: ").strip()
                if os.path.exists(filepath):
                    self.secure_send_file(filepath, "TELEGRAM")
                else:
                    print("❌ Файл не найден!")
                input("Нажми Enter чтобы продолжить...")
            elif choice == '4':
                self.auto_send_metrics()
            elif choice == '5':
                test_file = self.create_test_file()
                print(f"✅ Файл создан: {test_file}")
                input("Нажми Enter чтобы продолжить...")
            elif choice == '6':
                self.show_system_info()
            elif choice == '7':
                self.telegram_menu()
            elif choice == '8':
                self.security_menu()
            else:
                print("❌ Неверный выбор")
                time.sleep(1)
    
    def security_menu(self):
        """Меню настроек безопасности"""
        while True:
            print("\n" + "=" * 60)
            print("🔐 НАСТРОЙКИ БЕЗОПАСНОСТИ")
            print("=" * 60)
            print(f"Ключ шифрования: {'🟢 АКТИВЕН' if self.encryption_key else '🔴 ОТСУТСТВУЕТ'}")
            if self.encryption_key:
                key_hash = hashlib.sha256(self.encryption_key).hexdigest()
                print(f"Хэш ключа: {key_hash[:16]}...{key_hash[-16:]}")
            
            print("\nВыберите действие:")
            print("  [1] 🔑 Показать информацию о ключе")
            print("  [2] 🆕 Сгенерировать новый ключ")
            print("  [3] 🗑️  Удалить ключ (отключить шифрование)")
            print("  [4] 🧹 Безопасно удалить файл")
            print("  [5] 🧪 Проверить шифрование")
            print("  [B] ↩️ Назад")
            print("=" * 60)
            
            choice = input("> ").lower()
            
            if choice == 'b':
                break
            elif choice == '1':
                if self.encryption_key:
                    print(f"\n🔑 Информация о ключе:")
                    print(f"   Длина: {len(self.encryption_key)} байт")
                    print(f"   Base64: {base64.b64encode(self.encryption_key).decode()[:50]}...")
                    print(f"   SHA256: {hashlib.sha256(self.encryption_key).hexdigest()}")
                else:
                    print("❌ Ключ не установлен")
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '2':
                confirm = input("⚠️  Старый ключ будет удален. Продолжить? (y/n): ").lower()
                if confirm == 'y':
                    key = Fernet.generate_key()
                    with open("./encryption_key.key", 'wb') as f:
                        f.write(key)
                    self.encryption_key = key
                    print("✅ Новый ключ сгенерирован!")
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '3':
                confirm = input("⚠️  Шифрование будет отключено. Продолжить? (y/n): ").lower()
                if confirm == 'y':
                    if os.path.exists("./encryption_key.key"):
                        self.secure_delete("./encryption_key.key")
                    self.encryption_key = None
                    print("✅ Ключ удален, шифрование отключено")
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '4':
                filepath = input("Введите путь к файлу для безопасного удаления: ").strip()
                if os.path.exists(filepath):
                    self.secure_delete(filepath)
                else:
                    print("❌ Файл не найден")
                input("\nНажми Enter чтобы продолжить...")
                
            elif choice == '5':
                # Тест шифрования
                test_data = b"Test data for encryption " + os.urandom(100)
                print(f"\n🧪 Тестирую шифрование...")
                print(f"   Исходные данные: {len(test_data)} байт")
                
                encrypted, key = self.encrypt_data(test_data)
                print(f"   Зашифровано: {len(encrypted)} байт")
                
                if key:
                    decrypted = self.decrypt_data(encrypted)
                    print(f"   Расшифровано: {len(decrypted)} байт")
                    
                    if test_data == decrypted:
                        print("✅ Шифрование работает корректно!")
                    else:
                        print("❌ Ошибка: данные не совпадают после расшифровки")
                else:
                    print("⚠️  Шифрование отключено")
                
                input("\nНажми Enter чтобы продолжить...")
    
    def auto_send_metrics(self):
        """Автоматическая отправка метрик"""
        print("\n🔄 Автоматическая отправка метрик каждые 30 секунд")
        print("Нажми Ctrl+C для остановки")
        
        try:
            count = 0
            while count < 10:
                if self.send_metrics():
                    count += 1
                    print(f"🔄 Отправлено: {count}/10")
                
                for i in range(30, 0, -1):
                    print(f"  Следующая отправка через: {i} сек", end='\r')
                    time.sleep(1)
                print()
                
        except KeyboardInterrupt:
            print("\n⏹️  Автоматическая отправка остановлена")
    
    def show_system_info(self):
        """Показать информацию о системе"""
        print("\n" + "=" * 60)
        print("ℹ️  ИНФОРМАЦИЯ О СИСТЕМЕ")
        print("=" * 60)
        
        metrics = self.collect_system_metrics()
        if metrics:
            print(f"Хост: {metrics['hostname']}")
            print(f"CPU: {metrics['cpu_percent']}%")
            print(f"RAM: {metrics['memory_percent']}% ({metrics['memory_used']//(1024**3)}/{metrics['memory_total']//(1024**3)} GB)")
            print(f"Диск: {metrics['disk_usage']}%")
            print(f"Процессы: {metrics['processes']}")
            print(f"Время работы: {time.time() - metrics['boot_time']:.0f} сек")
        
        print("-" * 60)
        input("Нажми Enter чтобы продолжить...")

if __name__ == "__main__":
    # Настройки
    SERVER_IP = "192.168.1.100"  # ЗАМЕНИ НА РЕАЛЬНЫЙ IP ПК1
    SERVER_PORT = 9090
    
    # Создаем и запускаем агента
    agent = SystemAgent(server_ip=SERVER_IP, server_port=SERVER_PORT)
    agent.run_menu()