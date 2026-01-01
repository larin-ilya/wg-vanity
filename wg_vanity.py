import base64
import multiprocessing as mp
import os
import sys
import time
import qrcode
import configparser
from datetime import datetime, timedelta
from nacl import public, utils
from typing import Optional, List, Dict
import argparse
import random
from PIL import ImageDraw, ImageFont
import colorsys

# ДОПУСТИМЫЕ ЗАМЕНЫ
CHAR_SUBS = {
    "a": ["a", "A", "4"],
    "b": ["b", "B", "8"],
    "c": ["c", "C"],
    "d": ["d", "D", "9"],
    "e": ["e", "E", "3"],
    "f": ["f", "F"],
    "g": ["g", "G", "9", "6"],
    "h": ["h", "H"],
    "i": ["i", "I", "1", "l"],
    "j": ["j", "J"],
    "k": ["k", "K"],
    "l": ["l", "L", "1", "I"],
    "m": ["m", "M"],
    "n": ["n", "N"],
    "o": ["o", "O", "0"],
    "p": ["p", "P"],
    "q": ["q", "Q"],
    "r": ["r", "R"],
    "s": ["s", "S", "5"],
    "t": ["t", "T", "7", "+"],
    "u": ["u", "U"],
    "v": ["v", "V"],
    "w": ["w", "W"],
    "x": ["x", "X"],
    "y": ["y", "Y"],
    "z": ["z", "Z", "2"],
    "0": ["0", "O", "o"],
    "1": ["1", "l", "I", "i"],
    "2": ["2", "z", "Z"],
    "3": ["3", "e", "E"],
    "4": ["4", "a", "A"],
    "5": ["5", "s", "S"],
    "6": ["6", "b", "B", "g", "G"],
    "7": ["7", "T"],
    "8": ["8", "B"],
    "9": ["9", "g"],
}

class KeyGenerator:
    """Класс для генерации префиксов"""
    
    def __init__(self, base_word: str, strict_mode: bool = False):
        self.base_word = base_word.lower()
        self.strict_mode = strict_mode
        self.target_prefixes = self._generate_prefixes()
        self.target_prefixes_list = list(self.target_prefixes)
        
    def _generate_prefixes(self) -> set:
        """Генерация всех возможных вариантов префиксов"""
        variants = [""]
        
        for char in self.base_word:
            new_variants = []
            
            if self.strict_mode:
                # В строгом режиме используем только сам символ (без замен)
                replacements = [char]
            else:
                # В обычном режиме используем все возможные замены
                replacements = CHAR_SUBS.get(char, [char])
            
            for variant in variants:
                for replacement in replacements:
                    new_variants.append(variant + replacement)
            variants = new_variants
        
        return {v.encode() for v in variants}

def worker_process(worker_id: int, target_prefixes_list: List[bytes], 
                   found_event: mp.Event, counter: mp.Value, result_queue: mp.Queue,
                   strict_mode: bool = False):
    """Процесс-работник для генерации и проверки ключей"""
    try:
        keys_checked = 0
        decoded_prefixes = {p: p.decode() for p in target_prefixes_list}
        
        while not found_event.is_set():
            # Генерируем пару ключей
            private_key = utils.random(32)
            public_key = public.PrivateKey(private_key).public_key
            public_b64 = base64.b64encode(bytes(public_key))
            
            keys_checked += 1
            
            # Обновление счетчика каждые 1000 ключей
            if keys_checked % 1000 == 0:
                with counter.get_lock():
                    counter.value += 1000
            
            # Проверка на совпадение с любым префиксом
            public_str = public_b64.decode()
            
            if strict_mode:
                # В строгом режиме ищем точное совпадение слова
                for prefix in target_prefixes_list:
                    prefix_str = prefix.decode()
                    if public_str.startswith(prefix_str):
                        result = {
                            'private_key': base64.b64encode(private_key).decode(),
                            'public_key': public_str,
                            'prefix': prefix_str,
                            'worker_id': worker_id,
                            'keys_checked': keys_checked,
                            'timestamp': datetime.now(),
                            'strict_mode': True
                        }
                        result_queue.put(result)
                        found_event.set()
                        return
            else:
                # В обычном режиме используем байтовую проверку для скорости
                for prefix in target_prefixes_list:
                    if public_b64.startswith(prefix):
                        result = {
                            'private_key': base64.b64encode(private_key).decode(),
                            'public_key': public_str,
                            'prefix': decoded_prefixes[prefix],
                            'worker_id': worker_id,
                            'keys_checked': keys_checked,
                            'timestamp': datetime.now(),
                            'strict_mode': False
                        }
                        result_queue.put(result)
                        found_event.set()
                        return
    
    except Exception as e:
        print(f"[Worker {worker_id}] Ошибка: {e}")
    finally:
        # Добавить оставшиеся ключи в счетчик
        with counter.get_lock():
            counter.value += (keys_checked % 1000)

class StatsMonitor:
    """Мониторинг статистики поиска"""
    
    def __init__(self, counter: mp.Value, start_time: datetime):
        self.counter = counter
        self.start_time = start_time
        self.last_count = 0
        self.peak_speed = 0
        
    def update(self):
        """Обновление и вывод статистики"""
        with self.counter.get_lock():
            current_count = self.counter.value
        
        elapsed = (datetime.now() - self.start_time).total_seconds()
        current_speed = current_count - self.last_count
        
        if current_speed > self.peak_speed:
            self.peak_speed = current_speed
        
        avg_speed = current_count / elapsed if elapsed > 0 else 0
        estimated_time = self._calculate_eta(current_count, avg_speed)
        
        self._print_stats(current_count, current_speed, avg_speed, 
                         self.peak_speed, estimated_time, elapsed)
        
        self.last_count = current_count
    
    def _calculate_eta(self, current_count: int, avg_speed: float) -> Optional[timedelta]:
        """Расчет примерного времени до нахождения"""
        if current_count > 1000 and avg_speed > 0:
            probability = 1 / (64 ** 6 / 2)
            expected_keys = 1 / probability
            remaining = max(0, expected_keys - current_count)
            estimated_seconds = remaining / avg_speed
            return timedelta(seconds=int(estimated_seconds))
        return None
    
    def _print_stats(self, total: int, current_speed: int, avg_speed: float, 
                    peak_speed: int, estimated_time: Optional[timedelta], elapsed: float):
        """Вывод статистики в консоль"""
        elapsed_td = timedelta(seconds=int(elapsed))
        stats_line = (
            f"\r💻 CPU | Время: {elapsed_td} | "
            f"Всего: {total:,} | "
            f"Сейчас: {current_speed:,}/сек | "
            f"Средняя: {avg_speed:,.0f}/сек | "
            f"Пик: {peak_speed:,}/сек"
        )
        
        if estimated_time:
            stats_line += f" | ETA: {estimated_time}"
        
        sys.stdout.write(stats_line.ljust(160))
        sys.stdout.flush()

def load_config():
    """Загрузка конфигурации из config.ini"""
    config = configparser.ConfigParser()
    
    # Значения по умолчанию
    defaults = {
        'server': {
            'public_key': '',
            'endpoint': '',
            'allowed_ips': '0.0.0.0/0',
            'dns': '1.1.1.1, 8.8.8.8'
        }
    }
    
    config.read_dict(defaults)
    
    # Пытаемся загрузить из файла
    config_file = 'config.ini'
    if os.path.exists(config_file):
        config.read(config_file)
        print(f"📁 Загружена конфигурация из {config_file}")
    
    return config

def save_config(config):
    """Сохранение конфигурации в config.ini"""
    config_file = 'config.ini'
    with open(config_file, 'w') as f:
        config.write(f)
    print(f"💾 Конфигурация сохранена в {config_file}")

def get_server_config():
    """Получение данных сервера (из файла или запрос у пользователя)"""
    config = load_config()
    
    print("\n" + "="*60)
    print("⚙️  НАСТРОЙКА СЕРВЕРА WIREGUARD")
    print("="*60)
    
    # Публичный ключ сервера
    server_public_key = config.get('server', 'public_key', fallback='').strip()
    if not server_public_key:
        print("❓ Публичный ключ сервера не найден в config.ini")
        while True:
            server_public_key = input("Введите публичный ключ сервера: ").strip()
            if server_public_key and len(server_public_key) >= 40:
                try:
                    base64.b64decode(server_public_key + '==')
                    # Сохраняем в конфиг
                    config.set('server', 'public_key', server_public_key)
                    save_config(config)
                    break
                except:
                    print("⚠️  Неверный формат ключа. Должен быть base64.")
            else:
                print("⚠️  Публичный ключ не может быть пустым.")
    else:
        print(f"✅ Публичный ключ сервера загружен из config.ini")
    
    # Endpoint сервера
    endpoint = config.get('server', 'endpoint', fallback='').strip()
    if not endpoint:
        print("❓ Endpoint сервера не найден в config.ini")
        while True:
            endpoint = input("Введите Endpoint сервера (пример: vpn.example.com:51820): ").strip()
            if endpoint and ':' in endpoint:
                host, port = endpoint.split(':', 1)
                if port.isdigit() and 1 <= int(port) <= 65535:
                    # Сохраняем в конфиг
                    config.set('server', 'endpoint', endpoint)
                    save_config(config)
                    break
                else:
                    print("⚠️  Неверный порт. Должен быть от 1 до 65535.")
            else:
                print("⚠️  Endpoint должен быть в формате host:port")
    else:
        print(f"✅ Endpoint загружен из config.ini: {endpoint}")
    
    # AllowedIPs - ВСЕГДА из конфига (не спрашиваем)
    allowed_ips = config.get('server', 'allowed_ips', fallback='0.0.0.0/0').strip()
    print(f"✅ AllowedIPs из config.ini: {allowed_ips}")
    
    # DNS серверы - ВСЕГДА из конфига
    dns = config.get('server', 'dns', fallback='1.1.1.1, 8.8.8.8').strip()
    print(f"✅ DNS серверы из config.ini: {dns}")
    
    # Адрес клиента - ВСЕГДА случайный в диапазоне 31-254 (НЕ СПРАШИВАЕМ)
    client_address = f"10.0.0.{random.randint(31, 254)}/32"
    print(f"✅ Адрес клиента (случайный): {client_address}")
    
    return {
        'server_public_key': server_public_key,
        'endpoint': endpoint,
        'allowed_ips': allowed_ips,  # Всегда из конфига
        'client_address': client_address,  # Всегда случайный 31-254
        'dns': dns,  # Всегда из конфига
        'config': config
    }

def random_dark_color_hsv():
    """Генерирует темный цвет через HSV"""
    h = random.random()
    s = random.uniform(0.7, 1.0)
    v = random.uniform(0.2, 0.5)
    
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    return (int(r * 255), int(g * 255), int(b * 255))

def save_found_key(result: dict, base_word: str, server_config: dict = None):
    """Сохранение найденных ключей в файлы"""
    timestamp = result['timestamp'].strftime("%Y%m%d_%H%M%S")
    mode = "strict" if result.get('strict_mode', False) else "normal"
    prefix = result['prefix']
    
    # 1. Сохранение в ОБЩИЙ лог-файл (все ключи всех префиксов в одном файле)
    log_filename = "wg_keys_log.txt"
    
    try:
        # Проверяем, существует ли лог-файл
        file_exists = os.path.exists(log_filename)
        
        with open(log_filename, 'a', encoding='utf-8') as f:
            if not file_exists:
                f.write("=" * 80 + "\n")
                f.write("ЛОГ НАЙДЕННЫХ КЛЮЧЕЙ WIREGUARD\n")
                f.write(f"Создан: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 80 + "\n\n")
            
            # Запись новой найденной пары ключей
            f.write(f"[{result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}]\n")
            f.write(f"Слово: {base_word}\n")
            f.write(f"Режим: {'СТРОГИЙ' if result.get('strict_mode', False) else 'ОБЫЧНЫЙ'}\n")
            f.write(f"Префикс: {prefix}\n")
            f.write(f"Публичный ключ:  {result['public_key']}\n")
            f.write(f"Приватный ключ:  {result['private_key']}\n")
            f.write(f"Процесс: {result['worker_id']} | Проверено: {result['keys_checked']:,}\n")
            f.write(f"Адрес клиента:   {server_config['client_address']}\n")
            f.write(f"AllowedIPs:       {server_config['allowed_ips']}\n")
            f.write(f"Endpoint сервера: {server_config['endpoint']}\n")
            f.write("-" * 80 + "\n\n")
        
        print(f"\n✅ Ключи добавлены в общий лог-файл: {log_filename}")
    except Exception as e:
        print(f"Ошибка при сохранении в лог-файл: {e}")
    
    # 2. Создание отдельных файлов для текущего найденного ключа
    base_filename = f"wg_{base_word}_{prefix}_{timestamp}"
    
    # Файл с конфигурацией (conf)
    conf_filename = f"{base_filename}.conf"
    try:
        with open(conf_filename, 'w', encoding='utf-8') as f:
            f.write("[Interface]\n")
            f.write(f"PrivateKey = {result['private_key']}\n")
            f.write(f"Address = {server_config['client_address']}\n")
            f.write(f"DNS = {server_config['dns']}\n\n")
            f.write("[Peer]\n")
            f.write(f"PublicKey = {server_config['server_public_key']}\n")
            f.write(f"Endpoint = {server_config['endpoint']}\n")
            f.write(f"AllowedIPs = {server_config['allowed_ips']}\n")
            f.write("PersistentKeepalive = 25\n")
        
        print(f"✅ Конфигурация сохранена: {conf_filename}")
    except Exception as e:
        print(f"Ошибка при создании конфигурационного файла: {e}")
    
    # 3. Создание QR-кода с надписью префикса
    qr_filename = f"{base_filename}_qr.png"
    try:
        # Используем полную конфигурацию для QR-кода
        qr_data = f"[Interface]\n"
        qr_data += f"PrivateKey = {result['private_key']}\n"
        qr_data += f"Address = {server_config['client_address']}\n"
        qr_data += f"DNS = {server_config['dns']}\n\n"
        qr_data += f"[Peer]\n"
        qr_data += f"PublicKey = {server_config['server_public_key']}\n"
        qr_data += f"Endpoint = {server_config['endpoint']}\n"
        qr_data += f"AllowedIPs = {server_config['allowed_ips']}\n"
        qr_data += f"PersistentKeepalive = 25"
        
        qr = qrcode.QRCode(
            version=None,  # Автоподбор версии
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        # Генерация случайного темного цвета
        fill_color = random_dark_color_hsv()
        
        # Создаем изображение QR-кода
        img = qr.make_image(fill_color=fill_color, back_color="white")
        img = img.convert('RGB')
        
        # Добавляем текст с префиксом
        draw = ImageDraw.Draw(img)
        
        # Пытаемся использовать красивый шрифт
        font = None
        fonts_to_try = ["arial.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf", "Verdana.ttf"]
        
        for font_name in fonts_to_try:
            try:
                font = ImageFont.truetype(font_name, 24)
                break
            except:
                continue
        
        if font is None:
            # Используем стандартный шрифт
            try:
                font = ImageFont.load_default()
            except:
                pass
        
        # Получаем размеры изображения
        width, height = img.size
        
        # Текст для отображения
        text = f"wg:{prefix}"
        
        # Получаем размер текста
        if font:
            try:
                text_bbox = draw.textbbox((0, 0), text, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_height = text_bbox[3] - text_bbox[1]
            except:
                text_width = len(text) * 15
                text_height = 20
            
            # Позиция текста (центр внизу)
            text_x = (width - text_width) // 2
            text_y = height - text_height - 15
            
            # Добавляем белый фон для текста
            padding = 6
            draw.rectangle(
                [text_x - padding, text_y - padding, 
                 text_x + text_width + padding, text_y + text_height + padding],
                fill=(255, 255, 255)
            )
            
            # Добавляем текст
            draw.text(
                (text_x, text_y),
                text,
                font=font,
                fill=fill_color
            )
        
        # Сохраняем результат
        img.save(qr_filename)
        
        print(f"✅ QR-код сохранен: {qr_filename}")
    except Exception as e:
        print(f"Ошибка при создании QR-кода: {e}")
        import traceback
        traceback.print_exc()
    
    # 4. Отдельный файл только с ключами (txt)
    keys_filename = f"{base_filename}_keys.txt"
    try:
        with open(keys_filename, 'w', encoding='utf-8') as f:
            f.write(f"WireGuard ключи - {base_word}\n")
            f.write(f"Префикс: {prefix}\n")
            f.write(f"Дата: {result['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Режим: {'СТРОГИЙ' if result.get('strict_mode', False) else 'ОБЫЧНЫЙ'}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Публичный ключ клиента:\n{result['public_key']}\n\n")
            f.write(f"Приватный ключ клиента:\n{result['private_key']}\n\n")
            f.write(f"Публичный ключ сервера:\n{server_config['server_public_key']}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Endpoint сервера: {server_config['endpoint']}\n")
            f.write(f"Адрес клиента: {server_config['client_address']}\n")
            f.write(f"AllowedIPs: {server_config['allowed_ips']}\n")
            f.write(f"DNS: {server_config['dns']}\n")
        
        print(f"✅ Текстовый файл с ключами: {keys_filename}")
    except Exception as e:
        print(f"Ошибка при создании файла с ключами: {e}")

def print_result(result: dict, total_time: timedelta, total_keys: int):
    """Красивый вывод результата"""
    mode_text = "СТРОГИЙ РЕЖИМ" if result.get('strict_mode', False) else "ОБЫЧНЫЙ РЕЖИМ"
    print(f"\n\n{'='*60}")
    print(f"✅ НАЙДЕН СОВПАДАЮЩИЙ КЛЮЧ! ({mode_text})")
    print(f"{'='*60}")
    print(f"Режим поиска:   {'Строгий' if result.get('strict_mode', False) else 'Обычный'}")
    print(f"Префикс:       {result['prefix']}")
    print(f"Публичный:     {result['public_key']}")
    print(f"Приватный:     {result['private_key']}")
    print(f"Процесс:       {result['worker_id']}")
    print(f"Проверено:     {result['keys_checked']:,} ключей")
    print(f"Общее время:   {total_time}")
    print(f"Всего ключей:  {total_keys:,}")
    if total_time.total_seconds() > 0:
        print(f"Средняя скорость: {total_keys / total_time.total_seconds():,.0f}/сек")
    print(f"{'='*60}\n")

def main():
    """Основная функция программы"""
    parser = argparse.ArgumentParser(
        description='Поиск публичного ключа с заданным префиксом (CPU оптимизированная версия)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Примеры использования:
  python wg_vanity.py -w lenovo                     # Обычный режим с заменами
  python wg_vanity.py --word "my_prefix" --strict   # Строгий режим без замен
  python wg_vanity.py -w bitcoin --strict --workers 4
  python wg_vanity.py -w test --save
  
При флаге --save создаются:
  1. wg_keys_log.txt - общий лог ВСЕХ найденных ключей (всех префиксов)
  2. wg_<word>_<prefix>_<timestamp>.conf - конфигурация WireGuard
  3. wg_<word>_<prefix>_<timestamp>_qr.png - QR-код с надписью префикса
  4. wg_<word>_<prefix>_<timestamp>_keys.txt - текстовый файл с ключами
  
Конфигурационный файл config.ini:
  • Если файл существует, настройки загружаются из него
  • Если настроек нет, программа запросит их и сохранит
  • Формат config.ini:
    [server]
    public_key = ваш_публичный_ключ_сервера
    endpoint = vpn.example.com:51820
    allowed_ips = 0.0.0.0/0
    dns = 1.1.1.1, 8.8.8.8
  
Настройки по умолчанию:
  • AllowedIPs: всегда из config.ini (не спрашивается)
  • DNS: всегда из config.ini (не спрашивается)
  • Адрес клиента: всегда случайный 10.0.0.31-254/32 (не спрашивается)
        '''
    )
    parser.add_argument('-w', '--word', type=str, required=True,
                       help='Базовое слово для генерации префиксов (обязательно)')
    parser.add_argument('--strict', action='store_true',
                       help='Строгий режим поиска (без замен символов)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Количество рабочих процессов (по умолчанию - кол-во CPU)')
    parser.add_argument('-s', '--save', action='store_true',
                       help='Сохранять результаты в файлы (использует/создает config.ini)')
    
    args = parser.parse_args()
    
    base_word = args.word.strip()
    
    if not base_word:
        print("Ошибка: слово не может быть пустым!")
        sys.exit(1)
    
    # Запрашиваем данные сервера если нужно сохранять
    server_config = None
    if args.save:
        server_config = get_server_config()
        print(f"\n✅ Данные сервера получены:")
        print(f"   Endpoint: {server_config['endpoint']}")
        print(f"   Адрес клиента: {server_config['client_address']} (случайный)")
        print(f"   AllowedIPs: {server_config['allowed_ips']}")
        print(f"   DNS: {server_config['dns']}")
    
    print(f"\n{'='*60}")
    print("🔍 ПОИСК КЛЮЧЕЙ WIREGUARD С ЗАДАННЫМ ПРЕФИКСОМ")
    print(f"{'='*60}\n")
    
    generator = KeyGenerator(base_word, strict_mode=args.strict)
    target_prefixes_list = list(generator.target_prefixes)
    
    worker_count = args.workers if args.workers else os.cpu_count()
    
    print(f"Базовое слово:         {base_word}")
    print(f"Режим поиска:          {'Строгий (без замен символов)' if args.strict else 'Обычный (с заменами символов)'}")
    print(f"Сгенерировано префиксов: {len(target_prefixes_list)}")
    if not args.strict and len(target_prefixes_list) > 1:
        print(f"  (включая варианты с заменой символов)")
    print(f"Рабочих процессов:     {worker_count}")
    if args.save:
        print(f"Сохранение:           ВКЛЮЧЕНО")
        print(f"Лог-файл:            wg_keys_log.txt (общий для всех префиксов)")
        print(f"Конфиг:              config.ini (загружены настройки сервера)")
    print(f"{'='*60}")
    print("Начинаю поиск... (Ctrl+C для остановки)\n")
    
    found_event = mp.Event()
    counter = mp.Value('Q', 0)
    result_queue = mp.Queue()
    start_time = datetime.now()
    
    processes = []
    
    try:
        # Запуск всех рабочих процессов
        for i in range(worker_count):
            process = mp.Process(
                target=worker_process,
                args=(i + 1, target_prefixes_list, found_event, counter, result_queue, args.strict),
                daemon=False
            )
            processes.append(process)
            process.start()
        
        monitor = StatsMonitor(counter, start_time)
        
        # Мониторинг прогресса
        while not found_event.is_set():
            monitor.update()
            time.sleep(1)
        
        # Дождаться завершения процессов
        for process in processes:
            process.join(timeout=2)
        
    except KeyboardInterrupt:
        print("\n\n⛔ Программа остановлена пользователем")
        found_event.set()
        
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=1)
    
    finally:
        total_time = datetime.now() - start_time
        with counter.get_lock():
            total_keys = counter.value
        
        if not result_queue.empty():
            result = result_queue.get()
            print_result(result, total_time, total_keys)
            if args.save and server_config:
                save_found_key(result, base_word, server_config)
        else:
            print(f"\n\n{'='*60}")
            print("📊 ИТОГИ ПОИСКА")
            print(f"{'='*60}")
            print(f"Режим поиска:       {'Строгий' if args.strict else 'Обычный'}")
            print(f"Общее время:        {total_time}")
            print(f"Всего ключей:       {total_keys:,}")
            if total_time.total_seconds() > 0:
                print(f"Средняя скорость:   {total_keys / total_time.total_seconds():,.0f}/сек")
            print(f"{'='*60}\n")

if __name__ == "__main__":
    mp.freeze_support()
    main()
