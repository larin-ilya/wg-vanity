import base64
import multiprocessing as mp
import os
import sys
import time
from datetime import datetime, timedelta
from nacl import public, utils
from typing import Optional, List
import argparse

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
    "7": ["7", "t", "T"],
    "8": ["8", "b", "B"],
    "9": ["9", "g", "G"],
}

class KeyGenerator:
    """Класс для генерации префиксов"""
    
    def __init__(self, base_word: str):
        self.base_word = base_word.lower()
        self.target_prefixes = self._generate_prefixes()
        self.target_prefixes_list = list(self.target_prefixes)
        
    def _generate_prefixes(self) -> set:
        """Генерация всех возможных вариантов префиксов"""
        variants = [""]
        
        for char in self.base_word:
            new_variants = []
            replacements = CHAR_SUBS.get(char, [char])
            
            for variant in variants:
                for replacement in replacements:
                    new_variants.append(variant + replacement)
            variants = new_variants
        
        return {v.encode() for v in variants}

def worker_process(worker_id: int, target_prefixes_list: List[bytes], 
                   found_event: mp.Event, counter: mp.Value, result_queue: mp.Queue):
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
            for prefix in target_prefixes_list:
                if public_b64.startswith(prefix):
                    result = {
                        'private_key': base64.b64encode(private_key).decode(),
                        'public_key': public_b64.decode(),
                        'prefix': decoded_prefixes[prefix],
                        'worker_id': worker_id,
                        'keys_checked': keys_checked,
                        'timestamp': datetime.now()
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

def save_found_key(result: dict):
    """Сохранение найденных ключей в файл"""
    timestamp = result['timestamp'].strftime("%Y%m%d_%H%M%S")
    filename = f"found_key_{timestamp}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write(f"Найден совпадающий ключ - {result['timestamp']}\n")
            f.write("=" * 60 + "\n")
            f.write(f"Искомый префикс:  {result['prefix']}\n")
            f.write(f"Публичный ключ:   {result['public_key']}\n")
            f.write(f"Приватный ключ:   {result['private_key']}\n")
            f.write(f"Процесс:          {result['worker_id']}\n")
            f.write(f"Проверено ключей: {result['keys_checked']:,}\n")
            f.write("=" * 60 + "\n")
        
        print(f"\nКлючи сохранены в файл: {filename}")
    except Exception as e:
        print(f"Ошибка при сохранении в файл: {e}")

def print_result(result: dict, total_time: timedelta, total_keys: int):
    """Красивый вывод результата"""
    print(f"\n\n{'='*60}")
    print("✅ НАЙДЕН СОВПАДАЮЩИЙ КЛЮЧ!")
    print(f"{'='*60}")
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
  python script.py -w lenovo
  python script.py --word "my_prefix" --workers 4
  python script.py -w bitcoin --save
        '''
    )
    parser.add_argument('-w', '--word', type=str, required=True,
                       help='Базовое слово для генерации префиксов (обязательно)')
    parser.add_argument('--workers', type=int, default=None,
                       help='Количество рабочих процессов (по умолчанию - кол-во CPU)')
    parser.add_argument('-s', '--save', action='store_true',
                       help='Сохранять результаты в файл')
    
    args = parser.parse_args()
    
    base_word = args.word.strip()
    
    if not base_word:
        print("Ошибка: слово не может быть пустым!")
        sys.exit(1)
    
    print(f"{'='*60}")
    print("🔍 ПОИСК КЛЮЧЕЙ С ЗАДАННЫМ ПРЕФИКСОМ (CPU)")
    print(f"{'='*60}\n")
    
    generator = KeyGenerator(base_word)
    target_prefixes_list = list(generator.target_prefixes)
    
    worker_count = args.workers if args.workers else os.cpu_count()
    
    print(f"Базовое слово:         {base_word}")
    print(f"Сгенерировано префиксов: {len(target_prefixes_list)}")
    print(f"Рабочих процессов:     {worker_count}")
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
                args=(i + 1, target_prefixes_list, found_event, counter, result_queue),
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
            if args.save:
                save_found_key(result)
        else:
            print(f"\n\n{'='*60}")
            print("📊 ИТОГИ ПОИСКА")
            print(f"{'='*60}")
            print(f"Общее время:        {total_time}")
            print(f"Всего ключей:       {total_keys:,}")
            if total_time.total_seconds() > 0:
                print(f"Средняя скорость:   {total_keys / total_time.total_seconds():,.0f}/сек")
            print(f"{'='*60}\n")

if __name__ == "__main__":
    mp.freeze_support()
    main()