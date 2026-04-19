import uuid
import os
import datetime

# --- НАСТРОЙКИ ---
UUID = ""  # Оставь пустым для генерации нового или впиши свой постоянный
PORT = 443
SNI = "google.com" 
MY_NAME = "f3dorovv"
OUTPUT_DIR = "configs"
LIMIT = 200  # Количество конфигов на один файл

def get_uuid():
    return UUID if UUID else str(uuid.uuid4())

def generate():
    # Создаем папку, если её нет
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    # Очищаем старые сгенерированные файлы перед созданием новых
    for f in os.listdir(OUTPUT_DIR):
        if f.startswith("generated_vless.#"):
            os.remove(os.path.join(OUTPUT_DIR, f))

    user_uuid = get_uuid()
    raw_configs = []

    # 1. Читаем домены
    if os.path.exists('data/whitelist.txt'):
        with open('data/whitelist.txt', 'r') as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith('#'):
                    link = f"vless://{user_uuid}@{host}:{PORT}?security=tls&sni={SNI}&type=tcp#{MY_NAME}-{host}"
                    raw_configs.append(link)

    # 2. Читаем CIDR
    if os.path.exists('data/cidr.txt'):
        with open('data/cidr.txt', 'r') as f:
            for line in f:
                item = line.strip()
                if item and not item.startswith('#'):
                    ip = item.split('/')[0]
                    link = f"vless://{user_uuid}@{ip}:{PORT}?security=tls&sni={SNI}&type=tcp#{MY_NAME}-IP-{ip}"
                    raw_configs.append(link)

    if not raw_configs:
        print("Нет данных для генерации.")
        return

    # 3. Расфасовка по файлам
    yakutsk_time = datetime.datetime.now().strftime("%Y-%m-%d / %H:%M (Yakutsk)")
    
    # Разбиваем список raw_configs на части по LIMIT
    chunks = [raw_configs[i:i + LIMIT] for i in range(0, len(raw_configs), LIMIT)]

    for index, chunk in enumerate(chunks, start=1):
        file_name = f"generated_vless.#{index}.txt"
        file_path = os.path.join(OUTPUT_DIR, file_name)
        
        with open(file_path, 'w') as f:
            # Добавляем заголовок в каждый файл
            f.write(f"# profile-title: {MY_NAME}.Generated-Part{index}\n")
            f.write(f"# profile-update-interval: 5\n")
            f.write(f"# Date/Time: {yakutsk_time}\n")
            f.write('\n'.join(chunk))
        
        print(f"Создан файл: {file_name} ({len(chunk)} конфигов)")

if __name__ == "__main__":
    generate()
