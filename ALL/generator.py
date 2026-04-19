import uuid
import os
import datetime

# --- НАСТРОЙКИ ---
UUID = "" # Оставь пустым для генерации нового или впиши свой
PORT = 443
SNI = "google.com" 
MY_NAME = "f3dorovv"
# Путь к папке сохранения
OUTPUT_DIR = "configs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "generated_vless.txt")

def get_uuid():
    return UUID if UUID else str(uuid.uuid4())

def generate():
    # Создаем папку configs, если её нет
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Создана папка: {OUTPUT_DIR}")

    user_uuid = get_uuid()
    configs = []
    
    # Добавляем заголовки (как ты просил ранее)
    yakutsk_time = datetime.datetime.now().strftime("%Y-%m-%d / %H:%M (Yakutsk)")
    configs.append(f"# profile-title: {MY_NAME}.Generated")
    configs.append(f"# profile-update-interval: 5")
    configs.append(f"# Date/Time: {yakutsk_time}")

    # Читаем домены
    if os.path.exists('data/whitelist.txt'):
        with open('data/whitelist.txt', 'r') as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith('#'):
                    link = f"vless://{user_uuid}@{host}:{PORT}?security=tls&sni={SNI}&type=tcp#{MY_NAME}-{host}"
                    configs.append(link)

    # Читаем CIDR
    if os.path.exists('data/cidr.txt'):
        with open('data/cidr.txt', 'r') as f:
            for line in f:
                ip_range = line.strip()
                if ip_range and not ip_range.startswith('#'):
                    # Берем только IP до знака /
                    ip = ip_range.split('/')[0]
                    link = f"vless://{user_uuid}@{ip}:{PORT}?security=tls&sni={SNI}&type=tcp#{MY_NAME}-IP-{ip}"
                    configs.append(link)

    # Сохраняем результат в папку configs
    with open(OUTPUT_FILE, 'w') as f:
        f.write('\n'.join(configs))
    
    print(f"✅ Готово! Файл сохранен: {OUTPUT_FILE}")
    print(f"📥 Сгенерировано конфигов: {len(configs) - 3}") # -3 из-за строк заголовка

if __name__ == "__main__":
    generate()
