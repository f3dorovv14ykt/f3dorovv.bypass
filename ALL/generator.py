import uuid
import os

# --- НАСТРОЙКИ ---
UUID = "" # Или оставь пустой строкой, чтобы генерировать новый
PORT = 443
SNI = "google.com" # Домен для маскировки
MY_NAME = "f3dorovv"

def get_uuid():
    return UUID if UUID else str(uuid.uuid4())

def generate():
    user_uuid = get_uuid()
    configs = []

    # Читаем домены
    if os.path.exists('data/whitelist.txt'):
        with open('data/whitelist.txt', 'r') as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith('#'):
                    # Пример VLESS + TLS
                    link = f"vless://{user_uuid}@{host}:{PORT}?security=tls&sni={SNI}&type=tcp#{MY_NAME}-{host}"
                    configs.append(link)

    # Читаем CIDR (берем только начало диапазона для теста)
    if os.path.exists('data/cidr.txt'):
        with open('data/cidr.txt', 'r') as f:
            for line in f:
                ip_range = line.strip()
                if ip_range:
                    # Упрощенно берем IP до знака /
                    ip = ip_range.split('/')[0]
                    link = f"vless://{user_uuid}@{ip}:{PORT}?security=tls&sni={SNI}&type=tcp#{MY_NAME}-IP-{ip}"
                    configs.append(link)

    # Сохраняем результат
    with open('generated_vless.txt', 'w') as f:
        f.write('\n'.join(configs))
    
    print(f"Готово! Сгенерировано {len(configs)} конфигов.")

if __name__ == "__main__":
    generate()
