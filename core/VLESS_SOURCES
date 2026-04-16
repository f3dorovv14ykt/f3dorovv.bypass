import os
import json
import time
import random
import subprocess
import zipfile
import sys
import requests
from urllib.parse import urlparse, parse_qs

# 🔗 1. СЮДА ВСТАВЬТЕ ВАШИ ССЫЛКИ НА ОТКРЫТЫЕ РЕПОЗИТОРИИ
VLESS_SOURCES = [
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt"
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-1.txt"
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt"
    "https://raw.githubusercontent.com/Hidashimora/free-vpn-anti-rkn/main/configs/26.1.txt"
]

LOCAL_SOCKS_PORT = 10808 # Локальный порт для моста


# 📥 2. Автоматический загрузчик ядра Xray
def download_xray():
    """Автоматически скачивает Xray, если его нет в папке"""
    xray_bin = "xray.exe" if os.name == "nt" else "xray"
    
    if os.path.exists(xray_bin):
        return xray_bin
        
    print("📥 Ядро Xray не найдено. Начинаю загрузку...")
    
    url = "https://github.com"
    if os.name == "nt":
        url = "https://github.com"
        
    try:
        r = requests.get(url, stream=True)
        with open("xray.zip", "wb") as f:
            f.write(r.content)
            
        with zipfile.ZipFile("xray.zip", "r") as zip_ref:
            zip_ref.extractall(".")
            
        os.remove("xray.zip")
        
        if os.name != "nt":
            os.chmod(xray_bin, 0o755)
            
        print("✅ Xray успешно скачан и готов к работе!")
        return xray_bin
        
    except Exception as e:
        print(f"❌ Не удалось скачать Xray: {e}")
        sys.exit(1)


# 🛠️ 3. Генератор конфига для Xray
def parse_vless_to_json(vless_url, local_port):
    """Парсит vless:// строку и генерирует JSON для Xray"""
    parsed = urlparse(vless_url)
    uuid = parsed.username
    address = parsed.hostname
    port = parsed.port
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": address,
                    "port": int(port),
                    "users": [{
                        "id": uuid,
                        "encryption": params.get("encryption", "none"),
                        "flow": params.get("flow", "")
                    }]
                }]
            },
            "streamSettings": {
                "network": params.get("type", "tcp"),
                "security": params.get("security", "none")
            }
        }]
    }
    
    if params.get("security") == "reality":
        config["outbounds"][0]["streamSettings"]["realitySettings"] = {
            "publicKey": params.get("pbk", ""),
            "fingerprint": params.get("fp", "chrome"),
            "serverName": params.get("sni", ""),
            "shortId": params.get("sid", "")
        }
    
    return config


# 🎲 4. Главный движок обхода
def start_vless_bypass(target_url):
    xray_bin = download_xray()
    
    # Собираем VLESS из ваших источников
    links_pool = []
    print("⏳ Сбор VLESS-конфигураций из ваших источников...")
    for source_url in VLESS_SOURCES:
        try:
            res = requests.get(source_url, timeout=5)
            if res.status_code == 200:
                # Извлекаем все строки, начинающиеся с vless://
                links_pool.extend([line.strip() for line in res.text.split('\n') if line.startswith("vless://")])
        except Exception:
            continue
            
    links_pool = list(set(links_pool))
    print(f"✅ Готово к ротации. Найдено уникальных конфигов: {len(links_pool)}")
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36..."
    ]
    
    while links_pool:
        vless_link = random.choice(links_pool)
        print(f"\n🔄 Пробуем подключение через VLESS...")
        
        # Создаем JSON и запускаем Xray
        config_dict = parse_vless_to_json(vless_link, LOCAL_SOCKS_PORT)
        config_path = "temp_xray_config.json"
        with open(config_path, "w") as f:
            json.dump(config_dict, f, indent=2)
            
        try:
            xray_process = subprocess.Popen(
                [xray_bin, "-c", config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(2) # Даем Xray запуститься
        except Exception:
            links_pool.remove(vless_link)
            continue
            
        # 🎲 Рандомизация задержки (имитация человека)
        sleep_time = random.uniform(3.0, 7.5)
        print(f"⏸️ Имитация чтения/паузы: {sleep_time:.2f} сек.")
        time.sleep(sleep_time)
        
        proxies = {
            "http": f"socks5://127.0.0.1:{LOCAL_SOCKS_PORT}",
            "https": f"socks5://127.0.0.1:{LOCAL_SOCKS_PORT}"
        }
        headers = {"User-Agent": random.choice(user_agents)}
        
        try:
            print("🌐 Отправка запроса через VLESS-туннель...")
            response = requests.get(target_url, headers=headers, proxies=proxies, timeout=10)
            
            if response.status_code == 200:
                print("✅ Успех! Ответ получен.")
                xray_process.terminate()
                return response.text
                
        except Exception:
            print("⚠️ Ошибка соединения или VLESS мертв. Ротация...")
            
        xray_process.terminate()
        xray_process.wait()
        links_pool.remove(vless_link)
        
    print("🛑 Все найденные VLESS-конфигурации не сработали.")
    return None
