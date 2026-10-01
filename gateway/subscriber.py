#!/usr/bin/env python3
"""
Secure Motion Logger - Secure Gateway Receiver
Platform: Kali Linux / Linux / WSL2
Description:
  1. Subscribes to MQTT topic carrying ASCON-128 ciphertext payloads
  2. Measures cryptographic decryption latency (benchmarking)
  3. Decrypts and authenticates AEAD payload using NIST ASCON-128
  4. Forwards authenticated sensor telemetry to Google Cloud (Apps Script Webhook -> Google Sheets)
"""

import paho.mqtt.client as mqtt
import json
import binascii
import sys
import requests
import time
import os

# Import local ASCON-128 engine
import ascon

# ==========================================
# 1. KONFIGURASI SISTEM
# ==========================================
# Ganti dengan Web App URL hasil deployment Google Apps Script Anda:
GOOGLE_SCRIPT_URL = os.environ.get("GOOGLE_SCRIPT_URL", "PASTE_URL_WEB_APP_YANG_PANJANG_DISINI")

# Security Token (Authentication layer antara Gateway dan Cloud)
GOOGLE_TOKEN = os.environ.get("GOOGLE_TOKEN", "akses_aman_123")

# Konfigurasi MQTT Broker
MQTT_BROKER = os.environ.get("MQTT_BROKER", "broker.hivemq.com")
MQTT_PORT   = int(os.environ.get("MQTT_PORT", 1883))
MQTT_TOPIC  = os.environ.get("MQTT_TOPIC", "proyek/motion/data")

# Kunci Rahasia & Parameter Kriptografi (Harus identik dengan firmware ESP32-S3)
SECRET_KEY = b"rahasia_proyek16"  # 16-byte (128-bit) symmetric key
VARIANT    = "Ascon-128"
AAD        = b"sensor_auth"

# ==========================================
# 2. BANNER TERMINAL
# ==========================================
def print_banner():
    C_CYAN  = "\033[96m"
    C_GREEN = "\033[92m"
    C_YELLOW = "\033[93m"
    C_RESET = "\033[0m"

    print(C_CYAN + r"""
    ╔══════════════════════════════════════════════════════════╗
    ║         SECURE MOTION LOGGER - RECEIVER V.2.0            ║
    ║         DECRYPTION: ASCON-128 | CLOUD: CONNECTED         ║
    ╚══════════════════════════════════════════════════════════╝
    """ + C_RESET)
    print(f"{C_GREEN}[+] System Initialized...{C_RESET}")
    print(f"{C_GREEN}[+] Target Broker : {MQTT_BROKER}:{MQTT_PORT}{C_RESET}")
    print(f"{C_GREEN}[+] Target Topic  : {MQTT_TOPIC}{C_RESET}")
    print(f"{C_YELLOW}[+] Cryptography  : NIST ASCON-128 AEAD (Authenticated Decryption){C_RESET}")
    print("-" * 60)

# ==========================================
# 3. PENGIRIMAN KE CLOUD (Google Apps Script)
# ==========================================
def kirim_ke_google(data_sensor):
    if "PASTE_URL" in GOOGLE_SCRIPT_URL:
        print("   [CLOUD] ⚠️ Webhook URL belum dikonfigurasi. Lewati upload cloud.")
        return

    try:
        payload = {
            "token": GOOGLE_TOKEN,
            "temp": data_sensor.get("temp", 0),
            "gx": data_sensor.get("gx", 0),
            "gy": data_sensor.get("gy", 0),
            "gz": data_sensor.get("gz", 0)
        }
        resp = requests.post(GOOGLE_SCRIPT_URL, json=payload, timeout=3)
        if resp.status_code == 200:
            print(f"   [CLOUD] ✅ Data Saved to Spreadsheet ({resp.text.strip()})")
        else:
            print(f"   [CLOUD] ⚠️ Server Responded with status {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"   [CLOUD] ⚠️ Upload Skip: {e}")

# ==========================================
# 4. MQTT CALLBACKS & DEKRIPSI
# ==========================================
def on_connect(client, userdata, flags, rc, *args):
    C_GREEN = "\033[92m"
    C_RESET = "\033[0m"
    if rc == 0:
        print(f"{C_GREEN}[MQTT] Terhubung ke Broker! Berlangganan topik: {MQTT_TOPIC}{C_RESET}")
        print("[MQTT] Menunggu paket ciphertext terenkripsi...\n")
        client.subscribe(MQTT_TOPIC)
    else:
        print(f"[MQTT] Gagal terhubung ke broker, return code: {rc}")

def on_message(client, userdata, msg):
    C_GREEN  = "\033[92m"
    C_RED    = "\033[91m"
    C_YELLOW = "\033[93m"
    C_RESET  = "\033[0m"

    try:
        # 1. Terima dan parsing payload JSON
        payload_str = msg.payload.decode("utf-8")
        data_json = json.loads(payload_str)

        nonce = binascii.unhexlify(data_json["n"])
        ciphertext = binascii.unhexlify(data_json["c"])

        print("=" * 60)
        print(f"[TERIMA HEX]  Ciphertext: {data_json['c'][:40]}... (Total {len(ciphertext)} bytes)")
        print(f"              Nonce:      {data_json['n']}")

        # 2. BENCHMARK DEKRIPSI & OTENTIKASI
        start_time = time.perf_counter()
        decrypted_text = ascon.ascon_decrypt(SECRET_KEY, nonce, AAD, ciphertext, VARIANT)
        end_time = time.perf_counter()

        durasi_ms = (end_time - start_time) * 1000

        # 3. VERIFIKASI INTEGRITAS & OTENTIKASI (CIA TRIAD)
        if decrypted_text is not None:
            original_json = decrypted_text.decode("utf-8")
            sensor_data = json.loads(original_json)

            print(f"{C_GREEN}[BENCHMARK]   Waktu Dekripsi: {durasi_ms:.4f} ms{C_RESET}")
            print(f"{C_GREEN}[DATA ASLI]   🔓 {original_json}{C_RESET}")

            # 4. Teruskan data yang terverifikasi ke Cloud
            kirim_ke_google(sensor_data)
        else:
            print(f"{C_RED}[BAHAYA] Gagal Dekripsi! Tag autentikasi tidak cocok.{C_RESET}")
            print(f"{C_RED}         Paket dimanipulasi (Tampering) atau kunci tidak valid! Menolak paket.{C_RESET}")

    except Exception as e:
        print(f"[ERROR] Gagal memproses paket: {e}")

# ==========================================
# 5. ENTRY POINT
# ==========================================
def main():
    print_banner()

    # Mendukung kompatibilitas Paho-MQTT v1 dan v2
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1)
    except AttributeError:
        client = mqtt.Client()

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\n[SYSTEM] Gateway dihentikan oleh pengguna.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[SYSTEM ERROR] {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
