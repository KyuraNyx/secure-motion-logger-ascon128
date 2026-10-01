import network
import time
import machine
import ujson
import ubinascii
import os
from umqtt.simple import MQTTClient
import mpu6050
import ascon

# ==========================================
# 1. KONFIGURASI (Silakan sesuaikan)
# ==========================================
WIFI_SSID = "YOUR_WIFI_SSID"
WIFI_PASS = "YOUR_WIFI_PASSWORD"

MQTT_BROKER    = "broker.hivemq.com"
MQTT_CLIENT_ID = "esp32_motion_node"
MQTT_TOPIC     = "proyek/motion/data"

# Kunci Rahasia ASCON-128 (Harus 16 byte & identik dengan Gateway)
SECRET_KEY = b"rahasia_proyek16"
VARIANT    = "Ascon-128"
AAD        = b"sensor_auth"

# ==========================================
# 2. SETUP HARDWARE (SoftI2C)
# ==========================================
# Menggunakan Software I2C pada Pin 9 (SCL) dan 8 (SDA)
# Frekuensi 100kHz untuk transmisi sensor yang stabil pada ESP32-S3
i2c = machine.SoftI2C(scl=machine.Pin(9), sda=machine.Pin(8), freq=100000)

try:
    sensor = mpu6050.MPU6050(i2c)
    print("[INIT] Sensor MPU-6050 Berhasil Diinisialisasi!")
except Exception as e:
    print("[ERROR] Sensor gagal diinisialisasi:", e)

# ==========================================
# 3. KONEKSI WIFI
# ==========================================
def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Menghubungkan ke WiFi...", end="")
        wlan.connect(WIFI_SSID, WIFI_PASS)
        retry = 0
        while not wlan.isconnected():
            retry += 1
            time.sleep(0.5)
            print(".", end="")
            if retry > 20:
                print("\n[ERROR] Gagal terhubung ke WiFi. Periksa SSID dan Password!")
                return False
    print("\n[WIFI] Terhubung! IP Address:", wlan.ifconfig()[0])
    return True

# ==========================================
# 4. PROGRAM UTAMA (Publisher Loop)
# ==========================================
def main():
    if not connect_wifi():
        return

    print(f"[MQTT] Menghubungkan ke broker: {MQTT_BROKER}...")
    try:
        client = MQTTClient(MQTT_CLIENT_ID, MQTT_BROKER)
        client.connect()
        print("[MQTT] Terhubung ke broker!")
    except Exception as e:
        print("[MQTT] Gagal terhubung ke broker:", e)
        return

    print("\n=== SISTEM SECURE MOTION LOGGER AKTIF ===")
    print("Membaca sensor MPU-6050, mengenkripsi via ASCON-128, dan mempublikasikan via MQTT...\n")

    while True:
        try:
            # A. BACA SENSOR (PLAINTEXT ASLI)
            data = sensor.get_values()

            payload = {
                "gx": round(data["GyX"], 2),
                "gy": round(data["GyY"], 2),
                "gz": round(data["GyZ"], 2),
                "temp": round(data["Tmp"], 2)
            }

            plaintext = ujson.dumps(payload).encode("utf-8")
            print(f"[RAW DATA]    {plaintext}")

            # B. ENKRIPSI ASCON-128 & BENCHMARKING
            nonce = os.urandom(16)

            start_time = time.ticks_us()
            ciphertext_tag = ascon.ascon_encrypt(SECRET_KEY, nonce, AAD, plaintext, VARIANT)
            end_time = time.ticks_us()

            durasi_ms = time.ticks_diff(end_time, start_time) / 1000
            print(f"[BENCHMARK]   Waktu Enkripsi: {durasi_ms:.3f} ms")

            # C. BUNGKUS PAYLOAD HEX (CIPHERTEXT + TAG + NONCE)
            msg_final = ujson.dumps({
                "n": ubinascii.hexlify(nonce).decode(),
                "c": ubinascii.hexlify(ciphertext_tag).decode()
            })

            print(f"[SECURE HEX]  {msg_final}")
            print("-" * 50)

            # D. PUBLISH KE BROKER MQTT
            client.publish(MQTT_TOPIC, msg_final)

        except Exception as e:
            print("[ERROR LOOP]", e)
            try:
                client.connect()
            except Exception:
                pass

        time.sleep(2)

if __name__ == "__main__":
    main()
