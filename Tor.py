from stem import Signal
from stem.control import Controller
import time
import os

TOR_CONTROL_PORT = 9051  
TOR_PASSWORD = "Qwer@12345"  
def change_mac():
    os.system("sudo macchanger -r eth0")
    os.system("sudo macchanger -r tun0")
    os.system("sudo macchanger -r tun1")
def change_ip():
    try:
        with Controller.from_port(port=TOR_CONTROL_PORT) as controller:
            if TOR_PASSWORD:
                controller.authenticate(password=TOR_PASSWORD)
            controller.signal(Signal.NEWNYM)
            print("Requested new Tor circuit (IP change).")
    except Exception as e:
        print(f"Error changing IP: {e}")

if __name__ == "__main__":
    while True:
        change_ip()
        change_mac()
        time.sleep(10)  
