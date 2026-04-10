import random
import logging
from typing import List

# =====================================================================
# Configuration & Constants
# =====================================================================

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Known malicious IPs for deterministic testing
ATTACK_IPS = {
    "DDOS": "198.51.100.42",
    "BRUTE_FORCE": "10.15.22.8",
    "SCRAPING": "203.0.113.99",
    "C2_BEACON": "45.33.22.11",
    "SCANNER": "172.16.0.50",
    "SLOWLORIS": "8.8.4.4",
    "PULSING": "9.9.9.9"
}

# Baseline timestamp (e.g., Nov 2023)
BASE_TIMESTAMP = 1700000000

# =====================================================================
# Synthetic Log Generator
# =====================================================================

def generate_random_ip() -> str:
    """Generates a random valid IPv4 address for background noise."""
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_synthetic_threat_logs(file_path: str, background_traffic_lines: int) -> None:
    """
    Generates a massive log file with background traffic and injects specific 
    behavioral cyber threats at predefined milestones.
    """
    logging.info(f"Initializing synthetic log generation: '{file_path}' (~{background_traffic_lines:,} lines)")
    current_ts = BASE_TIMESTAMP
    
    with open(file_path, 'w', encoding='utf-8') as f:
        for i in range(background_traffic_lines):
            # 1. Background Noise (Normal Traffic)
            current_ts += random.randint(0, 2)
            f.write(f"{generate_random_ip()} {current_ts} GET /index.html 200\n")
            
            # Array to hold injected attack lines (batch writing for better I/O performance)
            attack_buffer: List[str] = []

            # 2. Inject L7 API Flood (DDoS)
            if i == 100_000:
                logging.info(f"Injecting L7 API Flood from {ATTACK_IPS['DDOS']}")
                attack_ts = current_ts
                attack_buffer.extend([f"{ATTACK_IPS['DDOS']} {attack_ts} GET /api/v1/data 503\n" for _ in range(300)])

            # 3. Inject Credential Brute Force
            elif i == 200_000:
                logging.info(f"Injecting Brute Force Attack from {ATTACK_IPS['BRUTE_FORCE']}")
                attack_ts = current_ts
                for _ in range(60):
                    attack_ts += random.choice([0, 1])
                    attack_buffer.append(f"{ATTACK_IPS['BRUTE_FORCE']} {attack_ts} POST /auth/login 401\n")

            # 4. Inject Data Scraping / Enumeration
            elif i == 300_000:
                logging.info(f"Injecting Data Scraping from {ATTACK_IPS['SCRAPING']}")
                attack_ts = current_ts
                for _ in range(160):
                    attack_ts += random.choice([0, 0, 1])
                    attack_buffer.append(f"{ATTACK_IPS['SCRAPING']} {attack_ts} GET /products/item 200\n")

            # 5. Inject C2 Beaconing (Robotic Periodic Comm)
            elif i == 400_000:
                logging.info(f"Injecting C2 Beaconing from {ATTACK_IPS['C2_BEACON']}")
                attack_ts = current_ts
                for _ in range(25):
                    attack_ts += 5  # Perfectly periodic (5 seconds)
                    attack_buffer.append(f"{ATTACK_IPS['C2_BEACON']} {attack_ts} GET /healthz 200\n")

            # 6. Inject Automated Fuzzing / Scanner
            elif i == 600_000:
                logging.info(f"Injecting Vulnerability Scanner from {ATTACK_IPS['SCANNER']}")
                attack_ts = current_ts
                for _ in range(150):
                    attack_ts += random.choice([0, 0, 0, 1])
                    attack_buffer.append(f"{ATTACK_IPS['SCANNER']} {attack_ts} GET /admin/config.php 404\n")

            # 7. Inject Low-and-Slow (Slowloris)
            elif i == 700_000:
                logging.info(f"Injecting Slowloris (Low-and-Slow) from {ATTACK_IPS['SLOWLORIS']}")
                attack_ts = current_ts
                for _ in range(40):
                    attack_ts += 4  # Slow, rhythmic connection holding
                    attack_buffer.append(f"{ATTACK_IPS['SLOWLORIS']} {attack_ts} POST /api/upload 200\n")

            # 8. Inject Pulsing DDoS (Evasion Tactic)

            elif i == 900_000:
                logging.info(f"Injecting Pulsing DDoS from {ATTACK_IPS['PULSING']}")
                attack_ts = current_ts
                for _ in range(3):  # CORREÇÃO AQUI: removido o "burst"
                    for _ in range(50):
                        attack_buffer.append(f"{ATTACK_IPS['PULSING']} {attack_ts} GET /heavy-query 500\n")
                    attack_ts += 20  # Long pause between bursts to evade simple rate limiters

            # Flush attack buffer to file
            if attack_buffer:
                f.writelines(attack_buffer)

    logging.info(f"Log generation completed successfully! Target file: {file_path}")

if __name__ == "__main__":
    generate_synthetic_threat_logs("teste.log", 1_000_000)