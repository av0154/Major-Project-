import time
import logging
from key_manager import generate_key

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

def rotate_keys():
    try:
        while True:
            generate_key()  
            logging.info("Key rotated successfully.")
            time.sleep(300)  
    except KeyboardInterrupt:
        logging.info("Key rotation process stopped by user.")
    except Exception as e:
        logging.error(f"Error during key rotation: {e}")

if __name__ == "__main__":
    logging.info("Starting key rotation script...")
    rotate_keys()

