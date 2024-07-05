import os
import pandas as pd
import glob
import time
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

BASE_PATH = "/path/to/your/data/"
VIRUS_SHARE_PATH = "/path/to/VirusShareHashes"
FIFO_PATH = "/tmp/virusshare_fifo"

# Find the latest report folder (QRadar-specific)
def find_latest_report_folder(base_path):
    try:
        folders = glob.glob(os.path.join(base_path, '*'))
        if not folders:
            raise FileNotFoundError(f"No folders found in base path: {base_path}")
        latest_folder = max(folders, key=os.path.getmtime)
        return latest_folder
    except Exception as e:
        raise RuntimeError(f"Error finding latest report folder: {e}")

def read_csv_file(csv_folder):
    try:
        csv_files = glob.glob(os.path.join(csv_folder, '*.csv'))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in folder: {csv_folder}")
        
        csv_file = csv_files[0]
        df = pd.read_csv(csv_file)
        logging.debug("Available columns in CSV: %s", df.columns)

        required_columns = ['MD5 Hash', 'Log Source', 'Hour']
        for column in required_columns:
            if column not in df.columns:
                raise KeyError(f"Column '{column}' not found in CSV file")

        return df[required_columns]
    except Exception as e:
        raise RuntimeError(f"Error reading CSV file: {e}")

def get_all_hashes(virus_share_path):
    all_hashes = set()
    try:
        md5_files = glob.glob(os.path.join(virus_share_path, '*.md5'))
        if not md5_files:
            raise FileNotFoundError(f"No .md5 files found in path: {virus_share_path}")
        
        for md5_file in md5_files:
            with open(md5_file, 'r') as f:
                lines = f.readlines()[6:]  # Ignore the first 6 line (VirusShare signature)
                all_hashes.update(line.strip().lower() for line in lines)
        return all_hashes
    except Exception as e:
        raise RuntimeError(f"Error reading .md5 files: {e}")

def compare_hashes(df, all_hashes, fifo_path):
    found_hashes = 0
    total_hashes = len(df)
    processed_hashes = 0

    try:
        with open(fifo_path, 'w') as fifo:
            for _, row in df.iterrows():
                hash_value = row['MD5 Hash']
                log_source = row['Log Source']
                hour = row['Hour']
                processed_hashes += 1
                if hash_value.lower() in all_hashes:
                    found_hashes += 1
                    message = f"Malicious hash found\tHash={hash_value}\tLog Source={log_source}\tHour={hour}\n"
                    fifo.write(message)
                    logging.debug(f"Malicious hash found: {hash_value} (Log Source: {log_source}, Hour: {hour})")
                
                if processed_hashes % 1000 == 0:
                    progress_percent = processed_hashes / total_hashes * 100
                    logging.info(f"Progresso: {processed_hashes}/{total_hashes} processed hashes ({progress_percent:.2f}%)")

        logging.info(f"Processed Hashes: {processed_hashes}/{total_hashes}")
        logging.info(f"Malicious hashes found: {found_hashes}")
    except Exception as e:
        raise RuntimeError(f"Error comparing hashes: {e}")

def main(): 
    if not os.path.exists(FIFO_PATH):
        os.mkfifo(FIFO_PATH)

    start_time = time.time()
    
    try:
        latest_report_folder = find_latest_report_folder(BASE_PATH)
        logging.info(f"Latest folder: {latest_report_folder}")
        csv_folder = os.path.join(latest_report_folder, "CSV")
        df = read_csv_file(csv_folder)
        all_hashes = get_all_hashes(VIRUS_SHARE_PATH)
        logging.info(f"MD5 Hashes found: {len(all_hashes)}")
        compare_hashes(df, all_hashes, FIFO_PATH)

        fifo_size = os.path.getsize(FIFO_PATH)
        if fifo_size == 0:
            logging.info("None Malicious Hash found")
        else:
            logging.info("There been malicious hashes found.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")

    end_time = time.time()
    logging.info(f"Process completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    main()

