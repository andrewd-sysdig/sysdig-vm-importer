import requests
import gzip
import os
import logging
from datetime import datetime, date
import xxhash
import sys
import clickhouse_connect
import pandas as pd

logging.basicConfig(level=getattr(logging, 'INFO'), format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

if os.getenv('REPORT_SCHEDULE_ID') is not None:
    REPORT_SCHEDULE_ID = os.getenv('REPORT_SCHEDULE_ID')
else:
    logging.error(f"ENV Var REPORT_SCHEDULE_ID not set")
    exit(1)

if os.getenv('SYSDIG_SECURE_API_TOKEN') is not None:
    SYSDIG_SECURE_API_TOKEN = os.getenv('SYSDIG_SECURE_API_TOKEN')
else:
    logging.error(f"ENV Var SYSDIG_SECURE_API_TOKEN not set")
    exit(1)

if os.getenv('SYSDIG_REGION_URL') is not None:
    SYSDIG_REGION_URL = os.getenv('SYSDIG_REGION_URL')
else:
    logging.error(f"ENV Var SYSDIG_REGION_URL not set")
    exit(1)

if os.getenv('ALL_VULNS_TABLE_NAME') is not None:
    ALL_VULNS_TABLE_NAME = os.getenv('ALL_VULNS_TABLE_NAME')
else:
    logging.error(f"ENV Var ALL_VULNS_TABLE_NAME not set")
    exit(1)

if os.getenv('CLICKHOUSE_HOSTNAME') is not None:
    CLICKHOUSE_HOSTNAME = os.getenv('CLICKHOUSE_HOSTNAME')
else:
    logging.error(f"ENV Var CLICKHOUSE_HOSTNAME not set")
    exit(1)

if os.getenv('CLICKHOUSE_USER') is not None:
    CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER')
else:
    logging.error(f"ENV Var CLICKHOUSE_USER not set")
    exit(1)

if os.getenv('CLICKHOUSE_PASSWORD') is not None:
    CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD')
else:
    logging.error(f"ENV Var CLICKHOUSE_PASSWORD not set")
    exit(1)

if os.getenv('BATCH_SIZE') is not None:
    BATCH_SIZE = int(os.getenv('BATCH_SIZE'))
else:
    logging.error(f"ENV Var BATCH_SIZE not set")
    exit(1)

if len(sys.argv) < 2:
    logging.error(f"Missing Parameter. Usage is: python3 import_sysdig_vulns.py [all|0|1|2]")
    logging.error(f"Where all means download all available reports and 0 means download the most recent, 1 day before the most recent etc...")
    logging.error(f"Example #1, to download all reports available: python3 import_sysdig_vulns.py all")
    logging.error(f"Example #2, to download the most recent report: python3 import_sysdig_vulns.py 0")
    exit(0)

headers = {
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {SYSDIG_SECURE_API_TOKEN}'
    }

temp_download_dir = "/tmp/sysdig-vm-import"
downloaded_gz_file = temp_download_dir + "/report.gz"
downloaded_csv_file = temp_download_dir + "/report.csv"

# Columns to keep from the CSV file downloaded
columns_to_keep = ['Vulnerability ID',
                        'Severity',
                        'Package name',
                        'Package version',
                        'Package path',
                        'Package type',
                        'Image',
                        'OS Name',
                        'K8S cluster name',
                        'K8S namespace name',
                        'K8S workload type',
                        'K8S workload name',
                        'K8S container name']

# Columns to hash to create a unique workload to track
columns_to_hash = ['Vulnerability ID', 
                       'Severity', 
                       'Package name', 
                       'Package version', 
                       'K8S cluster name', 
                       'K8S namespace name', 
                       'K8S workload type', 
                       'K8S workload name', 
                       'K8S container name', 
                       'Package path']

# To rename columns to be database friendly
new_column_names = {'Vulnerability ID': 'vulnerability_id', 
                        'Severity': 'severity', 
                        'Package name': 'package_name', 
                        'Package version': 'package_version',
                        'Package path':  'package_path', 
                        'Package type': 'package_type',
                        'Image': 'image', 
                        'OS Name': 'os_name', 
                        'K8S cluster name': 'k8s_cluster_name',
                        'K8S namespace name': 'k8s_namespace_name', 
                        'K8S workload type': 'k8s_workload_type', 
                        'K8S workload name': 'k8s_workload_name',
                        'K8S container name': 'k8s_container_name',
                        } 

# Connect to Database
logging.info(f"Connecting to Database...")
client = clickhouse_connect.get_client(host=CLICKHOUSE_HOSTNAME, port=8123, username=CLICKHOUSE_USER, password=CLICKHOUSE_PASSWORD)

def decompress_gzip(input_filepath, output_filepath):
    logging.info(f"Uncompressing gz file to csv...")
    with gzip.open(input_filepath, 'rb') as f_in:
        with open(output_filepath, 'wb') as f_out:
            f_out.write(f_in.read())

def hash_concatenated_columns(row, columns):
    concatenated_string = ''.join([str(row[col]) for col in columns])
    hash_value = xxhash.xxh64(concatenated_string).hexdigest()
    return int(hash_value, 16)  # Convert hexadecimal hash string to integer
    
def process_batch(filepath, columns_to_read, columns_to_concatenate, new_column_names, report_date, chunksize=None):
    if chunksize:
        chunks = pd.read_csv(filepath, usecols=columns_to_read, na_filter=False, chunksize=chunksize)
        for i, chunk in enumerate(chunks):
            logging.info(f"Adding report_date and Hashing columns for unique_hash column...")
            chunk['unique_hash'] = chunk.apply(lambda row: hash_concatenated_columns(row, columns_to_concatenate), axis=1)
            chunk['report_date'] = report_date
            chunk.rename(columns=new_column_names, inplace=True)
            yield chunk
    else:
        df = pd.read_csv(filepath, usecols=columns_to_read)
        df['unique_hash'] = df.apply(lambda row: hash_concatenated_columns(row, columns_to_concatenate), axis=1)
        yield df

def create_vuln_table():
    # Create table if it doesn't exist
    logging.info(f"Creating {ALL_VULNS_TABLE_NAME} Table if it doesn't exists...")
    # ORDER BY sets the primary key as well. https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree#selecting-the-primary-key
    create_table = f"""
        CREATE TABLE IF NOT EXISTS \"{ALL_VULNS_TABLE_NAME}\" (
            "vulnerability_id" text,
            "severity" text,
            "package_name" text,
            "package_version" text,
            "package_path" text,
            "package_type" text,
            "image" text,
            "os_name" text,
            "k8s_cluster_name" text,
            "k8s_namespace_name" text,
            "k8s_workload_type" text,
            "k8s_workload_name" text,
            "k8s_container_name" text,
            "unique_hash" UInt64,
            "report_date" Date
        )ENGINE = MergeTree()
        ORDER BY (report_date,severity,k8s_workload_type,k8s_cluster_name,k8s_namespace_name); 
    """
    client.command(create_table)

def download_report(url, report_date):
    response= requests.get(url) # Download report
    with open(downloaded_gz_file, 'wb') as f:
        f.write(response.content)
    decompress_gzip(downloaded_gz_file, downloaded_csv_file)
    for i, chunk in enumerate(process_batch(downloaded_csv_file, columns_to_keep, columns_to_hash, new_column_names, report_date, chunksize=BATCH_SIZE)):
        #print(chunk.head())
        logging.info(f"Importing Vulnerability Records. Row: {(i+1)*BATCH_SIZE} done")
        client.insert_df(ALL_VULNS_TABLE_NAME, chunk)
    
def main():
    # Create the output directory if it doesn't exist
    if not os.path.exists(temp_download_dir):
        os.makedirs(temp_download_dir)
    create_vuln_table()
    url = SYSDIG_REGION_URL + '/api/scanning/reporting/v2/schedules/' + REPORT_SCHEDULE_ID + '/reports'
    response = requests.get(url, headers=headers)
    if response.status_code==200:
        reports_available = response.json()

    # If this is run with the argument all, then download all daily reports available for last 14 days and load them to the DB
    if sys.argv[1] == "all":
        logging.info(f"Importing All data available for report schedule...")
        for report in reports_available:
            logging.info(f"Processing Report: {report['id']} from {report['completedAt']}")
            url = SYSDIG_REGION_URL + '/api/scanning/reporting/v2/schedules/' + REPORT_SCHEDULE_ID + '/reports/' + report['id'] + '/download'
            response = requests.get(url, headers=headers)
            if response.status_code==200:
                logging.info(f"Got Report Download Link, calculating report_date...")
                report_complete_time = report['completedAt']
                report_date = datetime.strptime(report_complete_time, '%Y-%m-%dT%H:%M:%S.%fZ').date()
                #report_date = (dt_object + timedelta(days=1)).date()
                logging.info(f"Calling Download Report with {report_date}")
                download_report(response.url, report_date)
                logging.info(f"Import Complete...")
                logging.info(f"------------------")
                    
    else:
        report_to_download = int(sys.argv[1]) # Expect this to be an int 0-13 where 0 means download today, 1 means 1 day ago etc...
        logging.info(f"Downloading report from {report_to_download} days ago...")
        logging.info(f"Processing Report: {reports_available[report_to_download]['id']} from {reports_available[report_to_download]['completedAt']}")
        url = SYSDIG_REGION_URL + '/api/scanning/reporting/v2/schedules/' + REPORT_SCHEDULE_ID + '/reports/' + reports_available[report_to_download]['id'] + '/download'
        response = requests.get(url, headers=headers)
        if response.status_code==200:
            logging.info(f"Report Downloaded, calculating report_date...")
            report_complete_time = reports_available[report_to_download]['completedAt']
            report_date = datetime.strptime(report_complete_time, '%Y-%m-%dT%H:%M:%S.%fZ').date()
            #report_date = (dt_object + timedelta(days=1)).date()
            #logging.info("Formatting the report date to YYYY-MM-DD...")
            #report_date = dt_object_plus_one_day.strftime('%Y-%m-%d')
            logging.info(f"Calling Download Report with {report_date}")
            download_report(response.url, report_date)
            logging.info(f"Import Complete...")
    
    logging.info(f"Finished, cleaning up removing downloaded files...")
    os.remove(downloaded_gz_file)
    os.remove(downloaded_csv_file)
    
if __name__ == "__main__":
    main()
