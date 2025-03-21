import os
import logging
from datetime import datetime
from libraries.YamlUtils import configure_logging, yaml_create_ipgroups_structure, yaml_create_policies_structure
from libraries.CsvUtils import csv_collect_policy_data, csv_render_csv

# Define relative paths
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
IPGROUPS_JSON_PATH = os.path.join(BASE_PATH, '..', 'arm', 'ipgroups.json')
POLICIES_JSON_PATH = os.path.join(BASE_PATH, '..', 'arm', 'policies.json')
IPGROUPS_OUTPUT_DIR = os.path.join(BASE_PATH, '..', '_ipgroups')
POLICIES_OUTPUT_DIR = os.path.join(BASE_PATH, '..', '_policies')
CSV_OUTPUT_DIR = os.path.join(BASE_PATH, '..', 'csv')
TEMPLATE_PATH = os.path.join(BASE_PATH, 'templates', 'policy.csv.jinja2')

# Default firewall name
FIREWALL_NAME = os.getenv('FIREWALL_NAME', 'CGOEW1NW')

# Ensure directories exist
os.makedirs(IPGROUPS_OUTPUT_DIR, exist_ok=True)
os.makedirs(POLICIES_OUTPUT_DIR, exist_ok=True)
os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

def main():
    configure_logging()
    
    if not os.path.exists(IPGROUPS_JSON_PATH):
        logging.error("Error: ipgroups.json must be present in the arm folder.")
        return
    if not os.path.exists(POLICIES_JSON_PATH):
        logging.error("Error: policies.json must be present in the arm folder.")
        return

    # Process IP groups
    yaml_create_ipgroups_structure(IPGROUPS_JSON_PATH, IPGROUPS_OUTPUT_DIR)

    # Process Policies
    yaml_create_policies_structure(POLICIES_JSON_PATH, POLICIES_OUTPUT_DIR)

    # Generate CSV
    resources = csv_collect_policy_data(POLICIES_OUTPUT_DIR)
    if resources:
        logging.info(f"Collected {len(resources)} resources")
        today_date = datetime.now().strftime("%Y%m%d")
        csv_output_path = os.path.join(CSV_OUTPUT_DIR, f'{FIREWALL_NAME}_{today_date}.csv')
        csv_render_csv(resources, TEMPLATE_PATH, csv_output_path)
    else:
        logging.warning("No resources found")

if __name__ == "__main__":
    main()
