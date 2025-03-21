import os
import logging
import sys
from datetime import datetime
from libraries.BicepUtils import configure_logging, load_csv, group_data, render_template, extract_date_suffix, generate_bicep_from_yaml

# Default values
default_subscriptionid = "1094279d-0d07-49dd-8a45-36af71ae2bc0"
default_ipgrouprg = "SecInt-Network-AzureFirewall-IaC-IPG-RG"
default_policiesrg = "SecInt-Network-AzureFirewall-IaC-FWP-RG"
default_firewallname = "CGOEW1NW"
    
# Define relative paths
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
CSV_FOLDER_PATH = os.path.join(BASE_PATH, '..', 'csv')
TEMPLATE_PATH = os.path.join(BASE_PATH, 'templates', 'policy.bicep.jinja2')
BICEP_FOLDER_PATH = os.path.join(BASE_PATH, '..', 'bicep')
IPGROUPS_FOLDER_PATH = os.path.join(BASE_PATH, '..', '_ipgroups')
IPGROUPS_TEMPLATE_PATH = os.path.join(BASE_PATH, 'templates', 'ipgroups.bicep.jinja2')

# Ensure directories exist
os.makedirs(CSV_FOLDER_PATH, exist_ok=True)
os.makedirs(os.path.dirname(TEMPLATE_PATH), exist_ok=True)
os.makedirs(BICEP_FOLDER_PATH, exist_ok=True)

# Configure logging
configure_logging()

# Main function
def main(subscriptionid, ipgrouprg, policiesrg):
    latest_date_suffix = None
    policies = {}

    # Loop through all CSV files in the folder
    for filename in sorted(os.listdir(CSV_FOLDER_PATH)):
        if filename.endswith('.csv'):
            csv_file_path = os.path.join(CSV_FOLDER_PATH, filename)
            data, date_suffix = load_csv(csv_file_path, delimiter=';')
            if data:
                for row in data:
                    row['DateSuffix'] = date_suffix
                policies = group_data(data, policies)
                if latest_date_suffix is None or date_suffix > latest_date_suffix:
                    latest_date_suffix = date_suffix

    if policies and latest_date_suffix:
        # Define the output path for the combined Bicep file
        bicep_file_name = f"{firewallname}_{latest_date_suffix}_policies.bicep"
        output_path = os.path.join(BICEP_FOLDER_PATH, bicep_file_name)
        render_template(policies, TEMPLATE_PATH, output_path, subscriptionid, ipgrouprg, policiesrg)

        # Define the output path for the IP groups Bicep file
        ipgroups_output_path = os.path.join(BICEP_FOLDER_PATH, f"{firewallname}_{latest_date_suffix}_ipgroups.bicep")
        # Generate Bicep file from YAML files
        generate_bicep_from_yaml(IPGROUPS_FOLDER_PATH, IPGROUPS_TEMPLATE_PATH, ipgroups_output_path)

if __name__ == "__main__":
    # Use command-line arguments if provided, otherwise use default values
    subscriptionid = sys.argv[1] if len(sys.argv) > 1 else default_subscriptionid
    ipgrouprg = sys.argv[2] if len(sys.argv) > 2 else default_ipgrouprg
    policiesrg = sys.argv[3] if len(sys.argv) > 3 else default_policiesrg
    firewallname = sys.argv[4] if len(sys.argv) > 4 else default_firewallname

    # Print usage information and parameter values
    logging.info("Usage: python 02-ExportPolicies.py <subscriptionid> <ipgrouprg> <policiesrg> <firewallname>")
    if len(sys.argv) > 1:
        logging.info(f"Using provided subscriptionid: {subscriptionid}")
    else:
        logging.info(f"Using default subscriptionid: {default_subscriptionid}")
    if len(sys.argv) > 2:
        logging.info(f"Using provided ipgrouprg: {ipgrouprg}")
    else:
        logging.info(f"Using default ipgrouprg: {default_ipgrouprg}")
    if len(sys.argv) > 3:
        logging.info(f"Using provided policiesrg: {policiesrg}")
    else:
        logging.info(f"Using default policiesrg: {default_policiesrg}")
    if len(sys.argv) > 4:
        logging.info(f"Using provided firewallname: {firewallname}")
    else:
        logging.info(f"Using default firewallname: {default_firewallname}")

    main(subscriptionid, ipgrouprg, policiesrg)