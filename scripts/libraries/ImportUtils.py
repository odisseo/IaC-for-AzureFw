import os
import sys
import logging
from datetime import datetime
from scripts.libraries.CommonUtils import get_base_path, clean_directory
from scripts.libraries.YamlUtils import yaml_create_ipgroups_structure, yaml_create_policies_structure
from scripts.libraries.CsvUtils import csv_collect_policy_data, csv_render_csv
from scripts.libraries.Parameters import Paths, Config

def validate_import_files():
    """
    Validate that the required JSON files exist for import.
    
    Returns:
        bool: True if files exist, False otherwise
    """
    if not os.path.exists(Paths.IPGROUPS_JSON):
        logging.error(f"Error: ipgroups.json must be present in the arm folder: {Paths.IPGROUPS_JSON}")
        return False
    if not os.path.exists(Paths.POLICIES_JSON):
        logging.error(f"Error: policies.json must be present in the arm folder: {Paths.POLICIES_JSON}")
        return False
        
    return True

def import_policies(firewall_key=None):
    """
    Import Azure Firewall policies from ARM templates to YAML structure.
    Also generates CSV files for policy visualization.
    
    Args:
        firewall_key: Optional firewall key to override the default

    Returns:
        tuple: (success, message) where success is a boolean and message provides
               information about the operation
    """
    # Use provided firewall name or default
    fw_name = firewall_key or Config.FIREWALL_NAME
    
    # Ensure directories exist
    os.makedirs(Paths.IPGROUPS_DIR, exist_ok=True)
    os.makedirs(Paths.POLICIES_DIR, exist_ok=True)
    os.makedirs(Paths.CSV_DIR, exist_ok=True)
    
    # Validate input files
    if not validate_import_files():
        return False, "Input files validation failed"

    # Process IP groups
    logging.info("Processing IP groups...")
    ip_groups_success = yaml_create_ipgroups_structure(Paths.IPGROUPS_JSON, Paths.IPGROUPS_DIR)
    if ip_groups_success:
        logging.info("IP groups processed successfully.")
    else:
        logging.error("Failed to process IP groups.")
        return False, "Failed to process IP groups"

    # Process Policies directly in the policies directory
    logging.info("Processing policies directly in _policies directory...")
    policies_success = yaml_create_policies_structure(Paths.POLICIES_JSON, Paths.POLICIES_DIR)
    if policies_success:
        logging.info("Policies processed successfully.")
    else:
        logging.error("Failed to process policies.")
        return False, "Failed to process policies"
    
    # Clean CSV directory before generating new files
    logging.info("Cleaning CSV directory before generating new files...")
    clean_directory(Paths.CSV_DIR)
        
    # Generate CSV from the policies folder
    logging.info("Generating CSV files directly in _csv directory...")
    resources_nat, resources_network, resources_application = csv_collect_policy_data(Paths.POLICIES_DIR)
    
    # NAT Rules
    if resources_nat:
        logging.info(f"Collected {len(resources_nat)} NAT resources")
        csv_output_path_nat = os.path.join(Paths.CSV_DIR, f'{fw_name}_nat.csv')
        csv_render_csv(resources_nat, csv_output_path_nat, "NatRule")
        logging.info(f"NAT rules CSV created: {csv_output_path_nat}")
    else:
        logging.warning("No NAT resources found")

    # Network Rules
    if resources_network:
        logging.info(f"Collected {len(resources_network)} Network resources")
        csv_output_path_network = os.path.join(Paths.CSV_DIR, f'{fw_name}_network.csv')
        csv_render_csv(resources_network, csv_output_path_network, "NetworkRule")
        logging.info(f"Network rules CSV created: {csv_output_path_network}")
    else:
        logging.warning("No Network resources found")

    # Application Rules
    if resources_application:
        logging.info(f"Collected {len(resources_application)} Application resources")
        csv_output_path_application = os.path.join(Paths.CSV_DIR, f'{fw_name}_application.csv')
        csv_render_csv(resources_application, csv_output_path_application, "ApplicationRule")
        logging.info(f"Application rules CSV created: {csv_output_path_application}")
    else:
        logging.warning("No Application resources found")
        
    logging.info("Import complete. Files created directly in _policies and _csv directories")
    return True, "Import successful"