import os
import logging
import csv
import shutil
import hashlib
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
# Update imports to use scripts.libraries prefix
from scripts.libraries.CommonUtils import normalize_name, ensure_list, clean_directory
from scripts.libraries.CsvUtils import csv_collect_policy_data
from scripts.libraries.YamlUtils import format_ip_group, extract_base_policy_name
from scripts.libraries.Parameters import Paths, Config, BASE_PATH

def compare_policy_files():
    """
    Compare the most recent files in _policies and _csv directories, factoring in directory modification times.
    """
    logging.info(f"Comparing files in {Paths.POLICIES_DIR} and {Paths.CSV_DIR}")
    
    if not os.path.isdir(Paths.POLICIES_DIR):
        logging.warning(f"Policies directory doesn't exist: {Paths.POLICIES_DIR}")
        return "NO_FILES"
    if not os.path.isdir(Paths.CSV_DIR):
        logging.warning(f"CSV directory doesn't exist: {Paths.CSV_DIR}")
        return "NO_FILES"
    
    # Check for lock file - use parent directory of POLICIES_DIR
    lock_file = os.path.join(BASE_PATH, ".sync_lock")
    if os.path.exists(lock_file):
        try:
            with open(lock_file, 'r') as f:
                lock_data = f.read().strip().split('|')
                
            if len(lock_data) >= 3:
                last_sync_time = float(lock_data[0])
                last_direction = lock_data[1]
                last_content_hash = lock_data[2]
                
                # Get file counts from last sync (stored in lock file if available)
                last_policy_count = int(lock_data[3]) if len(lock_data) > 3 else 0
                last_csv_count = int(lock_data[4]) if len(lock_data) > 4 else 0
                
                # Get current file counts
                current_policy_count = count_files(Paths.POLICIES_DIR, '.yaml')
                current_csv_count = count_files(Paths.CSV_DIR, '.csv')
                
                # Detect file deletions - this is a key change
                policy_files_deleted = current_policy_count < last_policy_count
                csv_files_deleted = current_csv_count < last_csv_count
                
                if policy_files_deleted:
                    logging.info(f"Detected file deletion in policies directory (was {last_policy_count}, now {current_policy_count})")
                    return "POLICIES"
                
                if csv_files_deleted:
                    logging.info(f"Detected file deletion in CSV directory (was {last_csv_count}, now {current_csv_count})")
                    return "CSV"
                
                # Calculate content hash for both directories
                current_hash = calculate_content_hash([Paths.POLICIES_DIR, Paths.CSV_DIR])
                
                # If content hasn't changed since last sync, no need to sync again
                if current_hash == last_content_hash:
                    logging.info("No content changes detected since last sync")
                    return "SAME"
                    
                # Check if files have been modified by the user since last sync
                policy_modified = has_user_changes(Paths.POLICIES_DIR, last_sync_time)
                csv_modified = has_user_changes(Paths.CSV_DIR, last_sync_time)
                
                if policy_modified and csv_modified:
                    logging.warning("Both directories have been modified by users - manual intervention needed")
                    return "CONFLICT"
                elif policy_modified:
                    logging.info("Policy files modified by user - updating CSV files")
                    return "POLICIES"
                elif csv_modified:
                    logging.info("CSV files modified by user - updating policy files")
                    return "CSV"
        except Exception as e:
            logging.warning(f"Error reading sync lock file: {e}")
            # Continue with normal comparison if lock file is invalid
    
    # Fall back to standard comparison if no lock file or lock file invalid
    policy_files = []
    for root, dirs, files in os.walk(Paths.POLICIES_DIR):
        for file in files:
            if file.endswith('.yaml'):
                policy_files.append(os.path.join(root, file))
                
    csv_files = [
        os.path.join(Paths.CSV_DIR, f)
        for f in os.listdir(Paths.CSV_DIR)
        if os.path.isfile(os.path.join(Paths.CSV_DIR, f)) and f.endswith('.csv')
    ]

    if not policy_files and not csv_files:
        logging.warning("No valid files found in either directory")
        return "NO_FILES"
    elif not policy_files:
        logging.info("No valid files in _policies directory")
        return "CSV"
    elif not csv_files:
        logging.info("No valid files in _csv directory")
        return "POLICIES"

    # Include directory modification time
    policy_times = [os.path.getmtime(f) for f in policy_files] + [os.path.getmtime(Paths.POLICIES_DIR)]
    csv_times = [os.path.getmtime(f) for f in csv_files] + [os.path.getmtime(Paths.CSV_DIR)]
    
    # Use second-level precision
    latest_policy_time = max(policy_times)
    latest_csv_time = max(csv_times)

    # Format datetime with seconds precision for display
    policy_time_formatted = datetime.fromtimestamp(latest_policy_time).strftime('%Y-%m-%d %H:%M:%S')
    csv_time_formatted = datetime.fromtimestamp(latest_csv_time).strftime('%Y-%m-%d %H:%M:%S')

    logging.info(f"Most recent policy file modified: {policy_time_formatted}")
    logging.info(f"Most recent CSV file modified: {csv_time_formatted}")

    # More significant time difference helps determine user changes (5 seconds threshold)
    time_diff = abs(latest_policy_time - latest_csv_time)
    if time_diff < 5:  # Less than 5 seconds difference
        logging.info("Files have similar timestamps, likely no user changes")
        return "SAME"
        
    if latest_policy_time > latest_csv_time:
        logging.info("Policies are more recent than CSV exports")
        return "POLICIES"
    else:
        logging.info("CSV exports are more recent than policies")
        return "CSV"

def count_files(directory, extension):
    """
    Count files with a specific extension in a directory (including subdirectories)
    
    Args:
        directory: Directory to check
        extension: File extension to count (including the dot)
        
    Returns:
        int: Number of files with the extension
    """
    count = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(extension):
                count += 1
    return count

def has_user_changes(directory, last_sync_time):
    """
    Check if files in the directory were likely modified by a user (not by sync)
    
    Args:
        directory: Directory to check
        last_sync_time: Timestamp of last sync
        
    Returns:
        bool: True if user changes likely occurred
    """
    # Only consider files from the last run as modified by sync
    # Files modified significantly before or after the sync timestamp
    # are likely modified by a user
    
    threshold = 5  # 5 seconds threshold
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                mod_time = os.path.getmtime(file_path)
                time_diff = abs(mod_time - last_sync_time)
                
                # If modification time is not close to sync time, it's likely a user change
                if time_diff > threshold:
                    return True
    
    # Also check if directory itself was modified (for file deletion detection)
    dir_mod_time = os.path.getmtime(directory)
    dir_time_diff = abs(dir_mod_time - last_sync_time)
    if dir_time_diff > threshold:
        # Check if this is likely due to a file deletion
        for root, dirs, _ in os.walk(directory):
            for subdir in dirs:
                subdir_path = os.path.join(root, subdir)
                subdir_mod_time = os.path.getmtime(subdir_path)
                subdir_time_diff = abs(subdir_mod_time - last_sync_time)
                if subdir_time_diff > threshold:
                    return True
    
    return False

def calculate_content_hash(directories):
    """
    Calculate a hash representing the content of files in the given directories
    
    Args:
        directories: List of directories to check
        
    Returns:
        str: Hash string representing content state
    """
    hasher = hashlib.md5()
    
    for directory in directories:
        if not os.path.isdir(directory):
            continue
            
        # Add directory structure to hash to detect folder changes/deletions
        dir_structure = []
        for root, dirs, files in os.walk(directory):
            rel_path = os.path.relpath(root, directory)
            dir_structure.append(f"D:{rel_path}")
            for file in sorted(files):  # Sort for consistent order
                dir_structure.append(f"F:{os.path.join(rel_path, file)}")
        
        # Sort and add directory structure to hash
        for item in sorted(dir_structure):
            hasher.update(item.encode())
            
        # Add file contents to hash
        for root, _, files in os.walk(directory):
            for file in sorted(files):  # Sort for consistent order
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, 'rb') as f:
                            # Add file content to hash
                            file_content = f.read()
                            hasher.update(file_content)
                            # Also add filename to detect renames
                            hasher.update(os.path.basename(file_path).encode())
                    except Exception as e:
                        logging.warning(f"Error hashing file {file_path}: {e}")
    
    return hasher.hexdigest()

def update_sync_lock(sync_direction):
    """
    Update the sync lock file with the latest sync information
    
    Args:
        sync_direction: Direction of the sync (POLICIES, CSV, SAME)
    """
    # Use root directory for lock file
    lock_file = os.path.join(BASE_PATH, ".sync_lock")
    current_time = datetime.now().timestamp()
    content_hash = calculate_content_hash([Paths.POLICIES_DIR, Paths.CSV_DIR])
    
    # Count current files
    policy_count = count_files(Paths.POLICIES_DIR, '.yaml')
    csv_count = count_files(Paths.CSV_DIR, '.csv')
    
    try:
        with open(lock_file, 'w') as f:
            # Include file counts in the lock file
            f.write(f"{current_time}|{sync_direction}|{content_hash}|{policy_count}|{csv_count}")
        logging.info(f"Updated sync lock file with direction: {sync_direction}, policy files: {policy_count}, CSV files: {csv_count}")
    except Exception as e:
        logging.warning(f"Failed to update sync lock file: {e}")

def process_csv_file(csv_path, rule_type, policies):
    """
    Process a CSV file and extract rule data into the policies dictionary.
    
    Args:
        csv_path (str): Path to the CSV file
        rule_type (str): Type of rule (application, network, or nat)
        policies (dict): Dictionary to store policy data
    """
    logging.info(f"Processing {rule_type} rules from {csv_path}")
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                policy_name = row.get('PolicyName', '').strip()
                if not policy_name:
                    continue
                    
                # Initialize policy if it doesn't exist
                if policy_name not in policies:
                    policies[policy_name] = {
                        'parent_policy': row.get('ParentPolicy', '').strip(),
                        'rule_collection_groups': {}
                    }
                
                rcg_name = row.get('RuleCollectionGroup', '').strip()
                if not rcg_name:
                    continue
                    
                # Parse priority from RCG name if it includes it
                rcg_parts = rcg_name.split('_', 1)
                rcg_priority = rcg_parts[0] if len(rcg_parts) > 1 and rcg_parts[0].isdigit() else '1000'
                
                # Initialize RCG if it doesn't exist
                if rcg_name not in policies[policy_name]['rule_collection_groups']:
                    policies[policy_name]['rule_collection_groups'][rcg_name] = {
                        'priority': rcg_priority,
                        'rule_collections': {}
                    }
                
                rc_name = row.get('RuleCollection', '').strip()
                if not rc_name:
                    continue
                    
                # Parse priority from RC name if it includes it
                rc_parts = rc_name.split('_', 1)
                rc_priority = rc_parts[0] if len(rc_parts) > 1 and rc_parts[0].isdigit() else '1000'
                
                # Determine rule collection type and action based on rule type
                rc_type = None
                if rule_type == 'application':
                    rc_type = 'FirewallPolicyFilterRuleCollection'
                elif rule_type == 'network':
                    rc_type = 'FirewallPolicyFilterRuleCollection'
                elif rule_type == 'nat':
                    rc_type = 'FirewallPolicyNatRuleCollection'
                
                rc_action = row.get('Action', 'Allow').strip()
                
                # Initialize rule collection if it doesn't exist
                if rc_name not in policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections']:
                    policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections'][rc_name] = {
                        'priority': rc_priority,
                        'type': rc_type,
                        'action': rc_action,
                        'rules': []
                    }
                
                # Extract rule data based on rule type
                rule_data = {}
                if rule_type == 'application':
                    rule_data = {
                        'name': row.get('RuleName', '').strip(),
                        'source_addresses': row.get('SourceAddresses', '').split(','),
                        'destination_addresses': row.get('DestinationAddresses', '').split(','),
                        'protocols': row.get('Protocols', '').split(','),
                        'target_fqdns': row.get('TargetFqdns', '').split(','),
                        'web_categories': row.get('WebCategories', '').split(','),
                    }
                elif rule_type == 'network':
                    rule_data = {
                        'name': row.get('RuleName', '').strip(),
                        'source_addresses': row.get('SourceAddresses', '').split(','),
                        'destination_addresses': row.get('DestinationAddresses', '').split(','),
                        'ip_protocols': row.get('IpProtocols', '').split(','),
                        'destination_ports': row.get('DestinationPorts', '').split(','),
                    }
                elif rule_type == 'nat':
                    rule_data = {
                        'name': row.get('RuleName', '').strip(),
                        'source_addresses': row.get('SourceAddresses', '').split(','),
                        'destination_addresses': row.get('DestinationAddresses', '').split(','),
                        'ip_protocols': row.get('IpProtocols', '').split(','),
                        'destination_ports': row.get('DestinationPorts', '').split(','),
                        'translated_address': row.get('TranslatedAddress', '').strip(),
                        'translated_port': row.get('TranslatedPort', '').strip(),
                    }
                
                # Clean up empty lists and strings
                for key, value in list(rule_data.items()):
                    if isinstance(value, list):
                        rule_data[key] = [item.strip() for item in value if item.strip()]
                        if not rule_data[key]:
                            del rule_data[key]
                    elif isinstance(value, str) and not value:
                        del rule_data[key]
                
                # Add rule to collection if it has data
                if rule_data and rule_data.get('name'):
                    policies[policy_name]['rule_collection_groups'][rcg_name]['rule_collections'][rc_name]['rules'].append(rule_data)
                
        logging.info(f"Successfully processed {rule_type} rules from {csv_path}")
        return True
    except Exception as e:
        logging.error(f"Error processing {rule_type} rules from {csv_path}: {e}", exc_info=True)
        return False