"""
Common utilities for Azure Firewall Policy Manager.

This module provides common functionality used across multiple modules,
including file operations, logging configuration, and Azure operations.
"""
import glob
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
# import winreg
import yaml
# Import directly from Parameters - updated location
from src.libraries.Parameters import Config, Paths
import hashlib
import time
from datetime import datetime

# Third-party imports
from colorama import Fore, Style, init
from jinja2 import Environment, FileSystemLoader

# Initialize colorama for cross-platform color support
init(autoreset=True)

##########################################################################
# CommonConfiguration Class
##########################################################################

class CommonConfiguration:
    """Common configuration utilities class."""
    
    class CustomFormatter(logging.Formatter):
        """Custom logging formatter to add colors to log levels."""
        FORMATS = {
            logging.DEBUG: Style.DIM + "%(asctime)s - %(levelname)s - %(message)s",
            logging.INFO: Fore.GREEN + "%(asctime)s - %(levelname)s - %(message)s",
            logging.WARNING: Fore.YELLOW + "%(asctime)s - %(levelname)s - %(message)s",
            logging.ERROR: Fore.RED + "%(asctime)s - %(levelname)s - %(message)s",
            logging.CRITICAL: Fore.RED + Style.BRIGHT + "%(asctime)s - %(levelname)s - %(message)s",
        }

        def format(self, record):
            log_fmt = self.FORMATS.get(record.levelno, "%(asctime)s - %(levelname)s - %(message)s")
            formatter = logging.Formatter(log_fmt)
            return formatter.format(record)
    
    # Helper methods (private)
    
    @staticmethod
    def _build_environments_list(firewalls_dir):
        """
        Build list of available environments from YAML files.
        
        Args:
            firewalls_dir: Directory containing firewall YAML files
            
        Returns:
            tuple: (environments_list, error_message)
                - environments_list: List of (idx, env_name, yaml_file) tuples, sorted by index
                - error_message: None on success, error string on failure
        """
        yaml_files = glob.glob(os.path.join(firewalls_dir, "*.yaml"))
        
        if not yaml_files:
            error_msg = "No firewall YAML files found in directory"
            logging.error(error_msg)
            return None, error_msg
        
        environments = []
        for yaml_file in yaml_files:
            filename = os.path.basename(yaml_file)
            name_parts = filename.split('.')
            
            # Validate filename pattern: idx.environment_name.yaml
            if len(name_parts) < 2:
                logging.warning(f"Filename {filename} doesn't match expected pattern idx.environment_name.yaml")
                continue
            
            try:
                idx = int(name_parts[0])
                env_name = name_parts[1]
                environments.append((idx, env_name, yaml_file))
            except ValueError:
                logging.warning(f"Invalid index number in filename {filename}")
                continue
        
        # Sort by index for consistent ordering
        environments.sort(key=lambda x: x[0])
        
        return environments, None
    
    @staticmethod
    def _select_environment(environments, environment_name):
        """
        Select an environment from the available list by name or index.
        Non-interactive - just performs lookup.
        
        Args:
            environments: List of (idx, env_name, yaml_file) tuples
            environment_name: Name or index to match
            
        Returns:
            tuple: (selected_file, selected_env_name, error_message)
        """
        if not environment_name:
            return None, None, "No environment name provided"
        
        # Create lookup dictionaries for O(1) access
        env_by_name = {env_name: (yaml_file, env_name) for _, env_name, yaml_file in environments}
        env_by_idx = {idx: (yaml_file, env_name) for idx, env_name, yaml_file in environments}
        
        # Try direct name match first
        if environment_name in env_by_name:
            selected_file, selected_env_name = env_by_name[environment_name]
            logging.info(f"Found environment match: {selected_env_name}")
            return selected_file, selected_env_name, None
        
        # Try index match
        try:
            env_idx = int(environment_name)
            if env_idx in env_by_idx:
                selected_file, selected_env_name = env_by_idx[env_idx]
                logging.info(f"Found environment match for index {env_idx}: {selected_env_name}")
                return selected_file, selected_env_name, None
        except ValueError:
            pass
        
        # Environment not found
        error_msg = f"Environment '{environment_name}' not found"
        logging.warning(error_msg)
        return None, None, error_msg
    
    @staticmethod
    def _load_and_validate_config(selected_file, environment_name, regiontype, 
                                  prod_firewall, required_fields):
        """
        Load YAML configuration and apply validation/filtering.
        
        Args:
            selected_file: Path to the YAML file to load
            environment_name: Name of the environment (for error messages)
            regiontype: Filter by region type
            prod_firewall: If True, return single production firewall
            required_fields: List of required field names
            
        Returns:
            tuple: (firewall_config, error_message)
        """
        if not selected_file:
            return None, "No environment selected"
        
        try:
            # Load YAML file
            fw_config = CommonFile.load_yaml_file(selected_file)
            if not fw_config or not isinstance(fw_config, list):
                error_msg = f"Invalid or empty configuration in {selected_file}"
                logging.warning(error_msg)
                return None, error_msg
            
            # Apply regiontype filter if specified
            if regiontype:
                fw_config = [
                    fw for fw in fw_config 
                    if str(fw.get('regionType', '')).lower() == str(regiontype).lower()
                ]
                logging.info(
                    f"Loaded {len(fw_config)} firewall configurations from "
                    f"{os.path.basename(selected_file)} with regionType={regiontype}"
                )
            else:
                logging.info(
                    f"Loaded {len(fw_config)} firewall configurations from "
                    f"{os.path.basename(selected_file)}"
                )
            
            # Validate we have data
            if not fw_config:
                error_msg = f"No firewall found for environment: {environment_name}"
                if regiontype:
                    error_msg += f" with regionType={regiontype}"
                logging.warning(error_msg)
                return None, error_msg
            
            # Handle prod_firewall requirements
            if prod_firewall:
                return CommonConfiguration._validate_production_firewall(
                    fw_config, environment_name, required_fields
                )
            
            # Return list of firewalls
            return fw_config, None
            
        except Exception as e:
            error_msg = f"Failed to load firewall data from {selected_file}: {str(e)}"
            logging.error(error_msg)
            return None, error_msg
    
    @staticmethod
    def _validate_production_firewall(fw_config, environment_name, required_fields):
        """
        Validate and return a single production firewall.
        
        Args:
            fw_config: List of firewall configurations
            environment_name: Name of environment (for error messages)
            required_fields: List of required field names
            
        Returns:
            tuple: (firewall_dict, error_message)
        """
        # Filter for production firewalls
        prod_firewalls = [
            fw for fw in fw_config 
            if str(fw.get('regionType', '')).lower() == 'prod'
        ]
        
        # Validate production firewall exists
        if not prod_firewalls:
            error_msg = (
                f"No production firewall (regionType='Prod') found for "
                f"environment: {environment_name}"
            )
            logging.warning(error_msg)
            return None, error_msg
        
        # Validate only one production firewall
        if len(prod_firewalls) > 1:
            error_msg = (
                f"Multiple production firewalls found for environment: "
                f"{environment_name}. Only one is supported."
            )
            logging.warning(error_msg)
            return None, error_msg
        
        fw = prod_firewalls[0]
        
        # Validate required fields
        if required_fields:
            missing_fields = [field for field in required_fields if not fw.get(field)]
            if missing_fields:
                error_msg = (
                    f"Missing required firewall configuration fields: "
                    f"{', '.join(missing_fields)}"
                )
                logging.warning(error_msg)
                return None, error_msg
        
        return fw, None
    
    # Public methods
    
    @staticmethod
    def get_available_environments(firewalls_dir=None):
        """
        Get list of available environments without loading YAML data.
        
        Args:
            firewalls_dir: Directory containing firewall YAML files (optional)
            
        Returns:
            tuple: (environments_list, error_message)
                - environments_list: List of (idx, env_name, yaml_file) tuples
                - error_message: None on success, error string on failure
        """
        if firewalls_dir is None:
            firewalls_dir = Paths.FIREWALLS_DIR
        
        return CommonConfiguration._build_environments_list(firewalls_dir)
    
    # @staticmethod
    # def set_list_separator(separator=";"):
    #     """
    #     Set the Windows list separator in the registry.
        
    #     Args:
    #         separator (str): The separator to use for lists (default: ";")
    #     """
    #     reg_path = r'Control Panel\International'
    #     try:
    #         reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)
    #         winreg.SetValueEx(reg_key, 'sList', 0, winreg.REG_SZ, separator)
    #         winreg.CloseKey(reg_key)
    #         logging.info(f"List separator successfully set to '{separator}'")
    #     except Exception as e:
    #         logging.warning(f"Failed to set list separator: {e}")
    
    @staticmethod
    def configure_logging():
        """Configure logging settings with color support."""
        # Reset any existing handlers
        root = logging.getLogger()
        if root.handlers:
            for handler in root.handlers:
                root.removeHandler(handler)
        
        # Add our custom handler with formatter
        handler = logging.StreamHandler()
        handler.setFormatter(CommonConfiguration.CustomFormatter())
        root.addHandler(handler)
        root.setLevel(logging.INFO)
    
    @staticmethod
    def get_environment(environment_name, load_yaml=True, 
                       firewalls_dir=None, regiontype=None, 
                       prod_firewall=False, required_fields=None):
        """
        Get environment configuration by name or index.
        Non-interactive - requires environment_name to be provided.
        
        Args:
            environment_name: Environment identifier (name or index) - REQUIRED
            load_yaml: If True, load and return YAML data; if False, return environment name only
            firewalls_dir: Directory containing firewall YAML files (optional)
            regiontype: Filter firewalls by region type (e.g., 'Prod', 'DR')
            prod_firewall: If True, return single production firewall dict (not list)
            required_fields: List of required field names to validate
            
        Returns:
            tuple: (data, error_message)
                - If load_yaml=True: (firewall_data, error_message) - firewall_data is list/dict or None
                - If load_yaml=False: (environment_name, error_message) - environment_name is string or None
                - error_message is None on success, or error string on failure
        """
        if firewalls_dir is None:
            firewalls_dir = Paths.FIREWALLS_DIR
        
        if not environment_name:
            return None, "Environment name is required"
        
        # Build environments list from YAML files
        environments, error_msg = CommonConfiguration._build_environments_list(firewalls_dir)
        if error_msg:
            return None, error_msg
        
        # Select environment (non-interactive lookup only)
        selected_file, selected_env_name, error_msg = CommonConfiguration._select_environment(
            environments, environment_name
        )
        if error_msg:
            return None, error_msg
        
        # Return just the environment name if YAML loading is not needed
        if not load_yaml:
            return selected_env_name, None
        
        # Load and process YAML configuration
        return CommonConfiguration._load_and_validate_config(
            selected_file, selected_env_name, regiontype, 
            prod_firewall, required_fields
        )

##########################################################################
# CommonFile Class
##########################################################################

class CommonFile:
    """Common file operations utilities class."""
    
    @staticmethod
    def load_yaml_file(file_path):
        """Load YAML data from a file with proper error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = yaml.safe_load(file)
                return data
        except (OSError, yaml.YAMLError) as e:
            logging.error(f"Error loading YAML file {file_path}: {e}", exc_info=True)
            return None

    @staticmethod
    def load_json_file(file_path):
        """Load JSON data from a file with proper error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
                return data
        except (OSError, json.JSONDecodeError) as e:
            logging.error(f"Error loading JSON file {file_path}: {e}", exc_info=True)
            return None

    @staticmethod
    def save_file(content, file_path):
        """Save content to a file with proper error handling."""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as file:
                file.write(content)
            return True
        except Exception as e:
            logging.error(f"Error saving file {file_path}: {e}", exc_info=True)
            return False

    @staticmethod
    def clean_directory(directory):
        """Clean a directory by removing all files and subdirectories."""
        if os.path.exists(directory):
            logging.info(f"Cleaning directory: {directory}")
            try:
                for item in os.listdir(directory):
                    item_path = os.path.join(directory, item)
                    try:
                        if os.path.isfile(item_path):
                            os.unlink(item_path)
                            logging.debug(f"Deleted file: {item_path}")
                        elif os.path.isdir(item_path):
                            try:
                                shutil.rmtree(item_path)
                            except Exception as e:
                                logging.error(f"Error removing {item_path}: {e}")
                            logging.debug(f"Deleted directory: {item_path}")
                    except Exception as e:
                        logging.error(f"Error removing {item_path}: {e}", exc_info=True)
                return True
            except Exception as e:
                logging.error(f"Error cleaning directory {directory}: {e}", exc_info=True)
                return False
        else:
            os.makedirs(directory, exist_ok=True)
            logging.info(f"Created new directory: {directory}")
            return True

    @staticmethod
    def delete_directory(directory):
        """
        Delete a directory and all its contents.
        
        Args:
            directory: Path to the directory to delete
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        if os.path.exists(directory):
            logging.info(f"Deleting directory: {directory}")
            try:
                shutil.rmtree(directory)
                logging.info(f"Successfully deleted directory: {directory}")
                return True
            except Exception as e:
                logging.error(f"Error deleting directory {directory}: {e}", exc_info=True)
                return False
        else:
            logging.warning(f"Directory does not exist: {directory}")
            return False

    @staticmethod
    def render_jinja_template(template_file, output_file, **kwargs):
        """Render a Jinja2 template to an output file."""
        try:
            env = Environment(loader=FileSystemLoader(Paths.TEMPLATES_DIR))
            template = env.get_template(os.path.basename(template_file))
            output = template.render(**kwargs)
            
            return CommonFile.save_file(output, output_file)
        except Exception as e:
            logging.error(f"Error rendering template {template_file} to {output_file}: {e}", exc_info=True)
            return False

    @staticmethod
    def calculate_folder_hash(folder_path):
        """
        Calculate MD5 hash of a folder by combining hashes of all files within it recursively.
        
        Args:
            folder_path (str): Path to the folder to hash
            
        Returns:
            str: MD5 hash of the folder contents
        """
        if not os.path.isdir(folder_path):
            logging.error(f"Path is not a directory: {folder_path}")
            return None
        
        try:
            logging.info(f"Calculating hash for folder: {folder_path}")
            md5_hash = hashlib.md5()
            
            # Get all files in the directory and subdirectories
            file_paths = []
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    # Skip temporary files and hidden files
                    if not os.path.basename(file_path).startswith('.'):
                        file_paths.append(file_path)
            
            # Sort files to ensure consistent hash calculation
            file_paths.sort()
            
            # Calculate hash for each file and update the folder hash
            for file_path in file_paths:
                try:
                    with open(file_path, 'rb') as f:
                        # Read in chunks to handle large files
                        for chunk in iter(lambda: f.read(4096), b''):
                            md5_hash.update(chunk)
                    
                    # Add file path to hash to account for directory structure
                    md5_hash.update(os.path.relpath(file_path, folder_path).encode())
                except Exception as e:
                    logging.warning(f"Error hashing file {file_path}: {e}")
                    continue
            
            return md5_hash.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating folder hash: {e}", exc_info=True)
            return None

    @staticmethod
    def update_lock_file(folder_path, folder_date=None):
        """
        Update the .lock file with folder hash information.
        
        Args:
            folder_path (str): Full path to the folder to hash and record
            folder_date (float, optional): Timestamp to use for the folder. 
                                           If None, current time is used.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            lock_file_path = Paths.LOCK_FILE
            
            # Extract folder name from path for lock file entry
            # The folder name should be the last component (e.g., 'yaml' or 'csv')
            folder_name = os.path.basename(folder_path)
            
            # Calculate folder hash
            folder_hash = CommonFile.calculate_folder_hash(folder_path)
            if not folder_hash:
                logging.error(f"Failed to calculate hash for folder: {folder_name}")
                return False
            
            # Use provided date or current timestamp
            if folder_date is None:
                folder_date = time.time()
            
            # Load existing lock file if it exists
            lock_data = []
            if os.path.exists(lock_file_path):
                try:
                    with open(lock_file_path, 'r', encoding='utf-8') as file:
                        lock_data = yaml.safe_load(file) or []
                        if not isinstance(lock_data, list):
                            lock_data = []
                except Exception as e:
                    logging.warning(f"Error reading .lock file, creating new: {e}")
                    lock_data = []
            
            # Check if folder entry already exists
            folder_entry = None
            for entry in lock_data:
                if entry.get('name') == folder_name:
                    folder_entry = entry
                    break
            
            # Update existing entry or create new one
            if folder_entry:
                folder_entry['hash'] = folder_hash
                folder_entry['date'] = folder_date
            else:
                lock_data.append({
                    'name': folder_name,
                    'hash': folder_hash,
                    'date': folder_date
                })
            
            # Write updated data to lock file
            with open(lock_file_path, 'w', encoding='utf-8') as file:
                yaml.dump(lock_data, file, sort_keys=False, default_flow_style=False)
            
            logging.info(f"Updated .lock file with folder: {folder_name}, hash: {folder_hash[:6]}...")
            return True
        
        except Exception as e:
            logging.error(f"Error updating .lock file: {e}", exc_info=True)
            return False

##########################################################################
# CommonData Class
##########################################################################

class CommonData:
    """Common data processing utilities class."""
    
    @staticmethod
    def parse_priority_name(full_name):
        """
        Parse priority-prefixed name into (priority, actual_name).
        
        Examples:
            "15000_NEW_DNAT_RCG" → (15000, "NEW_DNAT_RCG")
            "00260_SERVICES_TAGS" → (260, "SERVICES_TAGS")
            "200_Allow_HTTPS"    → (200, "Allow_HTTPS")
            "No_Priority_Here"   → (None, "No_Priority_Here")
        
        Args:
            full_name (str): Full name with optional priority prefix
            
        Returns:
            tuple: (priority, actual_name) where priority is int or None
        """
        if not full_name or not isinstance(full_name, str):
            return None, full_name
        
        parts = full_name.split('_', 1)
        if len(parts) == 2 and parts[0].isdigit():
            return int(parts[0]), parts[1]
        return None, full_name
    
    @staticmethod
    def ensure_list(value):
        """Ensure the value is a list."""
        if isinstance(value, list):
            return value
        elif value is None:
            return []
        elif isinstance(value, str):
            return [value]
        return [str(value)]

    @staticmethod
    def normalize_name(name):
        """Normalize a name by replacing '-', '_-_', and '.' with underscores."""
        if not name:
            return ""
        # Replace '_-_' with '_', then '-' with '_', then '.' with '_'
        name = name.replace('_-_', '_')
        name = name.replace('---', '_')
        name = name.replace('-', '_')
        name = name.replace('.', '_')
        return name

    @staticmethod
    def separate_name_suffix(name, with_date=False):
        """
        Separate a name from its date suffix.
        
        Separates suffix patterns like '_YYYYMMDD', '_YYYYMMDD_HHMM', or '-YYYYMMDD_HHMM_randomstring' 
        that are often added to resource names in ARM templates.
        Optionally returns the date if found in the suffix.
        
        Args:
            name (str): The name which may contain a date suffix
            with_date (bool): If True, also return the date (as string) if found
            
        Returns:
            tuple: (name_without_suffix, suffix) or (name_without_suffix, suffix, date)
                   - name_without_suffix is the name with any date suffix removed
                   - suffix is the date suffix that was removed, or None if no suffix was found
                   - date is the 8-digit date string if found, else None (only if with_date=True)
        """
        if not name:
            return ("", None, None) if with_date else ("", None)
        
        # Combined pattern: _YYYYMMDD or [-_]YYYYMMDD_HHMM_randomstring (HHMM is optional for backward compatibility)
        match = re.search(r'([-_](\d{8})(?:_\d{4})?(?:_[a-z0-9]+)?)$', name)
        
        if match:
            suffix = match.group(1)
            date = match.group(2)
            name_without_suffix = name[:-len(suffix)]
            return (name_without_suffix, suffix, date) if with_date else (name_without_suffix, suffix)
        
        # No suffix found
        return (name, None, None) if with_date else (name, None)

    @staticmethod
    def get_id_with_date():
        """
        Generate an ID combined with today's date and time using the hash from .lock file.
        
        This function:
        1. Reads the hash for yaml folder from the .lock file and takes the first 7 characters
        2. Combines it with the current date and time in YYYYMMDD_HHMM format
        
        Returns:
            str: Formatted string as 'YYYYMMDD_HHMM_hash7chars' (e.g., '20250612_1435_34ab70b')
                 or None if an error occurs
        
        Raises:
            ValueError: If .lock file doesn't exist or has invalid format
        """
        
        logging.info("Generating ID with date and time from yaml folder hash...")
        
        try:
            # Get current date and time in YYYYMMDD_HHMM format
            date_str = datetime.now().strftime("%Y%m%d_%H%M")
            
            # Path to .lock file at the project root
            lock_file_path = Paths.LOCK_FILE
            
            # Read the hash for yaml from .lock
            if os.path.exists(lock_file_path):
                with open(lock_file_path, 'r') as file:
                    lock_data = yaml.safe_load(file) or []
                    
                    # Find the entry for yaml folder
                    policies_entry = next((entry for entry in lock_data if entry.get('name') == Paths.POLICIES_FOLDER_NAME), None)
                    
                    if policies_entry and 'hash' in policies_entry:
                        # Extract the hash and take first 7 chars
                        policies_hash = policies_entry['hash'][:7]
                        # Combine date/time and hash
                        result = f"{date_str}_{policies_hash}"
                        logging.info(f"Generated ID with date/time and _policies hash: {result}")
                        return result
                    else:
                        error_msg = "No _policies entry found in .lock file. Please run a policy sync operation to regenerate it."
                        logging.error(error_msg)
                        raise ValueError(error_msg)
            else:
                error_msg = ".lock file not found. Please run a policy sync operation to generate it."
                logging.error(error_msg)
                raise ValueError(error_msg)
            
        except Exception as e:
            if isinstance(e, ValueError):
                # Re-raise ValueError exceptions
                raise
            
            error_msg = f"Error generating ID: {str(e)}. Please run a policy sync operation to resolve this issue."
            logging.error(error_msg, exc_info=True)
            raise ValueError(error_msg)

    @staticmethod
    def extract_logical_resources(resources_list):
        """
        Extract logical resources from a list of resources.
        
        This function maps resources to their logical identifiers to enable matching
        resources regardless of the string format used to represent their names.
        
        Args:
            resources_list (list): A list of resource objects
            
        Returns:
            dict: A dictionary mapping logical resource identifiers to their original objects
        """
        from src.libraries.CompareUtils import normalize_resource_name
        logical_resources = {}
        
        for resource in resources_list:
            if isinstance(resource, dict) and 'type' in resource and 'name' in resource:
                # Extract logical identifier for this resource
                resource_type = resource['type']
                resource_name = normalize_resource_name(resource['name'])

                # For rule collections, use just the last part (RCG name) after normalization
                if resource_type == "Microsoft.Network/firewallPolicies/ruleCollectionGroups" and '/' in resource_name:
                    parts = resource_name.split('/')
                    # Normalize both policy and RCG name
                    policy_name = CommonData.separate_name_suffix(parts[0])[0]
                    rcg_name = CommonData.separate_name_suffix(parts[-1])[0]
                    logical_id = f"RCG:{policy_name}/{rcg_name}"
                # For main policy resources, standardize the name without date/hash suffix
                elif resource_type == "Microsoft.Network/firewallPolicies":
                    policy_name = CommonData.separate_name_suffix(resource_name)[0]
                    logical_id = f"Policy:{policy_name}"
                # For other resource types, use type and full normalized name
                else:
                    logical_id = f"{resource_type}:{resource_name}"
                
                if logical_id:
                    # Use the logical identifier as the key
                    logical_resources[logical_id] = resource
        
        return logical_resources

    @staticmethod
    def compare_resource_collections(import_resources, export_resources):
        """
        Compare collections of resources based on their logical identifiers.

        This function matches resources by their logical identifiers (normalized) and
        compares their content, categorizing differences as import_only, export_only,
        or values_changed.

        Args:
            import_resources (list): List of resources from the import file
            export_resources (list): List of resources from the export file

        Returns:
            dict: Dictionary with categorized differences
        """
        from deepdiff import DeepDiff
        from src.libraries.CompareUtils import normalize_resource_names_in_json
        
        # Extract logical resource identifiers
        import_logical = CommonData.extract_logical_resources(import_resources)
        export_logical = CommonData.extract_logical_resources(export_resources)

        # Find resources only in import
        import_only_ids = set(import_logical.keys()) - set(export_logical.keys())
        import_only = {name: import_logical[name] for name in import_only_ids}

        # Fix the error in export_only_ids calculation
        export_only_ids = set(export_logical.keys()) - set(import_logical.keys())
        export_only = {name: export_logical[name] for name in export_only_ids}

        # Find resources in both but with differences
        common_ids = set(import_logical.keys()) & set(export_logical.keys())
        values_changed = {}
        
        # Helper function to parse DeepDiff path strings like root['a'][0]['b'] with meaningful names
        def parse_path_with_names(path_str, obj):
            tokens = re.findall(r"\['([^']+)\']|\[(\d+)\]", path_str)
            result = []
            current_obj = obj

            for i, (k, idx) in enumerate(tokens):
                if k:
                    result.append(k)
                    if isinstance(current_obj, dict):
                        current_obj = current_obj.get(k, {})
                else:
                    idx = int(idx)
                    if isinstance(current_obj, list) and idx < len(current_obj):
                        if 'name' in current_obj[idx]:
                            name = current_obj[idx]['name']
                            result.append(name)
                            
                            # Track the current object context
                            if i > 0 and result[-2] in ['ruleCollections', 'rules']:
                                current_obj = current_obj[idx]
                            else:
                                current_obj = current_obj[idx]
                        else:
                            result.append(idx)
                            current_obj = current_obj[idx]
                    else:
                        result.append(idx)
                        

            return result
            
        # Function to convert a parsed path back to a DeepDiff-style path string
        def path_to_string(path_parts):
            result = "root"
            for part in path_parts:
                if isinstance(part, int):
                    result += f"[{part}]"
                else:
                    result += f"['{part}']"
            return result

        # Helper function to extract minimal diff structure
        def extract_minimal_diff(import_obj, export_obj, diff_dict):
            """
            Given two objects and a DeepDiff diff dict, extract only the changed keys and their parent structure.
            Returns a tuple: (import_minimal, export_minimal)
            """
            def set_nested(d, path, value):
                for key in path[:-1]:
                    if isinstance(key, int):
                        if not isinstance(d, list):
                            logging.warning(f"Expected list at path {path}, but found {type(d).__name__}. Skipping.")
                            return
                        while len(d) <= key:
                            d.append({})
                        d = d[key]
                    else:
                        if not isinstance(d, dict):
                            logging.warning(f"Expected dict at path {path}, but found {type(d).__name__}. Skipping.")
                            return
                        if key not in d:
                            d[key] = {} if not isinstance(path[-1], int) else []
                        d = d[key]
                if isinstance(path[-1], int):
                    if not isinstance(d, list):
                        logging.warning(f"Expected list at path {path}, but found {type(d).__name__}. Skipping.")
                        return
                    while len(d) <= path[-1]:
                        d.append({})
                    d[path[-1]] = value
                else:
                    if not isinstance(d, dict):
                        logging.warning(f"Expected dict at path {path}, but found {type(d).__name__}. Skipping.")
                        return
                    d[path[-1]] = value

            def get_by_path(obj, path):
                """Retrieve a value from a nested object using a list of keys/indices."""
                for p in path:
                    if isinstance(obj, list) and isinstance(p, int):
                        if p < len(obj):
                            obj = obj[p]
                        else:
                            return None
                    elif isinstance(obj, dict) and p in obj:
                        obj = obj[p]
                    else:
                        return None
                return obj

            import_minimal = {}
            export_minimal = {}

            # Handle changed values
            for k, v in diff_dict.get('values_changed', {}).items():
                path = parse_path_with_names(k, import_obj)
                old_value = v.get('old_value')
                new_value = v.get('new_value')
                set_nested(import_minimal, path, old_value)
                set_nested(export_minimal, path, new_value)

            # Handle added/removed dictionary items
            for k, v in diff_dict.get('dictionary_item_added', {}).items():
                path = parse_path_with_names(k, export_obj)
                export_val = get_by_path(export_obj, path)
                set_nested(export_minimal, path, export_val)
                
            for k, v in diff_dict.get('dictionary_item_removed', {}).items():
                path = parse_path_with_names(k, import_obj)
                import_val = get_by_path(import_obj, path)
                set_nested(import_minimal, path, import_val)

            # Handle added/removed iterable items
            for k, v in diff_dict.get('iterable_item_added', {}).items():
                path = parse_path_with_names(k, export_obj)
                set_nested(export_minimal, path, v)
                
            for k, v in diff_dict.get('iterable_item_removed', {}).items():
                path = parse_path_with_names(k, import_obj)
                set_nested(import_minimal, path, v)

            return import_minimal, export_minimal

        for res_id in common_ids:
            import_resource = normalize_resource_names_in_json(dict(import_logical[res_id]))
            export_resource = normalize_resource_names_in_json(dict(export_logical[res_id]))

            # Remove ignored keys (e.g., `dependsOn`)
            keys_to_ignore = {"dependsOn"}
            import_resource = CommonData.remove_ignored_keys(import_resource, keys_to_ignore)
            export_resource = CommonData.remove_ignored_keys(export_resource, keys_to_ignore)

            import_resource = CommonData.handle_empty_and_missing(import_resource)
            export_resource = CommonData.handle_empty_and_missing(export_resource)

            diff = DeepDiff(import_resource, export_resource, 
                           ignore_order=True, 
                           report_repetition=True,
                           verbose_level=2)

            if diff:
                import_minimal, export_minimal = extract_minimal_diff(import_resource, export_resource, diff.to_dict())
                import_name = import_logical[res_id].get('name', res_id)
                export_name = export_logical[res_id].get('name', res_id)
                
                # Process the diff to use rule collection and rule names instead of indices
                processed_diff = {}
                
                for diff_type, diff_items in diff.to_dict().items():
                    processed_diff[diff_type] = {}
                    
                    for path, value in diff_items.items():
                        if diff_type == 'values_changed':
                            parsed_path = parse_path_with_names(path, import_resource)
                            new_path = path_to_string(parsed_path)
                            processed_diff[diff_type][new_path] = value
                            
                            # Fix the minimal diff with the actual values from the diff
                            old_value = value.get('old_value')
                            new_value = value.get('new_value')
                            
                            # Apply to import_minimal
                            obj = import_minimal
                            i = -1  # Initialize i before the loop
                            for i, p in enumerate(parsed_path[:-1]):
                                if isinstance(p, int) and isinstance(obj, list) and p < len(obj):
                                    obj = obj[p]
                                elif isinstance(p, str) and isinstance(obj, dict) and p in obj:
                                    obj = obj[p]
                                else:
                                    break
                            # Only check if i has reached the expected position in the path
                            if i >= 0 and i == len(parsed_path) - 2 and parsed_path[-1] in obj:
                                obj[parsed_path[-1]] = old_value
                                
                            # Apply to export_minimal
                            obj = export_minimal
                            i = -1  # Initialize i before the loop
                            for i, p in enumerate(parsed_path[:-1]):
                                if isinstance(p, int) and isinstance(obj, list) and p < len(obj):
                                    obj = obj[p]
                                elif isinstance(p, str) and isinstance(obj, dict) and p in obj:
                                    obj = obj[p]
                                else:
                                    break
                            # Only check if i has reached the expected position in the path
                            if i >= 0 and i == len(parsed_path) - 2 and parsed_path[-1] in obj:
                                obj[parsed_path[-1]] = new_value
                            
                        elif diff_type in ['dictionary_item_added', 'iterable_item_added']:
                            parsed_path = parse_path_with_names(path, export_resource)
                            new_path = path_to_string(parsed_path)
                            processed_diff[diff_type][new_path] = value
                        elif diff_type in ['dictionary_item_removed', 'iterable_item_removed']:
                            parsed_path = parse_path_with_names(path, import_resource)
                            new_path = path_to_string(parsed_path)
                            processed_diff[diff_type][new_path] = value
                        else:
                            processed_diff[diff_type][path] = value
                
                values_changed[res_id] = {
                    "import": {
                        "name": import_name,
                        "content": import_minimal
                    },
                    "export": {
                        "name": export_name,
                        "content": export_minimal
                    },
                    "diff": processed_diff
                }

        return {
            "import_only": import_only,
            "export_only": export_only,
            "values_changed": values_changed
        }

    @staticmethod
    def handle_empty_and_missing(data):
        """
        Handle empty arrays, missing keys, and sort lists for comparison.

        Args:
            data: The data to process

        Returns:
            Processed data with empty arrays/missing keys handled and lists sorted
        """
        if isinstance(data, list):
            # For lists of dictionaries, sort them by 'name' key if available
            if all(isinstance(item, dict) for item in data) and all('name' in item for item in data):
                return sorted(data, key=lambda x: x['name'])
            return sorted(data) if all(isinstance(item, (str, int, float, bool)) for item in data) else data
        elif isinstance(data, dict):
            return {k: CommonData.handle_empty_and_missing(v) for k, v in sorted(data.items())}
        elif data is None:
            return []  # Treat None as an empty list
        return data

    @staticmethod
    def remove_ignored_keys(data, keys_to_ignore):
        """
        Recursively remove specified keys from a dictionary or list.

        Args:
            data: The data to process (dict or list).
            keys_to_ignore: A set of keys to remove.

        Returns:
            The data with specified keys removed.
        """
        if isinstance(data, dict):
            return {k: CommonData.remove_ignored_keys(v, keys_to_ignore) for k, v in data.items() if k not in keys_to_ignore}
        elif isinstance(data, list):
            return [CommonData.remove_ignored_keys(item, keys_to_ignore) for item in data]
        return data


class CommonInteraction:
    """
    Common utilities for interactive user prompts and selections.
    Provides reusable methods for user input handling to reduce code duplication.
    """

    @staticmethod
    def prompt_user_selection(
        items,
        prompt_message="Select an option",
        item_formatter=None,
        allow_cancel=True,
        allow_skip=False,
        allow_text_input=False,
        cancel_keys=None,
        skip_keys=None
    ):
        """
        Generic selection prompt that displays items and handles user input.
        
        Args:
            items: List or dict of items to display
            prompt_message: Message to show before selection options
            item_formatter: Optional function to format each item for display
                          Signature: (index, item) -> str
            allow_cancel: Whether to allow user to cancel (default: True)
            allow_skip: Whether to allow user to skip (default: False)
            allow_text_input: Whether to allow direct text input instead of numeric (default: False)
            cancel_keys: List of keys that trigger cancellation (default: ['q', 'quit'])
            skip_keys: List of keys that trigger skip (default: ['s', 'skip'])
            
        Returns:
            tuple: (selected_item, action)
                   action can be: 'selected', 'cancelled', 'skipped', 'text_input'
                   selected_item is None for 'cancelled' and 'skipped' actions
        """
        if cancel_keys is None:
            cancel_keys = ['q', 'quit']
        if skip_keys is None:
            skip_keys = ['s', 'skip']
        
        # Convert dict to list if needed, preserving keys
        if isinstance(items, dict):
            item_list = list(items.items())
            is_dict = True
        else:
            item_list = items
            is_dict = False
        
        if not item_list:
            logging.warning("No items to select from")
            return None, 'cancelled'
        
        # Display items
        print(f"\n{prompt_message}:")
        for i, item in enumerate(item_list, 1):
            if item_formatter:
                formatted = item_formatter(i, item)
            else:
                # Default formatting
                if is_dict:
                    formatted = f"{item[0]}: {item[1]}"
                else:
                    formatted = str(item)
            print(f"  {i}. {formatted}")
        
        # Build help message
        help_parts = []
        if allow_cancel:
            help_parts.append("'q' to cancel")
        if allow_skip:
            help_parts.append("'s' to skip")
        if allow_text_input:
            help_parts.append("or enter name directly")
        
        help_message = ", ".join(help_parts) if help_parts else ""
        prompt = f"Enter selection number{' (' + help_message + ')' if help_message else ''}: "
        
        while True:
            try:
                user_input = input(prompt).strip().lower()
                
                # Check for cancel
                if allow_cancel and user_input in cancel_keys:
                    return None, 'cancelled'
                
                # Check for skip
                if allow_skip and user_input in skip_keys:
                    return None, 'skipped'
                
                # Try numeric input first
                try:
                    choice = int(user_input)
                    if 1 <= choice <= len(item_list):
                        selected = item_list[choice - 1]
                        # Return key-value pair for dicts, item for lists
                        return selected if is_dict else selected, 'selected'
                    else:
                        print(f"Please enter a number between 1 and {len(item_list)}")
                        continue
                except ValueError:
                    # Not a number
                    if allow_text_input:
                        # Allow direct text input
                        if is_dict:
                            # Check if input matches any key
                            matching = [item for item in item_list if user_input == item[0].lower()]
                            if matching:
                                return matching[0], 'text_input'
                        else:
                            # Check if input matches any item (case-insensitive)
                            matching = [item for item in item_list if user_input == str(item).lower()]
                            if matching:
                                return matching[0], 'text_input'
                        print(f"'{user_input}' not found. Please enter a number or valid name.")
                    else:
                        print("Invalid input. Please enter a number.")
                        
            except KeyboardInterrupt:
                print("\nOperation cancelled by user")
                return None, 'cancelled'
            except EOFError:
                print("\nEnd of input stream")
                return None, 'cancelled'


