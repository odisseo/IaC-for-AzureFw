"""
Comparison utilities for Azure Firewall Policy Manager.

This module provides the functionality for comparing ARM templates between imported and exported versions.
"""
import os
import json
import logging
import re
import subprocess
from datetime import datetime
from deepdiff import DeepDiff
from src.libraries.Parameters import Paths, Config
from src.libraries.CommonUtils import remove_date_suffix, clean_directory, ensure_azure_login

def transpile_bicep_to_arm(bicep_file, arm_output_dir):
    """
    Transpile a Bicep file to an ARM template using the Azure CLI.
    
    Args:
        bicep_file: Path to the Bicep file
        arm_output_dir: Directory where the ARM template will be saved
        
    Returns:
        tuple: (success, output_file_path) where success is a boolean and
               output_file_path is the path to the generated ARM template
    """
    logging.info("Ensuring Azure authentication before transpiling Bicep...")
    ensure_azure_login()
    
    try:
        # Extract the filename without extension
        file_name = os.path.basename(bicep_file)
        file_name_no_ext = os.path.splitext(file_name)[0]
        
        # Define the output ARM template path
        arm_file_path = os.path.join(arm_output_dir, f"{file_name_no_ext}.json")
        
        # Build the az bicep build command
        command = f'az bicep build --file "{bicep_file}" --outfile "{arm_file_path}"'
        
        # Execute the command
        logging.info(f"Transpiling Bicep to ARM template: {bicep_file}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        
        # Check if the output file was created
        if os.path.exists(arm_file_path):
            logging.info(f"Successfully transpiled Bicep to ARM template: {arm_file_path}")
            return True, arm_file_path
        else:
            logging.error(f"ARM template file not created: {arm_file_path}")
            return False, None
            
    except subprocess.CalledProcessError as e:
        logging.error(f"Error transpiling Bicep to ARM template: {str(e)}")
        logging.error(f"Command output: {e.stdout}")
        logging.error(f"Command error: {e.stderr}")
        
        # Check for common errors and provide more helpful messages
        if "'az' is not recognized" in e.stderr:
            logging.error("Azure CLI ('az') is not installed or not in the PATH. Please install Azure CLI or add it to the PATH.")
        elif "bicep build" in e.stderr and "is not a valid" in e.stderr:
            logging.error("Azure CLI Bicep extension is not installed. Please run 'az bicep install' to install it.")
        
        return False, None
    except FileNotFoundError:
        logging.error("Azure CLI ('az') is not installed or not in the PATH. Please install Azure CLI or add it to the PATH.")
        return False, None
    except Exception as e:
        logging.error(f"Unexpected error transpiling Bicep to ARM template: {str(e)}")
        return False, None

def load_json_file(file_path):
    """
    Load a JSON file and return its contents.
    
    Args:
        file_path (str): Path to the JSON file
        
    Returns:
        dict: The contents of the JSON file or None if the file cannot be loaded
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
        logging.error(f"Failed to load JSON file {file_path}: {str(e)}")
        return None

def normalize_resource_name(name_value):
    """
    Normalize a resource name by converting format expressions to plain strings.
    
    Args:
        name_value (str): The resource name value to normalize
        
    Returns:
        str: The normalized resource name
    """
    if not isinstance(name_value, str):
        return name_value
    
    # Check if the name is a format expression like:
    # [format('{0}/{1}', 'TestEW_VNET00_GLOBAL_POLICY_P01_20250627_v7wlxg', '00260_AZURE_SERVICES_TAGS_RCG')]
    format_pattern = r'\[format\(\s*[\'"]([^\'"]*)[\'"]\s*,\s*[\'"]([^\'"]*)[\'"](?:\s*,\s*[\'"]([^\'"]*)[\'"])*\s*\)\]'
    
    match = re.match(format_pattern, name_value)
    if match:
        # Extract format string and parameters
        format_str = match.group(1)
        params = [match.group(2)]
        
        # Add additional parameters if they exist
        if match.group(3):
            params.append(match.group(3))
        
        # Replace placeholders in format string with parameters
        result = format_str
        for i, param in enumerate(params):
            result = result.replace(f'{{{i}}}', param)
        
        return result
    
    # Remove date suffixes from resource names for better matching
    # Example: TestEW_VNET00_GLOBAL_POLICY_P01_20250627_v7wlxg
    return remove_date_suffix(name_value)

def normalize_resource_names_in_json(json_data):
    """
    Recursively normalize resource names in a JSON object.
    
    Args:
        json_data: The JSON data to normalize
        
    Returns:
        The JSON data with normalized resource names
    """
    if isinstance(json_data, dict):
        result = {}
        for key, value in json_data.items():
            # If the key is 'name', normalize the value
            if key == 'name':
                result[key] = normalize_resource_name(value)
            else:
                result[key] = normalize_resource_names_in_json(value)
        return result
    elif isinstance(json_data, list):
        return [normalize_resource_names_in_json(item) for item in json_data]
    else:
        return json_data

def normalize_keys_for_comparison(json_data):
    """
    Normalize JSON data for comparison by sorting arrays and dictionaries.
    
    Args:
        json_data: The JSON data to normalize
        
    Returns:
        The normalized JSON data
    """
    if isinstance(json_data, dict):
        return {k: normalize_keys_for_comparison(v) for k, v in sorted(json_data.items())}
    elif isinstance(json_data, list):
        # For lists of dictionaries, try to sort them by a common key
        if all(isinstance(item, dict) for item in json_data):
            # Try to find a common key to sort by
            common_keys = set.intersection(*[set(item.keys()) for item in json_data]) if json_data else set()
            priority_keys = ['name', 'id', 'type']
            sort_key = next((k for k in priority_keys if k in common_keys), None)
            
            if sort_key:
                sorted_list = sorted(json_data, key=lambda x: x.get(sort_key, ''))
                return [normalize_keys_for_comparison(item) for item in sorted_list]
        
        # If not a list of dictionaries or no common key, just normalize each item
        return [normalize_keys_for_comparison(item) for item in json_data]
    else:
        return json_data

def get_resource_display_name(resource):
    """
    Get a human-readable display name for a resource.
    
    Args:
        resource (dict): A resource object
        
    Returns:
        str: A display name for the resource
    """
    if not isinstance(resource, dict):
        return "Unknown"
    
    name = resource.get('name', 'Unknown')
    
    # If it's a format expression, try to extract a more readable name
    if isinstance(name, str) and name.startswith('[format('):
        normalized = normalize_resource_name(name)
        return normalized
    
    return name

def compare_arm_templates(import_file, export_file, include_diff=False):
    """
    Compare two ARM templates and return the differences.
    
    Args:
        import_file (str): Path to the imported ARM template
        export_file (str): Path to the exported ARM template
        include_diff (bool): Whether to include the full diff in the output
        
    Returns:
        dict: A dictionary with comparison results
    """
    # Load JSON files
    import_data = load_json_file(import_file)
    export_data = load_json_file(export_file)
    
    if not import_data or not export_data:
        return {
            "success": False,
            "error": "Failed to load one or both JSON files",
            "import_file": import_file,
            "export_file": export_file,
            "import_data_loaded": import_data is not None,
            "export_data_loaded": export_data is not None
        }
    
    # First normalize resource names to handle format expressions
    import_normalized_names = normalize_resource_names_in_json(import_data)
    export_normalized_names = normalize_resource_names_in_json(export_data)
    
    # Make deep copies to avoid modifying the originals
    import_normalized_copy = dict(import_normalized_names)
    export_normalized_copy = dict(export_normalized_names)
    
    # Handle resources separately for better matching
    import_resources = import_normalized_copy.pop('resources', []) if 'resources' in import_normalized_copy else []
    export_resources = export_normalized_copy.pop('resources', []) if 'resources' in export_normalized_copy else []
    
    # Then normalize JSON data for comparison (sorting, etc.)
    import_normalized = normalize_keys_for_comparison(import_normalized_copy)
    export_normalized = normalize_keys_for_comparison(export_normalized_copy)
    
    # Compare the normalized data (excluding resources)
    diff = DeepDiff(import_normalized, export_normalized, 
                   ignore_order=True, 
                   report_repetition=True,
                   verbose_level=2)
    
    # Categorize differences by file (import vs export)
    import_only = {}
    export_only = {}
    values_changed = {}
    
    # Process differences (non-resource differences)
    if "dictionary_item_added" in diff:
        for key, value in diff["dictionary_item_added"].items():
            export_only[key] = value
            
    if "dictionary_item_removed" in diff:
        for key, value in diff["dictionary_item_removed"].items():
            import_only[key] = value
            
    if "values_changed" in diff:
        for key, value in diff["values_changed"].items():
            values_changed[key] = {
                "import": value["old_value"],
                "export": value["new_value"]
            }
    
    # Process array differences (except resources which are handled separately)
    if "iterable_item_added" in diff:
        for key, value in diff["iterable_item_added"].items():
            export_only[key] = value
            
    if "iterable_item_removed" in diff:
        for key, value in diff["iterable_item_removed"].items():
            import_only[key] = value
    
    # Special handling for resources
    resource_diff = compare_resource_collections(import_resources, export_resources)
    
    # Format resource differences for better readability
    formatted_import_only = {}
    formatted_export_only = {}
    formatted_values_changed = {}
    
    # Format import-only resources
    for res_id, resource in resource_diff['import_only'].items():
        display_name = get_resource_display_name(resource)
        formatted_import_only[display_name] = resource
    
    # Format export-only resources
    for res_id, resource in resource_diff['export_only'].items():
        display_name = get_resource_display_name(resource)
        formatted_export_only[display_name] = resource
    
    # Format changed resources
    for res_id, change_data in resource_diff['values_changed'].items():
        import_display = change_data['import']['name']
        export_display = change_data['export']['name']
        
        # Use a common display name if possible, otherwise show both
        if normalize_resource_name(import_display) == normalize_resource_name(export_display):
            display_name = normalize_resource_name(import_display)
        else:
            display_name = f"{import_display} <-> {export_display}"
        
        formatted_values_changed[display_name] = {
            "import": change_data['import']['content'],
            "export": change_data['export']['content'],
            "diff": change_data['diff']
        }
    
    # Add resource differences to the overall differences
    if formatted_import_only:
        import_only['resources'] = formatted_import_only
    
    if formatted_export_only:
        export_only['resources'] = formatted_export_only
    
    if formatted_values_changed:
        values_changed['resources'] = formatted_values_changed
    
    has_differences = bool(diff) or bool(resource_diff['import_only']) or bool(resource_diff['export_only']) or bool(resource_diff['values_changed'])
    
    # Prepare result
    result = {
        "success": True,
        "has_differences": has_differences,
        "import_file": import_file,
        "export_file": export_file,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Add categorized differences
    if has_differences:
        result["differences"] = {
            "import_only": import_only,
            "export_only": export_only,
            "values_changed": values_changed,
            "raw_diff": diff.to_dict() if include_diff else None
        }
    
    return result

def save_comparison_result(result, save_to_file=True):
    """
    Save the comparison result to a file and return a summary.
    
    Args:
        result (dict): The comparison result
        save_to_file (bool): Whether to save the result to a file
        
    Returns:
        str: A summary of the comparison result
    """
    if not result.get("success", False):
        return f"Comparison failed: {result.get('error', 'Unknown error')}"
    
    # Extract file names for the output file name
    import_file_name = os.path.basename(result["import_file"])
    export_file_name = os.path.basename(result["export_file"])
    
    # Create a summary
    if result["has_differences"]:
        differences = result.get("differences", {})
        summary = f"Differences found between {import_file_name} and {export_file_name}"
        
        # Count regular differences (non-resource differences)
        regular_import_only = {k: v for k, v in differences.get("import_only", {}).items() if k != 'resources'}
        regular_export_only = {k: v for k, v in differences.get("export_only", {}).items() if k != 'resources'}
        regular_values_changed = {k: v for k, v in differences.get("values_changed", {}).items() if k != 'resources'}
        
        import_only_count = len(regular_import_only)
        export_only_count = len(regular_export_only)
        values_changed_count = len(regular_values_changed)
        
        # Count resource differences
        resources_import_only = differences.get("import_only", {}).get("resources", {})
        resources_export_only = differences.get("export_only", {}).get("resources", {})
        resources_values_changed = differences.get("values_changed", {}).get("resources", {})
        
        import_only_resources_count = len(resources_import_only)
        export_only_resources_count = len(resources_export_only)
        changed_resources_count = len(resources_values_changed)
        
        # Add summary counts for non-resource differences
        if import_only_count > 0 or export_only_count > 0 or values_changed_count > 0:
            summary += "\n\nGeneral differences:"
            if import_only_count > 0:
                summary += f"\n - Items only in ARM Import file: {import_only_count}"
            if export_only_count > 0:
                summary += f"\n - Items only in ARM Export file: {export_only_count}"
            if values_changed_count > 0:
                summary += f"\n - Items with different values: {values_changed_count}"
        
        # Add resource-specific summary
        if import_only_resources_count > 0 or export_only_resources_count > 0 or changed_resources_count > 0:
            summary += "\n\nResource differences:"
            
            # Add resource counts
            if import_only_resources_count > 0:
                summary += f"\n - Resources only in ARM Import file: {import_only_resources_count}"
            if export_only_resources_count > 0:
                summary += f"\n - Resources only in ARM Export file: {export_only_resources_count}"
            if changed_resources_count > 0:
                summary += f"\n - Resources with different content: {changed_resources_count}"
            
            # List examples of resource differences
            if import_only_resources_count > 0:
                summary += "\n\nExamples of resources only in Import file:"
                for i, name in enumerate(list(resources_import_only.keys())[:3]):  # Show up to 3 examples
                    summary += f"\n - {name}"
                if import_only_resources_count > 3:
                    summary += f"\n   ... and {import_only_resources_count - 3} more"
            
            if export_only_resources_count > 0:
                summary += "\n\nExamples of resources only in Export file:"
                for i, name in enumerate(list(resources_export_only.keys())[:3]):  # Show up to 3 examples
                    summary += f"\n - {name}"
                if export_only_resources_count > 3:
                    summary += f"\n   ... and {export_only_resources_count - 3} more"
            
            if changed_resources_count > 0:
                summary += "\n\nExamples of resources with different content:"
                for i, name in enumerate(list(resources_values_changed.keys())[:3]):  # Show up to 3 examples
                    summary += f"\n - {name}"
                if changed_resources_count > 3:
                    summary += f"\n   ... and {changed_resources_count - 3} more"
        
        # Add info about name normalization
        summary += "\n\nNote: Resource names have been normalized for comparison:"
        summary += "\n - Format expressions like [format('{0}/{1}', 'Policy_20250627_v7wlxg', 'RCG_Name')] are"
        summary += "\n   treated as equivalent to 'Policy/RCG_Name'"
        summary += "\n - Date suffixes like '_20250627_v7wlxg' are removed for matching"
        summary += "\n - Resources are matched by their logical structure rather than exact string representation"
    else:
        summary = f"No differences found between {import_file_name} and {export_file_name}"
    
    # Save to file if requested
    if save_to_file:
        # Use only the date part (YYYYMMDD) without the time for overwriting files on the same day
        date_only = datetime.now().strftime("%Y%m%d")
        base_name = remove_date_suffix(os.path.splitext(import_file_name)[0])
        output_file = os.path.join(Paths.COMPARISON_DIR, f"comparison_{base_name}_{date_only}.json")
        
        try:
            # Save JSON result with clear formatting
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2)
            
            summary += f"\n\nComparison result saved to {output_file}"
        except Exception as e:
            logging.error(f"Failed to save comparison result: {str(e)}")
            summary += f"\n\nFailed to save comparison result: {str(e)}"
    
    return summary

def generate_arm_templates_from_bicep():
    """
    Generate ARM templates from all Bicep files in the bicep directory.
    
    This function should be called before comparing ARM templates to ensure
    the exported ARM templates are up-to-date with the Bicep files.
    
    Returns:
        tuple: (success, templates_dict) where:
            - success (bool): True if all templates were generated successfully
            - templates_dict (dict): A dictionary mapping Bicep filenames to generated ARM templates
    """
    logging.info("Generating ARM templates from Bicep files...")
    
    # Clean the ARM export directory first
    logging.info("Cleaning ARM export directory before generating templates...")
    if not clean_directory(Paths.ARM_EXPORT_DIR):
        logging.error("Failed to clean ARM export directory")
        return False, {}
    
    # Ensure ARM export directory exists (although clean_directory should create it if it doesn't exist)
    os.makedirs(Paths.ARM_EXPORT_DIR, exist_ok=True)
    
    # Get all Bicep files
    bicep_files = [f for f in os.listdir(Paths.BICEP_DIR) if f.endswith('.bicep')]
    
    if not bicep_files:
        logging.warning("No Bicep files found in bicep directory")
        return False, {}
    
    generated_templates = {}
    success_count = 0
    fail_count = 0
    
    for bicep_file in bicep_files:
        bicep_path = os.path.join(Paths.BICEP_DIR, bicep_file)
        
        # Transpile Bicep to ARM template
        success, arm_file_path = transpile_bicep_to_arm(bicep_path, Paths.ARM_EXPORT_DIR)
        
        if success:
            generated_templates[bicep_file] = arm_file_path
            success_count += 1
        else:
            logging.error(f"Failed to transpile Bicep file to ARM template: {bicep_file}")
            fail_count += 1
    
    # Log summary of generation results
    if fail_count == 0:
        logging.info(f"Successfully generated all {success_count} ARM templates from Bicep files")
        return True, generated_templates
    else:
        logging.error(f"Failed to generate {fail_count} of {len(bicep_files)} ARM templates from Bicep files")
        return False, generated_templates

def find_matching_templates():
    """
    Find matching ARM templates between import and export directories.
    
    Returns:
        list: A list of tuples (import_file, export_file) for matching templates
    """
    matches = []
    
    # Get all JSON files in the import directory
    import_files = [f for f in os.listdir(Paths.ARM_DIR) if f.endswith('.json')]
    
    # Get all JSON files in the export directory
    export_files = [f for f in os.listdir(Paths.ARM_EXPORT_DIR) if f.endswith('.json')]
    
    # For each import file, find a matching export file
    for import_file in import_files:
        # Remove date suffix from import file name
        base_name = remove_date_suffix(os.path.splitext(import_file)[0])
        
        # Look for a matching export file
        for export_file in export_files:
            export_base_name = os.path.splitext(export_file)[0]
            
            # If the base names match, add to matches
            if base_name == export_base_name:
                import_path = os.path.join(Paths.ARM_DIR, import_file)
                export_path = os.path.join(Paths.ARM_EXPORT_DIR, export_file)
                matches.append((import_path, export_path))
                break
    
    return matches

def extract_logical_resource_identifier(resource):
    """
    Extract a logical identifier for a resource that can be used for matching.
    
    This function creates a unique identifier based on the resource type and normalized name,
    allowing resources to be matched regardless of how their names are formatted.
    
    Args:
        resource (dict): A resource object
        
    Returns:
        str: A logical identifier for the resource
    """
    if not isinstance(resource, dict) or 'type' not in resource or 'name' not in resource:
        return None
    
    resource_type = resource['type']
    resource_name = normalize_resource_name(resource['name'])
    
    # For rule collections, use just the last part
    if resource_type == "Microsoft.Network/firewallPolicies/ruleCollectionGroups" and '/' in resource_name:
        parts = resource_name.split('/')
        return f"RCG:{parts[-1]}"
        
    # For main policy resources, standardize the name without date suffix
    if resource_type == "Microsoft.Network/firewallPolicies":
        return f"Policy:{resource_name.split('-')[0]}"
        
    # For other resource types, use type and full normalized name
    return f"{resource_type}:{resource_name}"

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
    logical_resources = {}
    
    for resource in resources_list:
        if isinstance(resource, dict):
            # Get the logical identifier for this resource
            logical_id = extract_logical_resource_identifier(resource)
            if logical_id:
                # Use the logical identifier as the key
                logical_resources[logical_id] = resource
    
    return logical_resources

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
    # Extract logical resource identifiers
    import_logical = extract_logical_resources(import_resources)
    export_logical = extract_logical_resources(export_resources)

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
        import_resource = remove_ignored_keys(import_resource, keys_to_ignore)
        export_resource = remove_ignored_keys(export_resource, keys_to_ignore)

        import_resource = handle_empty_and_missing(import_resource)
        export_resource = handle_empty_and_missing(export_resource)

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
        return {k: handle_empty_and_missing(v) for k, v in sorted(data.items())}
    elif data is None:
        return []  # Treat None as an empty list
    return data

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
        return {k: remove_ignored_keys(v, keys_to_ignore) for k, v in data.items() if k not in keys_to_ignore}
    elif isinstance(data, list):
        return [remove_ignored_keys(item, keys_to_ignore) for item in data]
    return data
