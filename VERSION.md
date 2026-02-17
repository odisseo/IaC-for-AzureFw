# Versions

## V. 1.10 (February 17, 2026)
- **Enhanced policy suffix format with timestamp**: Changed policy naming suffix from `_YYYYMMDD_hash` to `_YYYYMMDD_HHMM_hash`
  - Includes hours and minutes in the suffix (e.g., `parent_20260217_1435_6269c7f`)
  - Provides better versioning granularity for multiple exports on the same day
  - Eliminates the need for complex state tracking across developer branches
  - Updated `get_id_with_date()` in CommonUtils to generate timestamp-based suffixes
  - Updated `separate_name_suffix()` regex pattern to parse new format while maintaining backward compatibility
- **Improved SNAT handling in Bicep templates**: Fixed empty SNAT property rendering
  - Empty `snat:` in YAML now correctly renders as `snat: {}` in Bicep output (single line)
  - Previously would render as multi-line empty block or be omitted entirely
  - Changed condition from `{% if policy_data.get("snat") is not none %}` to `{% if "snat" in policy_data %}`
  - Added logic to detect empty vs. populated SNAT properties for proper formatting

## V. 1.9 (February 3, 2026)
- **Fixed comparison logic to eliminate false positives**: Replaced DeepDiff-based comparison with custom field-by-field normalization
- **Implemented canonical rule normalization**: Added `normalize_rule()` function to standardize both ARM JSON and YAML structures
  - Converts null/None values to empty arrays [] for consistent comparison
  - Sorts all array fields (sourceAddresses, destinationAddresses, targetFqdns, etc.)
  - Normalizes dictionary arrays using JSON string representation for stable comparison
  - Handles structural differences between ARM templates (null values) and YAML (empty/missing values)
- **Enhanced comparison accuracy**: Created `compare_rules()` function for granular field-by-field comparison
  - Returns detailed difference list with field name, Azure value, and local value
  - Eliminates false modifications caused by property ordering or structural differences
  - Properly identifies only actual rule content changes
- **Improved comparison workflow**: Updated comparison engine to use identity-based rule matching
  - Rules matched by name across ARM and YAML sources
  - Tracks rule_changes, rules_added, and rules_deleted separately
  - Correctly identifies priority changes as modifications, not deletions
- **Automated comparison in export workflow**: Added automatic comparison step after export but before git commit
  - Reuses firewall selection from export without re-prompting user
  - Provides immediate validation of exported policies against Azure
  - Streamlined workflow: sync → export → compare → commit
- **Enhanced comparison report formatting**: Improved Markdown output for better readability
  - Applied Jinja2 whitespace control ({%- -%}) to reduce excessive blank lines
  - Fixed HTML rendering with proper markdown list formatting
  - Positioned horizontal lines correctly under section headers only
  - Rule modifications display: "**Rule:** `name` **Field:** `field` **Before:** `value` **After:** `value`"
- **Bug fix**: Comparison now correctly shows only actual differences (e.g., TEST1 deleted, TEST3 priority changed) without false positive modifications

## V. 1.8 (February 3, 2026)
- **Complete redesign of policy comparison system**: Replaced ARM-to-ARM comparison with YAML-to-Azure comparison workflow
- **Identity-based matching**: Implemented priority-prefix parsing to distinguish priority changes from actual additions/deletions
  - Priority-prefixed names (e.g., "15000_NEW_DNAT_RCG") now correctly parsed to extract priority and actual name
  - RCGs, RCs, and rules matched by actual name instead of full priority-prefixed name
  - Priority changes now detected as modifications rather than delete+add operations
- **New comparison workflow**:
  1. Download ARM templates from Azure using AzureDownload class
  2. Normalize ARM JSON to standard policy structure
  3. Load local YAML policies from directory structure
  4. Compare with identity-based matching and DeepDiff
  5. Generate hierarchical Markdown report in root directory
- **New functions in CompareUtils.py**:
  - `parse_priority_name()`: Parse priority-prefixed names into (priority, actual_name) tuples
  - `normalize_arm_template()`: Transform ARM JSON to normalized policy structure
  - `load_policy_from_yaml()`: Read YAML directory tree and normalize to policy structure
  - `compare_policies()`: Identity-based comparison with priority change detection
  - `generate_comparison_report()`: Render Jinja2 template to Markdown output
- **New Jinja2 template**: Created `comparison.md.jinja2` for hierarchical Markdown reports
  - Summary table with added/modified/deleted counts
  - Emoji indicators (🟢 added, 🔴 deleted, 🟡 modified)
  - Collapsible details sections for modified rule collections
  - Priority change highlighting with before/after values
- **Updated OrchestratorUtils.py**: Replaced `handle_compare_arm()` with new workflow
  - Now requires `--policy-name` argument for targeted comparison
  - Step-by-step progress indicators with emoji feedback
  - Automatic cleanup of downloaded ARM files
  - Saves comparison reports to root directory as `comparison_{policy_name}.md`
- **Updated Parameters.py**: Added ROOT_DIR, POLICY_DIR, and TEMPLATE_DIR aliases
- **Breaking change**: Removed backward compatibility - old comparison functions deleted (no ARM-to-ARM comparison)
- **Improved accuracy**: Priority changes no longer create false positives in diff reports

## V. 1.7 (February 2, 2026)
- Added colored Git changes display before committing
- Implemented `display_git_changes()` function in GitUtils to show categorized file changes
- Enhanced commit workflow to display modified, added, and deleted files with color-coded output (green for added, yellow for modified, red for deleted)
- Improved visibility into Git operations before commits are executed
- Fixed filename parsing bug in git status output to correctly display all filenames

## V. 1.6 (January 21, 2026)
- simplified base_path in Parameters.py by removing redundant path constructions

## V. 1.5 (January 21, 2026)
- Implemented true parallel Bicep deployment across all firewalls using ThreadPoolExecutor
- Added deployment mode selection: Mode 1 (parallel) and Mode 2 (sequential with confirmation)
- Created new `deploy_resources_parallel_all()` method in AzureDeploy class for simultaneous multi-firewall deployment
- Refactored deployment workflow in OrchestratorUtils to support both parallel and sequential modes
- Authentication caching implemented to avoid redundant Azure logins in parallel mode
- Enhanced deployment summary showing success/failed counts across all firewalls with firewall-specific error reporting
- Parallel mode eliminates all confirmation prompts for streamlined automated deployments
- Sequential mode preserves per-file confirmation workflow for controlled deployments
- Non-interactive mode defaults to parallel deployment
- Improved error tracking with file-to-firewall mapping in error details
- All 3 firewalls now deploy concurrently instead of sequentially, reducing deployment time

## V. 1.4 (January 2026)
- Added `firewallSubscriptionId` field to firewall YAML configuration
- Separated firewall operations from policy operations with dedicated subscription IDs
- Updated all firewall-related Azure operations to use `firewallSubscriptionId`:
  - `get_firewalls_in_resource_group()` - listing firewalls
  - `get_current_policy_assignment()` - checking assigned policies
  - `assign_policy_to_firewall()` - assigning policies to firewalls
  - `_get_firewall_assigned_policy()` - retrieving firewall's current policy
- Modified `OrchestratorUtils.py` to extract and use `firewallSubscriptionId` in assignment workflow
- Updated `AzureUtils.py` download functions to pass both `policiesSubscriptionId` and `firewallSubscriptionId`
- Added `firewallSubscriptionId` to required fields validation
- Updated documentation with new field in example configurations
- Improved separation of concerns: policies and firewalls can now be in different subscriptions

## V. 1.3 (January 2026)
- Redesigned `export_policies()` workflow with explicit PROD→DR policy mapping based on firewall YAML `policiesName` indexes
- Refactored basePolicy handling: now stores separate `basePolicyName` (per-firewall) and `basePolicyVersion` (consistent across all firewalls)
- Updated policy YAML structure to maintain `basePolicyName` and `basePolicyVersion` as distinct fields during import
- Implemented automatic basePolicy ID construction during export: `/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/firewallPolicies/{name}_{version}`
- Added robust handling for both list and dict formats in `policiesName` field (supports legacy dict with integer keys)
- Simplified `handle_export_policies()` to call `export_policies(environment_name, version)` once instead of per-firewall loops
- Enhanced `import_policies()` to extract `basePolicyVersion` from ARM template ID using regex pattern: `_\d{8}_[a-f0-9]+$`
- Removed `_edit_region_name()` method - now uses explicit firewall YAML `basePolicyName` field for DR policy identification
- Added `_generate_bicep()` helper function for single policy export with basePolicy construction
- Updated `policy.yaml.jinja2` template to conditionally store `basePolicyName` and `basePolicyVersion` fields
- Fixed `policiesName` dict handling in `AzureUtils.py` and `OrchestratorUtils.py` for download and deploy operations
- Improved code maintainability by separating policy name and version concerns in basePolicy management

## V. 1.2 (December 2025)
- Standardized firewall YAML configuration structure across all firewall definitions
- Replaced legacy `fwPipPipxName` and `fwPipPipxValue` fields with unified `fwPip` structure
- Renamed `subscriptionId` to `policiesSubscriptionId` for better semantic clarity
- Added consistent field ordering in all firewall YAML files
- Ensured all firewall entries include required fields: `parentPolicyResourceGroup` and `parentPolicySubscriptionId`
- Updated all Python code references to use `policiesSubscriptionId` instead of `subscriptionId`
- Updated documentation (README files) to reflect new field naming conventions
- Improved naming consistency: `policiesSubscriptionId`, `ipGroupssubscriptionId`, `parentPolicySubscriptionId`
- Enhanced code maintainability with standardized configuration structure

## V. 1.1 (December 2025)
- Added automatic cleanup of temporary ARM directories after successful operations
- Implemented `delete_directory` utility function in CommonUtils.py for consistent directory deletion
- ARM import directory (`arm_import/`) is now automatically deleted after successful download and sync operations
- ARM export directory (`arm_export/`) is now automatically deleted after successful ARM template comparison
- Refactored path handling throughout the codebase for better maintainability
- Updated `update_lock_file` function to accept full folder paths instead of folder names
- Updated `sync_policies` function to use Paths constants (POLICIES_DIR, CSV_DIR) as default parameters
- Eliminated hardcoded path construction logic across multiple functions
- Improved code consistency by using centralized path constants from Parameters.py
- Enhanced user feedback with emoji indicators for cleanup operations (🗑️ for successful deletion, ⚠️ for warnings)

## V. 1.0 (October 2025)
- Official release of PoliFire version 1.0
- elimination of duplicate and not used code
- elimination of submodule
- organization in classes

## V. 0.36 (October 2025)
- Added fallback logic for parent policy parameters in firewall configurations
- Enhanced `export_policies_workflow()` to use `policiesResourceGroup` and `subscriptionId` as defaults when `parentPolicyResourceGroup` or `parentPolicySubscriptionId` are empty
- Improved cross-subscription parent policy reference handling in Bicep template generation
- Fixed basePolicy template rendering for scenarios where parent policy parameters are not explicitly configured
- Enhanced robustness of policy inheritance configuration across different firewall environments

## V. 0.35 (October 2025)
- Enhanced deployment naming strategy in DeployUtils.py
- Primary deployment ID now uses `get_id_with_date()` from policy synchronization hash for better traceability
- Fallback to `get_git_commit_id()` when policy hash is unavailable
- Improved deployment tracking consistency with folder hash mechanism
- Added robust error handling for deployment ID generation

## V. 0.34 (October 2025)
- Added automatic Windows list separator configuration for CSV compatibility
- Implemented `set_list_separator()` function in CommonUtils.py to set Windows registry list separator to semicolon (";")
- Integrated list separator configuration in main script startup and repository update operations
- Enhanced CSV file handling consistency across different Windows regional settings
- Improved system configuration management for better cross-regional compatibility

## V. 0.33 (August 2025)
- Added default tags when no custom tags are provided in both import and export templates
- Fixed typo in default tags (corrected "Enviroment" to "Environment")
- Made default tags consistent between import and export templates
- Ensured tag handling is consistent throughout the entire import/export cycle

## V. 0.32 (August 2025)
- Enhanced tag support: policy tags are now preserved throughout the entire import/export cycle
- Added tag extraction in collect_policy_data_from_yaml for accurate tag export to Bicep
- Fixed Bicep template rendering to properly include custom tags in exported resources
- Improved error handling for policy metadata processing

## V. 0.31 (August 2025)
- Import/export now supports Azure Firewall Policy 'insights' property (Log Analytics integration)
- Bicep export includes 'insights' and workspace external ID variable
- Export process improved: tags and SKU are preserved, output matches Azure ARM/Bicep structure
- Bugfix: YAML-to-Bicep export now handles all policy metadata and analytics settings

## V. 0.30 (August 2025)
- new option menu

## V. 0.29 (August 2025)
- resolved a bug with nat rule bicep for DR firewall
- created new Gitutils library

## V. 0.28 (July 2025)
- Added new comparison feature for python, not working on new .exe file

## V. 0.27 (July 2025)
- Resolved deploy error 
- Added new .exe file

## V. 0.26 (July 2025)
- Renamed `deploy_firewall_resources` function to `deploy_policies` in DeployUtils.py
- Updated all references to the renamed function in OrchestratorUtils.py
- Improved code clarity by using more specific function naming

## V. 0.25 (July 2025)
- Added `--loop` parameter to control whether the main program loops after operation
- Refactored program flow for better control of interaction modes
- Fixed utility function imports and workflow issues
- Renamed and relocated utility functions for better code organization
- Improved user experience with more intuitive command-line options

## V. 0.24 (July 2025)
- Implemented a robust folder hash and lock mechanism for policy synchronization
- Refactored SyncUtils.py to use a YAML-based `.lock` file instead of `.sync_lock`
- Added `calculate_folder_hash` and `update_lock_file` functions to CommonUtils.py
- Moved SyncUtils.py from `src/libraries_common/` to `src/libraries/` and updated all import references
- Enhanced sync logic to handle all folder existence/hash scenarios with intelligent conflict resolution
- Improved documentation and code organization throughout the codebase
- Added command-line option for conflict resolution (`--conflict-resolution`)

## V. 0.23 (July 2025)
- Removed `get_commit_id_with_date` function and all references
- Refactored `commit_changes_to_git` to only use the `changes_description` argument
- Removed all `git_id` logic and related tuple returns
- Moved all imports to the top of each Python file for consistency
- Cleaned up and modernized code for maintainability and clarity
- Updated OrchestratorUtils and CommonUtils to reflect these changes

## V. 0.22 (July 2025)
- Added policy assignment workflow for directly connecting policies to firewalls
- Reorganized CommonUtils.py into logical sections for better maintainability
- Consolidated environment selection logic with unified `get_environment` function
- Added interactive menu loop so users can perform multiple operations without restarting
- Enhanced policy and firewall listing functions in the Azure operations utilities
- Added new command-line option for listing available environments
- Improved code organization with clearer section headers and better documentation
- Code refactoring for better maintainability and extensibility

## V. 0.21 (Current)
- Project renamed to **PoliFire** (Azure Firewall Policies Infrastructure as Code)
- Improved workflow for ARM/Bicep comparison and deployment
- Enhanced error handling, logging, and user feedback
- New command-line arguments for automation and CI/CD
- Bicep filenames no longer include commit suffix; versioning is handled inside policy names
- Directory structure reorganized for clarity and automation

## V. 0.20 (Folder Structure Reorganization)
- Renamed `arm` directory to `arm_import` for clarity, storing imported ARM templates
- Added new `arm_export` directory to store ARM templates generated from Bicep files
- Added automatic Bicep to ARM template transpilation during export process
- Fixed indentation issues in ImportUtils.py for improved stability
- Removed unused parameters from Parameters.py
- Enhanced code organization and maintainability

## V. 0.19 (Enhanced Bicep Comparison Tool)
- Fixed and enhanced the Bicep/ARM template comparison functionality (option 6)
- Improved file matching logic to handle date-suffixed filenames and naming differences
- Added smarter normalization for matching files with hyphen/underscore differences
- Fixed an issue where the comparison was not finding matches for valid files
- Created a more robust implementation with better error handling

## V. 0.18 (Enhanced Bicep Comparison Tool)
- Improved Bicep comparison tool to support non-interactive mode
- Added command-line parameters for automated comparison without prompts:
  - `--include-diff` to include unified diff in the output
  - `--save-results` to save comparison results to files
- Automatically compares all Bicep files in the `bicep` folder with matching ARM templates in the `arm` folder
- Updated CLI help documentation with new examples

## V. 0.17 (Added Bicep Comparison Tool)
- Added a new tool for intelligent comparison of Bicep files with ARM templates
- Uses difflib to provide similarity scores and detailed difference reports
- Integrated as option 6 in the main menu: "Compare Biceps with ARM Templates"
- Supports saving comparison results to a file

## V. 0.16 (20252306)
- Removed ipgroups functions
- Download arm templates

## V. 0.15 (20252006)
- New export workflow: create bicep, git push, deploy

## V. 0.14 (20251806)
- New version of AzFwManager.exe
- Resolved naming convention issue with DR

## V. 0.13 (20250906)
- New version of FIREWALL_DATA
- Folder for firewall yaml files
- New --verbose parameter

## V. 0.12 (20252905)
- Changed the importpolicy
- Added the possibility to manage application, NAT and network rules
- Added the capacity to import csv and yaml in a folder with date

## V. 0.11 (20251905)
- Add matteo test parameter
- New Import and Export file.exe

## V. 0.10 (20251605)
- Add a new compiled python 'ExportPolicies.exe' and its updated '_internal/' data source folder.
- Add new delimiter "$"
- Add time.sleep function in ExportPolicies.exe

## V. 0.9 (20250505)
- Update 'scripts/libraries/Parameters.py'.
- Update 'scripts/ExportPolicies.py' with new parameters.
- Add a new compiled python 'ExportPolicies.exe' and its updated '_internal/' data source folder.

## V. 0.8 (20250403)
- Update 'scripts/libraries/Parameters.py' with 'test', 'prod', 'matteo', 'francisco'.
- Update 'scripts/ExportPolicies.py' with new parameters.
- Add a new compiled python 'ExportPolicies.exe' and its updated '_internal/' data source folder.

## V. 0.7 (20250402)
- Removed venv feature.
- Add Export and Import file '.exe'.
- Add '_internal/' folder.

## V. 0.6 (20250402)
- Removed the 'libraries_python/' folder
- Add virtual environment named 'env'.

## V. 0.5 (20250401)
- Fixed az cli User Path.
- Update function 'deploy_bicep' with powershell command instead of cmd.

## V. 0.4 (20250326)
- Add ipgroups incremental deployment with new function 'deploy_ipgroups()'.
- Split deploy function in 'deploy_ipgroups()' and 'deploy_bicep_files()'.
- Deployment priority is assigned first to ipgroups and then to parent and child policies.
- Add 'parameters.py' in 'libraries/'.
- Add parameters feature.

## V. 0.3 (20250325)
- Update function 'clean_output_directory()' in 'YamlUtils.py' library to delete only yaml files and not '.gitkeep' or 'readme.md' files. This edit is crucial to keep folder structure intact.
- Add new .gitkeep files.
- Update 'requirements.txt' file.
- Add 'scripts\libraries_python' to import libraries in repo folder.
- Updated scripts to use repo folder as libraries source.
- Update function 'deploy_bicep' in 'BicepUtils.py' with 'az.cmd' instead of 'az' to solve known issues with az cli installation path.

## V. 0.2 (20250324)
- Date format from "yyyyMMdd" to "yyyyMMddHHmmss"

## V. 0.1 (20250321)
- Multiple bicep file: 1 bicep for policy
  - Add 'P' or 'C' to deploy Parent policies first.
- az cli deployment in export policy