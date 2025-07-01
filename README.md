# Versions
## 0.21 (Enhanced Workflow and Error Handling)
- Renamed project to PoliFire (Azure Firewall Policies Infrastructure as Code)
- Added new commit suffix format (`_<datetime>_<six digits>` from `.sync_lock`)
- Enhanced ARM template comparison workflow:
  - Added option to download latest templates before comparison
  - Improved file matching logic and error handling
  - Added `--skip-download-prompt` flag for automated workflows
- Added `--clean-export` flag (default: true) to clean export directories before generation
- Enhanced error handling:
  - Better handling of missing/invalid `.sync_lock` file
  - Fixed UnboundLocalError in CompareUtils.py
  - Added validation for file naming conventions
- Improved Bicep file handling:
  - Bicep filenames no longer include commit_suffix
  - Policy names inside Bicep files maintain suffix for versioning
- Added new command line arguments:
  - `--commit-message`: Custom message for git commits
  - `--skip-download-prompt`: Skip template download prompt
  - `--clean-export`: Control export directory cleaning
- Updated documentation and help text with AFPIAC explanation
- Enhanced logging and user feedback
- Improved error messages and recovery suggestions

## 0.20 (Folder Structure Reorganization)
- Renamed `arm` directory to `arm_import` for clarity, storing imported ARM templates
- Added new `arm_export` directory to store ARM templates generated from Bicep files
- Added automatic Bicep to ARM template transpilation during export process
- Fixed indentation issues in ImportUtils.py for improved stability
- Removed unused parameters from Parameters.py
- Enhanced code organization and maintainability

## 0.19 (Enhanced Bicep Comparison Tool)
- Fixed and enhanced the Bicep/ARM template comparison functionality (option 6)
- Improved file matching logic to handle date-suffixed filenames and naming differences
- Added smarter normalization for matching files with hyphen/underscore differences
- Fixed an issue where the comparison was not finding matches for valid files
- Created a more robust implementation with better error handling

## 0.18 (Enhanced Bicep Comparison Tool)
- Improved Bicep comparison tool to support non-interactive mode
- Added command-line parameters for automated comparison without prompts:
  - `--include-diff` to include unified diff in the output
  - `--save-results` to save comparison results to files
- Automatically compares all Bicep files in the `bicep` folder with matching ARM templates in the `arm` folder
- Updated CLI help documentation with new examples

## 0.17 (Added Bicep Comparison Tool)
- Added a new tool for intelligent comparison of Bicep files with ARM templates
- Uses difflib to provide similarity scores and detailed difference reports
- Integrated as option 6 in the main menu: "Compare Biceps with ARM Templates"
- Supports saving comparison results to a file

## 0.16 (20252306)
- removed ipgroups functions
- download arm templates

## V. 0.15 (20252006)
- New export workflow: create bicep, git push, deploy

## V. 0.14 (20251806)
- new version of AzFwManager.exe
- Resolved naming convention issue with DR

## V. 0.13 (20250906)
- new version of FIREWALL_DATA
- folder for firewall yaml files
- new --verbose parameter

## V. 0.12 (20252905)
- changed the importpolicy
- added the possibility to manage application, NAT and network rules
- added the capacity to import csv and yaml in a folder with date

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

# Azure Firewall IaC project for NOC team

[[_TOC_]]

## Overview

AFPIAC (Azure Firewall Policies Infrastructure as Code) is a methodology for managing Azure Firewall policies through version-controlled configuration files rather than manual configuration. This project provides a complete workflow for managing Azure Firewall Policies using YAML files as the source of truth, with conversion to/from CSV and ARM/Bicep templates for deployment to Azure.

### Workflow

The AFPIAC workflow is designed to provide a complete Infrastructure as Code solution for Azure Firewall Policies:

::: mermaid
sequenceDiagram
    %% Declare participants in the desired order:
    participant Azure as Azure
    participant ARM as ARM Template
    participant YAML as YAML
    participant CSV as CSV
    participant Bicep as Bicep

    %% Download and Import flow:
    Azure->>ARM: Download Latest (op 2)
    ARM->>YAML: Import (op 3)
    
    %% Bidirectional sync:
    YAML-->>CSV: Sync (op 4)
    CSV-->>YAML: Sync (op 4)
    
    %% Export and Deploy flow:
    YAML->>Bicep: Export (op 5)
    Bicep->>Azure: Deploy (op 8)
    
    %% Comparison flow:
    Bicep->>ARM: Compare (op 6)
    ARM-->>Azure: Optional Download
    
    %% Version Control:
    Note over YAML,Bicep: Git Operations (op 1, 7)
:::

Key Operations:
1. Update local Git repository (pull latest changes)
2. Download latest ARM templates from Azure
3. Import policies from ARM templates to YAML
4. Synchronize between YAML and CSV formats
5. Export policies from YAML to Bicep
6. Compare ARM templates (Import vs Export)
7. Commit changes to Git repository
8. Deploy Bicep templates to Azure

File Versioning:
- All resources use a commit suffix format: `_<datetime>_<six digits>`
- Suffix is generated from `.sync_lock` file
- Bicep filenames do not include suffix
- Policy names inside files maintain suffix for versioning

### AzFwManager.py
::: mermaid
flowchart TD
    A[Start] --> B[Parse Arguments]
    B --> C{List Environments?}
    C -->|Yes| D[List Available Environments]
    C -->|No| E{Non-Interactive Mode?}
    D --> F[Exit]
    E -->|Yes| G{Operation Provided?}
    G -->|No| H[Error: Operation Required]
    G -->|Yes| I{Operation Choice}
    E -->|No| I{Operation Choice}    I -->|1: Update Repository| J[handle_update_repository]
    I -->|2: Download ARM Templates| N[handle_download_templates]
    I -->|3: Import Policies| K[handle_import_policies]
    I -->|4: Sync Policies| L[handle_sync_policies]
    I -->|5: Export Policies| M[handle_export_policies]
    I -->|6: Compare Biceps| O[handle_diff_biceps]
    J --> F
    K --> F
    L --> F
    M --> F
    N --> F
    O --> F

    click J call linkCallback("./scripts/libraries/OrchestratorUtils.py#L527")
    click K call linkCallback("./scripts/libraries/OrchestratorUtils.py#L589")
    click L call linkCallback("./scripts/libraries/OrchestratorUtils.py#L616")
    click M call linkCallback("./scripts/libraries/OrchestratorUtils.py#L638")
    click N call linkCallback("./scripts/libraries/OrchestratorUtils.py#L557")
    click O call linkCallback("./scripts/libraries/OrchestratorUtils.py#L800")
:::



## Directory Structure

Project Directories:
- `_firewalls/`: Contains firewall-related YAML configuration files
- `_policies/`: Contains Firewall Policies in YAML format (source of truth)
- `_csv/`: Contains Firewall Policies in CSV format (for easy editing)
- `arm_import/`: Stores downloaded ARM templates from Azure
- `arm_export/`: Contains ARM templates generated from Bicep files
- `bicep/`: Contains generated Bicep templates for deployment
- `comparison/`: Stores comparison results between templates
- `env/`: Contains the Python virtual environment
- `src/`: Main source code directory
  - `libraries/`: Core library modules
  - `templates/`: Jinja2 templates for file generation
- `docs/`: Documentation and utility scripts

Key Files:
- `AzFwManager.py`: Main entry point and CLI interface
- `.sync_lock`: Contains hash used for generating commit suffixes
- `requirements.txt`: Python package dependencies

### Key Scripts & Libraries

Core Components:
- `AzFwManager.py`: Main entry point and CLI interface
  - Parses arguments and manages environment modes
  - Provides interactive and non-interactive workflows
  - Integrates all component operations

Libraries (`src/libraries/`):
- `OrchestratorUtils.py`: Workflow coordination
  - Manages all operation handlers
  - Coordinates Git operations
  - Handles error recovery and user interaction

- `CommonUtils.py`: Core utilities
  - File and directory management
  - Template rendering (Jinja2)
  - Version suffix handling
  - Error handling and logging

- `Parameters.py`: Configuration management
  - CLI argument parsing
  - Environment settings
  - Global configuration
  - Subscription management

- `CompareUtils.py`: Template comparison
  - ARM template comparison logic
  - Similarity scoring
  - Difference reporting
  - File matching algorithms

- `ImportUtils.py`: Import operations
  - Downloads ARM templates from Azure
  - Converts ARM to YAML/CSV
  - Handles template versioning

- `ExportUtils.py`: Export operations
  - Generates Bicep from YAML/CSV
  - Manages export directories
  - Handles version suffixes

- `BicepUtils.py`: Bicep management
  - Builds Bicep resources
  - Manages policy naming
  - Handles deployment preparation

- `SyncUtils.py`: Synchronization
  - YAML/CSV synchronization
  - Conflict resolution
  - Change detection

- `DeployUtils.py`: Deployment
  - Bicep deployment to Azure
  - Environment validation
  - Deployment monitoring

- `CsvUtils.py`: CSV handling
  - CSV file processing
  - Data transformation
  - Template application

Each library follows SOLID principles and includes comprehensive error handling and logging. All operations support both interactive and non-interactive modes, with appropriate validation and error recovery.

With these scripts and libraries, you can import firewall policy data, transform it between JSON, CSV, and YAML, generate Bicep templates, and deploy everything to Azure.

## Getting Started
### Prerequisites
- PowerShell version >= 7.2.x
- Python version >= 3.10.x

### Installation
1. Clone the repository:
```sh
git clone <repository-url> # create the new repo folder in current system location
cd <repository-directory> # change directory path to the new repo folder
```
- Enable the git config to support longpaths `>= 260` chars on Windows:
```sh
# this configuration enables the creation of files with a fullpath exceeding 260 chars, due to a Windows limitation. Linux supports up to 4096 chars.
git config --global core.longpaths true
```

**IF YOU DON'T HAVE PYTHON IN YOUR MACHINE INSTALLED SKIP THE 2. PARAGRAPH**

2. (ONLY IF YOU ARE WORKING WITH PYTHON)
Activate the virtual environment `env`and install the requirements: (ONLY IF YOU ARE WORKING WITH PYTHON)
To get all the necessary python libraries, you must activate the virtual environment env.
Use this command:
  ```powershell
  .\env\Scripts\Activate.ps1
  ```
Then use this command to install all the requirements inside the venv env:
```sh
pip install -r .\requirements.txt 
```
**N.B. YOU NEED TO ACTIVATE YOUR VENV ENV EVERYTIME YOU WORK WITH THE SCRIPT. THE INSTALLATION OF THE REQUIREMENTS IS NECESSARY ONLY IF THEY ARE NOT YET BEEN INSTALLED**

To exit from the venv env, use this command:
  ```powershell
  deactivate
  ```


### Usage

This project provides a unified interface for managing Azure Firewall Policies as code, supporting import, export, synchronization, comparison, and deployment operations. All operations can be performed interactively or via command-line arguments for automation.

#### 1. Activate the Python Virtual Environment

Before running any scripts, activate the virtual environment and install dependencies (if not already done):

```powershell
./env/Scripts/Activate.ps1
pip install -r ./requirements.txt
```


#### 2. Run the Policy Manager

The main entry point is `policiesdeploy.py`. You can run it directly to access an interactive menu, or use command-line arguments for automation.

**Interactive Mode:**

```powershell
python policiesdeploy.py
```

You will be presented with a menu to choose from the following operations:

1. Update local Git repository (pull latest changes)
2. Download the latest ARM templates from Azure
3. Import policies from ARM templates to YAML/CSV
4. Synchronize policies between YAML and CSV formats
5. Export policies from YAML/CSV to Bicep templates
6. Compare ARM templates (Import vs Export)
7. Commit all changes to Git
8. Deploy new Bicep templates to Azure

**Non-Interactive Mode:**

You can automate any operation by specifying the `--operation` parameter (1-8) and other options as needed:

```powershell
python policiesdeploy.py --operation 5 --environment Test --commit-message "Updated firewall rules"
```

**Common Command-Line Options:**

- `--operation, -o`: Select operation (1-8)
- `--environment, -e`: Specify environment (e.g., Test, Prod)
- `--list-environments, -l`: List available environments
- `--non-interactive, -n`: Run without prompts
- `--verbose, -v`: Enable detailed logging
- `--commit-message, -m`: Custom message for Git commits
- `--skip-git, -s`: Skip Git operations during export
- `--conflict-resolution, -c`: Conflict resolution mode for sync (policies/csv/cancel)
- `--include-diff, -d`: Show detailed diffs in comparison
- `--save-results, -r`: Save comparison results to files
- `--skip-download-prompt, -p`: Skip prompt to download latest templates
- `--clean-export`: Clean export directories before generation (default: true)

#### 4. Example Workflows

- **Import policies from ARM templates:**
  ```powershell
  python policiesdeploy.py --operation 3 --environment Test
  ```

- **Export policies to Bicep and deploy:**
  ```powershell
  python policiesdeploy.py --operation 5 --environment Prod
  python policiesdeploy.py --operation 8 --environment Prod
  ```

- **Synchronize YAML and CSV:**
  ```powershell
  python policiesdeploy.py --operation 4 --environment Test --conflict-resolution policies
  ```

- **Compare Bicep and ARM templates:**
  ```powershell
  python policiesdeploy.py --operation 6 --include-diff --save-results
  ```

#### 5. Notes

- All operations support both interactive and automated workflows.
- Ensure your environment parameters (subscription, resource groups, etc.) are set correctly in `src/libraries/Parameters.py`.
- The script will create any missing directories as needed.
- For advanced usage and troubleshooting, enable verbose mode with `--verbose`.

## Bicep Comparison Tool

The project includes a tool for comparing Bicep files with ARM templates to identify differences. This is useful for validating that your Bicep templates will generate the expected ARM templates.

