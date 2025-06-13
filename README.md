# Versions
## V. 0.14 (20251306)
- main script in the root
- changed name of the bicep

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
### Workflow

::: mermaid
sequenceDiagram
    %% Declare participants in the desired order:
    participant A as JSON (Arm Template)
    participant B as YAML
    participant C as CSV
    participant D as BICEP

    %% Process flow messages:
    A->>B: Export Arm Template to YAML
    B->>D: Export YAML to BICEP

    %% Bidirectional sync between YAML and CSV:
    B-->>C: Sync YAML to CSV
    C-->>B: Sync CSV to YAML
:::

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
    E -->|No| I{Operation Choice}
    I -->|1: Update Repository| J[handle_update_repository]
    I -->|2: Import Policies| K[handle_import_policies]
    I -->|3: Sync Policies| L[handle_sync_policies]
    I -->|4: Export Policies| M[handle_export_policies]
    J --> F
    K --> F
    L --> F
    M --> F

    click J call linkCallback("./scripts/libraries/OrchestratorUtils.py#L452")
    click K call linkCallback("./scripts/libraries/OrchestratorUtils.py#L488")
    click L call linkCallback("./scripts/libraries/OrchestratorUtils.py#L430")
    click M call linkCallback("./scripts/libraries/OrchestratorUtils.py#L514")
:::



## Directory Structure

- `_firewalls/`: Contains firewall-related YAML files.
- `_ipgroups/`: Output folder for `scripts/ImportPolicies.py`. Contains IP groups in YAML format.
- `_policies/`: Output folder for `scripts/ImportPolicies.py`. Contains Firewall Policies in YAML format.
- `_csv/`: Output folder for `scripts/ImportPolicies.py`. Contains Firewall Policies in CSV format.
- `arm/`: Contains the source ARM templates (JSON) for IP groups and Azure Firewall Policies.
- `bicep/`: Output folder for `scripts/ExportPolicies.py`. Contains Azure Firewall Policies and IP groups in Bicep format.
- `docs/`: Archive of old documentation and many utility scripts.
- `env/`: Contains the Python virtual environment.
- `scripts/`: Main folder for Python scripts, Python libraries, and Jinja2 templates.

### Key Scripts & Libraries

- `AzFwManager.py`:  
  - Main entry point. Parses arguments, manages environment modes, displays menu, and calls:
    - `handle_update_repository()`  
    - `handle_import_policies()`  
    - `handle_sync_policies()`  
    - `handle_export_policies()`  
  - These methods reside in **OrchestratorUtils.py**.

**Libraries** (located in `scripts/libraries/`) and their actions:

- `CommonUtils.py`:  
  - Provides color support using Colorama.  
  - Contains helper methods (rendering Jinja templates, loading YAML, handling file paths, etc.).

- `Parameters.py`:  
  - Holds global config, environment parameters, subscription info.  
  - Parses command-line arguments and manages environment settings.

- `SyncUtils.py`:  
  - Inspects `_policies/` and `_csv/` folders.  
  - Determines which side is more up-to-date for synchronization.

- `ImportUtils.py`:  
  - Imports ARM templates (JSON).  
  - Converts them into YAML and CSV for firewall policy data.

- `ExportUtils.py`:  
  - Reads YAML/CSV to generate Bicep via Jinja templates.  
  - Outputs Bicep files to the `bicep/` folder.

- `DeployUtils.py`:  
  - Calls `BicepUtils.py` to deploy the generated Bicep files.  
  - Uses the subscription settings from `Parameters.py`.

- `CsvUtils.py`:  
  - Processes CSV files for firewall policies.  
  - Applies Jinja templates to produce structured data.

- `BicepUtils.py`:  
  - Builds and deploys Bicep resources for IP groups and firewall policies.  
  - Ensures correct structure in the final templates.

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

#### STEP 1 - Download IP Groups and Firewall Policies in ARM (json) format
1. Open the [Azure Portal](https://portal.azure.com) and open the specific Resource Group containing IP Groups or Firewall Policies.
1. On the left window, navigate to the "Automation" section and click on `Export template`.
1. In the code view, deselect the "Include parameters" option at the top of the page and wait until the template is created.
1. Download the template.
1. Once downloaded, save the file into the `arm/` folder of your local repo. Rename the file as `ipgroups.json` for the IP Groups extraction or `policies.json` for the Firewall Policies extraction.

#### STEP 2 - Run .exe or .py files 
- First of all you need to login with your Azure credentials and tenant, otherwise the script won't run correctly.
  Use this command:
  ```powershell
  az login --tenant "Your tenant ID" 
  ```

WITHOUT PYTHON:
```powershell
.\ImportPolicies.exe # import json arm templates into csv and yaml conf files
.\ExportPolicies.exe # export csv and yaml conf file to bicep files
```

WITH PYTHON:
- To run a specific script if you have python, navigate to the `scripts/` directory and execute the script:
```powershell
cd scripts
python3 .\ImportPolicies.py # import json arm templates into csv and yaml conf files
python3 .\ExportPolicies.py # export csv and yaml conf file to bicep files
```

##### 1) Run `ImportPolicies`
- You need to have the correct json files for the import and then check if you put them in the correct folder. 
- The JSON files must be called `policy.json` and `ipgroup.json`; otherwise, they will not work. 
- This script extracts JSON data and converts it into YAML and CSV files for use by other scripts.
- Use this command to run the script:

WITHOUT PYTHON: 
```powershell
.\ImportPolicies.exe # import json arm templates into csv and yaml conf files
```

WITH PYTHON:
```powershell
cd scripts
python3 .\ImportPolicies.py # import json arm templates into csv and yaml conf files
```

##### 2) Params
- Before the `ExportPolicies` command, you must set the Prod and Test params in the `Parameter.py` file, inside the `scripts\libraries\` folder.
- Ensure to change the `subscriptionid`, `ipgrouprg` and `policiesrg` with your specific Subscription ID and Resource Group names.
```powershell
# Parameters for test environment
test = {
    "subscriptionid": "368f3330-e38a-46e8-b394-7146ab9a0933",
    "ipgrouprg": "SecInt_IpGroups_DTest",
    "policiesrg": "SecInt_Policies_DTest",
    "firewallname": "CGOEW1NW"
}

# Parameters for production environment
prod = {
    "subscriptionid": "prod-12345678-1234-1234-1234-123456789abc",
    "ipgrouprg": "Prod-Network-AzureFirewall-IaC-IPG-RG",
    "policiesrg": "Prod-Network-AzureFirewall-IaC-FWP-RG",
    "firewallname": "PRODFW1"
}
```

##### 3) Run `ExportPolicies` and Deploy on Visual Sudio Code's Terminal
- This script reads YAML files containing IP group information, processes them using a Jinja2 template, and generates a Bicep file for resource definition. After the bicep files are generated, these will be deployed using the local az cli command.
- Use this command to run the script and to deploy the bicep from Visual Studio Code Terminal:

WITHOUT PYTHON:
```powershell
.\ExportPolicies.exe [prod]# export csv and yaml conf file to bicep files
```

WITH PYTHON:
```powershell
cd scripts
python3 .\ExportPolicies.py [prod]# export csv and yaml conf file to bicep files
```
- If you want to deploy the resource on Prod subscription, then add at the end of the previous command: `prod`
- Otherwise by default the script will deploy on Test subscription.

- N.B. CHECK YOUR CURRENT PATH BEFORE RUNNING THE SCRIPT:  

- Ensure all required directories exist before running the scripts. If not the directories will be generated by the script itself.
- If necessary, edit the global variables in the Python files to match your deployment architecture on Azure.


## Deploy on Azure (Optional alternative)

### Using Azure Command Line Interface (Az CLI)

##### Deployment of the IPGroups 
- To deploy the IPgroups, select the correct resource group and open the Azure Cloudshell. Select Bash and in "Settings" click on "Go to classic version".
- Write: code all_ipgroups.bicep
- Copy the bicep generated from exportipgroups.py and paste in. Save it and press ctrl + q
- Use this command to start the deploy (change the resource group and the subscription with the correct ones) 
```sh
az deployment group create -g "<INSERT_IP_GROUPS_RG>" -o none --subscription "<INSERT_SUBSCRIPTION_ID>" --template-file ipgroups.bicep
```
##### Deployment of the Policies 
- To deploy the Policies, select the correct resource group and open the Azure Cloudshell. Select Bash and in "Settings" click on "Go to classic version".
- Write: code all_policies.bicep
- Copy the bicep generated from generate_bicep.py and paste in. Save it and press ctrl + q
- Use this command to start the deploy (change the resource group and the subscription with the correct ones)
- deploy firewall policies:
```sh
az deployment group create -g "<INSERT_POLICIES_RG>" -o none --subscription "<INSERT_SUBSCRIPTION_ID>" --template-file policies.bicep
```

## Create new file.exe with python
- In terminal install pyinstaller with "pip install pyinstaller"
- Select the correct folder where you want to create the file.exe 
- Use the command: pyinstaller --onefile --add-data "libraries:libraries" --add-data "templates:templates" ./ImportPolicies.py or ./ExportPolicies.py
- Get the file.exe and drop it in the scripts folder 
- Delete the build and dist folder. (unecessary folders)
- For Export.exe shortcut, in the File Explorer, right-click on the shortcut you just created and select "Properties". In the "Shortcut" tab, locate the "Target" field.

-Add the desired environment parameter after the name of the executable.
For Example:
  ```powershell
  C:\Users\YourUsername\path\to\ExportPolicies.exe "mim_prod_ew"
  ```

## Structure of FIREWALL_DATA
```
FIREWALL_DATA = {
    {
	FirewallKey: Test
	FirewallOrder: 1
	Firewalls: {
		{
			firewallName: TestEW, regionName: westeurope, ...
		},
		{
			firewallName: TestEN, regionName: northeurope, ...
		}
	}
    },
    {
	FirewallKey: Prod
	FirewallOrder: 2
	Firewalls: {
		{
			firewallName: ProdEW, regionName: westeurope, ...
		},
		{
			firewallName: ProdEN, regionName: northeurope, ...
		}
	}
    }
}
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.