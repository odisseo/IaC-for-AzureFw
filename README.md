# PoliFire - Azure Firewall Policy Infrastructure as Code Manager

## Introduction

**PoliFire** (formerly Azure Firewall Policy Manager) is a comprehensive Infrastructure as Code (IaC) tool designed to streamline the management of Azure Firewall Policies. The tool enables teams to:

- **Import** Azure Firewall policies from ARM templates into structured YAML format
- **Export** policies from YAML to Bicep templates for deployment
- **Synchronize** between YAML and CSV formats for easy editing
- **Compare** ARM templates to validate changes
- **Deploy** Bicep templates directly to Azure
- **Version control** all policy configurations with Git integration

PoliFire bridges the gap between Azure's native formats and developer-friendly workflows, making firewall policy management more accessible and maintainable.

## Key Features

### 🔄 Multi-Format Support
- **ARM Templates**: Import existing policies from Azure
- **YAML**: Human-readable structured format for version control
- **CSV**: Spreadsheet-friendly format for bulk editing
- **Bicep**: Modern IaC for Azure deployment

### 🔐 Policy Management
- Application rules, Network rules, and NAT rules
- Parent-child policy inheritance
- IP Groups integration
- Policy tags and metadata preservation
- Log Analytics (Insights) configuration

### 🚀 Automation Features
- Automatic directory cleanup after operations
- Interactive and non-interactive modes for CI/CD
- Git integration for version control
- Hash-based change detection (.lock file mechanism)
- Batch processing for multiple firewalls
- **Intelligent PROD→DR policy mapping** based on firewall configuration indexes
- **Flexible basePolicy handling** supporting cross-subscription parent policies
- **True parallel Bicep deployment** - deploy all firewalls concurrently using ThreadPoolExecutor
- **Deployment mode selection** - choose between parallel (fast, no confirmations) or sequential (controlled, with confirmations)
- **Multi-firewall deployment** - handle 3+ firewalls simultaneously with proper authentication caching
- **Firewall-aware error reporting** - see which firewall had deployment issues at a glance

### 📊 Advanced Capabilities
- ARM template comparison with normalized resource names
- Policy assignment workflow
- Multi-environment support
- Cross-subscription policy management
- Intelligent conflict resolution for synchronization
- Parallel deployment execution reducing overall deployment time

## Getting Started

### Prerequisites

1. **Python 3.8+** installed
2. **Azure CLI** installed and configured
3. **Git** for version control features
4. **Azure subscription** with appropriate permissions

### Installation

1. Clone the repository:
```powershell
git clone <repository-url>
cd SecInt-IaC-AzureFW-Policies-Logic
```

2. Install Python dependencies:
```powershell
pip install -r requirements.txt
```

3. Configure your firewall environments in `Inventory/firewall.yaml`

### Quick Start

Run the main script:
```powershell
python policiesdeploy.py
```

The interactive menu will guide you through available operations:

1. **Update repository** - Pull latest changes from Git
2. **Switch Git branch** - Change working branch
3. **Download ARM templates** - Import policies from Azure
4. **Sync policies** - Synchronize between YAML and CSV
5. **Export policies** - Generate Bicep templates
6. **Deploy Bicep** - Deploy to Azure
7. **Compare ARM templates** - Validate changes
8. **Commit changes** - Push to Git repository
9. **Assign policies** - Attach policies to firewalls

## Project Structure

```
SecInt-IaC-AzureFW-Policies-Logic/
├── policiesdeploy.py          # Main entry point
├── requirements.txt           # Python dependencies
├── VERSION.md                 # Version history
├── src/
│   ├── libraries/             # Core functionality
│   │   ├── AssignUtils.py     # Policy assignment
│   │   ├── OrchestratorUtils.py  # Workflow orchestration
│   │   └── ...
│   ├── libraries_common/      # Shared utilities
│   │   ├── CommonUtils.py     # File operations, hashing
│   │   ├── CompareUtils.py    # ARM template comparison
│   │   ├── CsvUtils.py        # CSV handling
│   │   ├── DeployUtils.py     # Azure deployment
│   │   ├── ExportUtils.py     # Bicep generation
│   │   ├── ImportUtils.py     # ARM import
│   │   ├── Parameters.py      # Configuration constants
│   │   ├── SyncUtils.py       # YAML/CSV sync
│   │   └── YamlUtils.py       # YAML operations
│   └── templates/             # Jinja2 templates
│       ├── policy.bicep.jinja2
│       ├── policy.yaml.jinja2
│       └── ...
└── .lock                      # Sync state tracking

SecInt-IaC-AzureFW-Policies-Inventory/
├── Inventory/
│   ├── firewall.yaml          # Firewall configurations
│   └── policies.yaml          # Policy definitions
├── Policies/
│   ├── yaml/                  # YAML policy definitions
│   └── csv/                   # CSV format for editing
├── Bicep/                     # Generated Bicep templates
├── arm_import/                # Temporary: downloaded ARM (auto-deleted)
├── arm_export/                # Temporary: generated ARM (auto-deleted)
└── comparison/                # ARM comparison results
```

## Configuration

### Firewall Environment Setup

Edit `Inventory/firewall.yaml` to define your firewall environments:

```yaml
- environment: PRODUCTION
  firewalls:
    - firewallName: AZEW_PRD_VNET_FW_P01
      policiesSubscriptionId: "xxxx-xxxx-xxxx-xxxx"
      firewallSubscriptionId: "yyyy-yyyy-yyyy-yyyy"
      tenantId: "zzzz-zzzz-zzzz-zzzz"
      firewallResourceGroup: RG-FIREWALL
      policiesResourceGroup: RG-POLICIES
      ipGroupsResourceGroup: RG-IPGROUPS
      regionName: westeurope
      policiesName:
        - AZEW_PRD_VNET_POLICY_P01
```

### Path Configuration

All paths are centralized in `src/libraries/Parameters.py`:

```python
class Paths:
    BASE_PATH = os.path.dirname(...)
    POLICIES_DIR = os.path.join(BASE_PATH, 'policies', 'yaml')
    CSV_DIR = os.path.join(BASE_PATH, 'policies', 'csv')
    BICEP_DIR = os.path.join(BASE_PATH, 'Bicep')
    ARM_DIR = os.path.join(BASE_PATH, 'arm_import')
    ARM_EXPORT_DIR = os.path.join(BASE_PATH, 'arm_export')
    COMPARISON_DIR = os.path.join(BASE_PATH, 'comparison')
```

## Workflow Examples

### Import Policies from Azure

```powershell
# Interactive mode
python policiesdeploy.py

# Non-interactive mode
python policiesdeploy.py --non-interactive --environment PRODUCTION --action download
```

This will:
1. Clean the ARM import directory
2. Download ARM templates from Azure using Azure CLI
3. Parse ARM templates and extract basePolicy information
4. Import policies to YAML format with separate `basePolicyName` and `basePolicyVersion` fields
5. Sync to CSV format for easy editing
6. Delete the ARM import directory automatically

**Key Feature**: During import, the `basePolicyVersion` is extracted from the ARM template's basePolicy ID and stored for consistent use across all policies in subsequent exports.

### Edit and Export Policies

1. Edit policies in CSV format (`Policies/csv/`)
2. Sync changes back to YAML:
```powershell
python policiesdeploy.py --action sync
```
3. Export to Bicep with PROD→DR mapping:
```powershell
python policiesdeploy.py --action export --environment PRODUCTION --version 20260119_6404cba
```

**Key Features**:
- Automatic PROD→DR policy mapping based on firewall YAML `policiesName` indexes
- PolicyName index 0 in PROD firewall links to index 0 in all DR firewalls
- BasePolicy ID automatically constructed from:
  - Firewall-specific `basePolicyName` and `basePolicyResourceGroup` (from firewall.yaml)
  - Environment-wide `basePolicyVersion` (from import or provided via CLI)
  - Azure subscription and resource group information per firewall
- Handles both legacy dict format and modern list format for `policiesName` field
- Generated Bicep files ready for immediate deployment

### Compare and Validate Changes

```powershell
python policiesdeploy.py --action compare
```

This compares:
- Downloaded ARM templates with previously exported versions
- Normalized resource names for accurate change detection
- Policy definitions and rule collections

### Deploy Bicep to Azure

```powershell
python policiesdeploy.py --action deploy --environment PRODUCTION --resource-group RG-POLICIES
```

Deployment features:
- Automatic subscription and resource group selection
- Validates policy resources before deployment
- Creates or updates firewall policies as needed
- Maintains parent-child policy relationships
- What-if analysis available with `--whatif` flag for dry-run testing

### Assign Policies to Firewalls

```powershell
python policiesdeploy.py --action assign --environment PRODUCTION
```

Assignment workflow:
- Links firewall policies to firewall resources
- Supports batch assignment across multiple firewalls
- Validates firewall and policy existence before assignment

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `--action` | Operation to perform (download, sync, export, deploy, compare, etc.) |
| `--environment` | Target firewall environment |
| `--non-interactive` | Run without user prompts (for CI/CD) |
| `--skip-git` | Skip Git operations |
| `--whatif` | Perform what-if deployment analysis |
| `--complete-mode` | Use complete deployment mode |
| `--conflict-resolution` | Strategy for sync conflicts (folder1, folder2, skip) |
| `--verbose` | Enable verbose logging |
| `--loop` | Keep program running after operation |

## Advanced Features

### Lock File Mechanism

PoliFire uses a `.lock` file to track folder state using SHA-256 hashes:

```yaml
- name: yaml
  hash: c2cd0741d470431edf3a68f292fa7c29
  date: 1764687600.5447483
- name: csv
  hash: f96eb82a7b9dbd55c647c24797ebe1b8
  date: 1764687600.5447483
```

This enables:
- Change detection between YAML and CSV
- Intelligent conflict resolution
- Deployment version tracking

### Automatic Directory Cleanup

**Version 1.1** introduced automatic cleanup of temporary directories:

- **ARM Import** (`arm_import/`): Deleted after successful download and import
- **ARM Export** (`arm_export/`): Deleted after successful ARM comparison

This keeps the repository clean and reduces disk usage.

### Policy Inheritance

PoliFire supports parent-child policy relationships:

```yaml
parentPolicy:
  name: PARENT_POLICY
  resourceGroup: RG-PARENT-POLICIES
  policiesSubscriptionId: "xxxx-xxxx-xxxx-xxxx"
```

### Cross-Subscription Support

Manage policies across multiple Azure subscriptions with proper authentication handling.

## Troubleshooting

### Common Issues

**Error: "Path is not a directory"**
- Ensure all required directories exist
- Check path configuration in Parameters.py

**Azure Login Failed**
- Run `az login` manually
- Verify subscription and tenant IDs

**Sync Conflicts**
- Use `--conflict-resolution` flag to specify strategy
- Review .lock file for hash mismatches

**Deployment Errors**
- Use `--whatif` flag to validate before deploying
- Check Azure permissions
- Review deployment logs

### Logging

Logs are written to console and can be configured for verbosity:

```powershell
python policiesdeploy.py --verbose
```

## Version History

See [VERSION.md](VERSION.md) for detailed version history.

**Current Version: 1.10** (February 17, 2026)
- Enhanced policy suffix format with hours and minutes timestamp
- Improved SNAT handling in Bicep templates
- Automatic directory cleanup
- Enhanced code maintainability

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Code Style**: Follow existing patterns and conventions
2. **Testing**: Test changes with multiple environments
3. **Documentation**: Update VERSION.md and README.md
4. **Git**: Create feature branches and descriptive commit messages

## Building the Executable

### Create a standalone EXE file

PoliFire can be packaged as a standalone Windows executable using PyInstaller. This allows distribution without requiring Python installation.

**Prerequisites:**
- PyInstaller installed: `pip install pyinstaller`

**Build Steps:**

1. Navigate to the project root directory:
```powershell
cd SecInt-IaC-AzureFW-Policies-Logic
```

2. Run PyInstaller with the following command:
```powershell
pyinstaller --onefile --add-data "src/libraries;src/libraries" --add-data "src/templates;src/templates" policiesdeploy.py
```

This command:
- `--onefile`: Creates a single executable file
- `--add-data`: Embeds the `src/libraries` and `src/templates` directories into the executable

3. Clean up build artifacts:
```powershell
# Delete the build folder
Remove-Item -Recurse -Force build

# Move the executable from dist folder to root
Move-Item dist\policiesdeploy.exe .\policiesdeploy.exe

# Delete the dist folder
Remove-Item -Recurse -Force dist

# Delete the spec file
Remove-Item policiesdeploy.spec
```

**Result:**
A standalone `policiesdeploy.exe` file in the project root directory that can be distributed and run on any Windows machine with the required dependencies (Azure CLI, Git).

**Usage:**
```powershell
.\policiesdeploy.exe
```

Or use it the same way as the Python script with command-line arguments:
```powershell
.\policiesdeploy.exe --action export --environment PRODUCTION --version 20260119_6404cba
```

**Advantages:**
- ✅ No Python installation required
- ✅ Faster startup time
- ✅ Single file distribution
- ✅ Easy to use for non-technical users



## Best Practices

### For Development

- Always sync before making changes
- Test exports in what-if mode first
- Keep environments separated in different branches
- Use meaningful commit messages with the auto-generated IDs

### For Production

- Use non-interactive mode in CI/CD pipelines
- Enable complete audit trails with Git integration
- Validate changes with ARM comparison before deployment
- Maintain separate parent policies for inheritance

### For Collaboration

- Use CSV format for bulk policy editing
- Leverage Git branches for different environments
- Document custom configurations in firewall.yaml
- Review comparison results before deployment

## License

[Specify your license here]

## Support

For issues and questions:
- Check [VERSION.md](VERSION.md) for recent changes
- Review troubleshooting section above
- Contact your Azure administrator for permission issues

---

**PoliFire** - Making Azure Firewall Policy management simple, scalable, and maintainable.