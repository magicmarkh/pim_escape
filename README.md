# PIM Escape

This repository contains a PowerShell script for migrating Azure PIM assignments to CyberArk SCA policies.

## Usage

1. Clone the repository and edit the `cyberark-config.txt` file with your environment details. Any values left blank will be prompted during execution.
2. Run the script with PowerShell:
   ```powershell
   ./escape.ps1 -ConfigFile cyberark-config.txt
   ```

The script logs operations to `logs.txt` in the working directory.

## How It Works

The script performs four steps:

1. **Export PIM data from Azure** – gathers eligible assignments for each subscription.
2. **Authenticate with CyberArk SCA** – requests an OAuth2 token using credentials from the config file.
3. **Create CyberArk SCA policies** – generates access policies for each PIM assignment.
4. **Final summary** – prints totals and a summary of successes and errors.

See `escape.ps1` for the detailed implementation.

## Configuration

```text
# CyberArk SCA Migration Configuration File
# This file contains configuration variables for the PIM to CyberArk SCA migration script
# Leave values empty to be prompted during script execution
```

Adjust the values to match your environment.

## Disclaimer

This project is open source and not actively maintained. It is intended for proof of concept purposes only. Use at your own risk.

