# NoTrackWin.ps1
PowerShell script to batch-change privacy settings in Windows 10 and Windows 11.

## Description

Windows collects a lot of data by default, which can be concerning for privacy-conscious users. **NoTrackWin** is a PowerShell script designed to modify Windows settings to enhance privacy, reduce telemetry, and disable unnecessary tracking features.

## Requirements

- Windows 10 or Windows 11
- PowerShell with administrator privileges

## Downloading the Script

There are several ways to obtain the script: downloading the ZIP, cloning the repository, or saving the file manually. You can also download it via PowerShell:

Open a PowerShell window, navigate to the desired directory, for example:

    cd ~\Downloads

Then, run the following command to download the script:

    (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/yourusername/NoTrackWin/main/NoTrackWin.ps1') | Out-File .\NoTrackWin.ps1 -Force

After downloading, always review the script before executing it to ensure it aligns with your privacy preferences:

    ise .\NoTrackWin.ps1

## Alternative Installation Method

You can also install the script using PowerShell by running:

    Install-Script -Name NoTrackWin

You may be required to confirm additional prompts during installation.

## Running the Script

Once downloaded, run the script with one of the predefined privacy levels:

    .\NoTrackWin.ps1 -Strong

This applies the **Strong** privacy settings for the current user. Other available options are:
- **Default** (similar to Windows' default settings)
- **Balanced** (moderate privacy adjustments)

To modify system-wide privacy settings, use the `-admin` switch:

    .\NoTrackWin.ps1 -Strong -admin

**Note:** Running with `-admin` requires launching PowerShell with elevated privileges.

### Getting More Help

To view detailed information about available parameters, run:

    help .\NoTrackWin.ps1 -full

## Script Output

The script provides real-time feedback on the changes applied.
- **Green**: Setting was already applied and remains unchanged.
- **Yellow**: Setting has been modified by the script.

## Troubleshooting

### Execution Policy Issues
If you encounter the following error:

    ...NoTrackWin.ps1 cannot be loaded because running scripts is disabled on this system...

You need to adjust the execution policy. To allow local unsigned scripts temporarily, run:

    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

To make this change permanent for your user:

    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

## What Does the Script Change?

The script adjusts various privacy settings based on the selected mode (`-Default`, `-Balanced`, `-Strong`).

A `*` means the feature is enabled, while `-` means it is disabled.

| **Setting**            | **Default** | **Balanced** | **Strong** | **Description** |
|------------------------|------------|-------------|------------|----------------|
| AdvertisingId         | *          | -           | -          | Disable personalized advertising ID |
| ImproveTyping         | *          | -           | -          | Stop sending typing data to Microsoft |
| SmartScreen           | *          | *           | -          | Disable SmartScreen filtering |
| Location              | *          | -           | -          | Disable location tracking |
| Camera Access         | *          | -           | -          | Restrict app access to the camera |
| Microphone Access     | *          | -           | -          | Restrict app access to the microphone |
| Feedback Frequency    | *          | -           | -          | Disable feedback requests |
| DoNotTrack            | -          | *           | *          | Enable Do-Not-Track in Edge |
| SearchSuggestions     | *          | -           | -          | Disable search suggestions in Edge |
| PagePrediction        | *          | -           | -          | Disable page preloading in Edge |
| AppNotifications      | *          | -           | -          | Restrict app access to notifications |
| CallHistory           | *          | -           | -          | Restrict app access to call history |
| Email Access         | *          | -           | -          | Restrict app access to email |
| Task Access          | *          | -           | -          | Restrict app access to tasks |

## System-Wide Changes (`-admin` mode)

| **Setting**      | **Default** | **Balanced** | **Strong** | **Description** |
|------------------|------------|-------------|------------|----------------|
| ShareUpdates    | *          | +           | -          | Disable sharing of Windows updates |
| WifiSense       | *          | -           | -          | Disable Wi-Fi Sense |
| Telemetry       | *          | -           | -          | Reduce diagnostic data collection |
| SpyNet          | *          | *           | -          | Disable Windows Defender cloud-based protection |

## What Is NOT Changed?

The script does **not** modify the following:
- **Background Apps**: While some consider this a privacy issue, it is not included in the script.
- **Non-Privacy Related Tweaks**: The focus is strictly on privacy settings.
- **SpyNet Reporting**: Windows prevents full control over some telemetry features.

## Disclaimer

This script modifies system settings to improve privacy. Use at your own risk and ensure you have a backup before applying changes. The author is not responsible for any unintended effects caused by this script.

