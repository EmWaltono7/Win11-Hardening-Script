# ===== Variables Section Start =====
$MaxPasswordAge = 60  # Maximum password age in days
$TempPassword = '1CyberPatriot!' # Temporary password for user accounts

# Color variables
$HeaderColor = "Cyan"            # Color for headers
$PromptColor = "Yellow"          # Color for prompts
$EmphasizedNameColor = "Green"   # Color for emphasized names
$KeptLineColor = "DarkYellow"    # Color for kept lines
$RemovedLineColor = "Red"        # Color for removed lines
$WarningColor = "Red"            # Color for warnings
# ===== Variables Section End =====

# Check for admin rights and relaunch as admin if needed
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Script is not running as administrator. Relaunching as admin..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
# Display the computer's hostname
Write-Host "Computer Name: $env:COMPUTERNAME"

# Display the Windows version
Write-Host "Windows Version:"
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer
Write-Host "Script Run Time: $(Get-Date)"

# Define menu options
$menuOptions = @(
    "Document the system",
    "Enable updates",
    "User Auditing",
    "Account Policies",
    "Local Policies",
    "Defensive Countermeasures",
    "Uncategorized OS Settings",
    "Service Auditing",
    "OS Updates",
    "Application Updates",
    "Prohibited Files",
    "Unwanted Software",
    "Malware",
    "Application Security Settings",
    "Exit"
)

# Define functions for each option
function Document-System {
    Write-Host "`n--- Starting: Document the system ---`n"

    # Detect the current user's desktop folder
    $desktopFolder = [Environment]::GetFolderPath("Desktop")
    $docsFolder = Join-Path -Path $desktopFolder -ChildPath "DOCS"

    # Create the DOCS folder if it does not already exist
    if (-not (Test-Path -Path $docsFolder)) {
        Write-Host "Creating DOCS folder at: $docsFolder"
        New-Item -Path $docsFolder -ItemType Directory | Out-Null
    } else {
        Write-Host "DOCS folder already exists at: $docsFolder"
    }

    # Begin documentation with a list of local users
    $localUsersFile = Join-Path -Path $docsFolder -ChildPath "LocalUsers.txt"
    Write-Host "Documenting local users to: $localUsersFile"

    try {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon | Format-Table -AutoSize | Out-String | Set-Content -Path $localUsersFile
        Write-Host "Local users documented successfully."
    } catch {
        Write-Warning "Failed to document local users: $($_.Exception.Message)"
    }

    # Additional audit results can be added here
    Write-Host "Documentation process completed."
# Get the current username
$PUSER = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]

# Define the folder path
$docsFolder = "C:\Users\$PUSER\Desktop\DOCS"

# Check if the folder exists
if (-not (Test-Path -Path $docsFolder)) {
    # Create the folder if it does not exist
    Write-Host "Creating folder: $docsFolder"
    New-Item -Path $docsFolder -ItemType Directory | Out-Null
} else {
    Write-Host "Folder already exists: $docsFolder"
}
}

function Enable-Updates {
    Write-Host "`n--- Starting: Enable updates ---`n"
}

function User-Auditing {
    Write-Host "`n--- Starting: User Auditing ---`n"
    # ...existing code...
     # Disable and rename the built-in Guest account
    Write-Host "Disabling and renaming the built-in Guest account..."
    try {
        Disable-LocalUser -Name "Guest"
        Write-Host "Guest account has been disabled."

        Rename-LocalUser -Name "Guest" -NewName "DisabledGuest"
        Write-Host "Guest account has been renamed to 'DisabledGuest'."
    } catch {
        Write-Host "Failed to disable or rename the Guest account: $_"
    }
     # Disable and rename the built-in Administrator account
    Write-Host "Disabling and renaming the built-in Administrator account..."
    try {
        Disable-LocalUser -Name "Administrator"
        Write-Host "Administrator account has been disabled."

        Rename-LocalUser -Name "Administrator" -NewName "SecAdminDisabled"
        Write-Host "Administrator account has been renamed to 'SecAdminDisabled'."
    } catch {
        Write-Host "Failed to disable or rename the Administrator account: $_"
    }
    # Enumerate all local user accounts
    $localUsers = Get-LocalUser

    foreach ($user in $localUsers) {
        # Skip built-in accounts
        if ($user.Name -in @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')) {
            continue
        }

        $prompt = "Is '$($user.Name)' an Authorized User? [Y/n]: "
        $answer = Read-Host -Prompt $prompt
        try {
            # Set password to $TempPassword
            Set-LocalUser -Name $user.Name -Password (ConvertTo-SecureString $TempPassword -AsPlainText -Force)
            Write-Host "Password for '$($user.Name)' reset to temporary value."

            # Require password change at next logon
            net user $user.Name /logonpasswordchg:yes
            Write-Host "User '$($user.Name)' must change password at next logon."
        } catch {
            Write-Host "Failed to reset password for '$($user.Name)': $_"
        }

        if ($answer -eq 'n' -or $answer -eq 'N') {
            try {
                Remove-LocalUser -Name $user.Name
                Write-Host "Deleted user: $($user.Name)"
            } catch {
                Write-Host "Failed to delete user: $($user.Name) - $_"
            }
        } else {
            Write-Host "Kept user: $($user.Name)"
        }
    }

    # After all users have been processed, enumerate all users in the Administrators group
    $adminGroup = Get-LocalGroupMember -Group "Administrators"

    foreach ($admin in $adminGroup) {
        # Only process user accounts (not groups or service accounts)
        if ($admin.ObjectClass -ne 'User') {
            continue
        }

        $prompt = "Is '$($admin.Name)' an Authorized Administrator? [Y/n]: "
        $answer = Read-Host -Prompt $prompt

        if ($answer -eq 'n' -or $answer -eq 'N') {
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name
                Write-Host "Removed administrator: $($admin.Name)"
            } catch {
                Write-Host "Failed to remove administrator: $($admin.Name) - $_"
            }
        } else {
            Write-Host "Kept administrator: $($admin.Name)"
        }
    }
}

function Account-Policies {
    Write-Host "`n--- Starting: Account Policies ---`n"
    Write-Host "Setting maximum password age to $MaxPasswordAge days..."
    net accounts /maxpwage:$MaxPasswordAge
}

function Local-Policies {
    Write-Host "`n--- Starting: Local Policies ---`n"
}

function Defensive-Countermeasures {
    Write-Host "`n--- Starting: Defensive Countermeasures ---`n"
}

function Uncategorized-OS-Settings {
    Write-Host "`n--- Starting: Uncategorized OS Settings ---`n"
}

function Service-Auditing {
    Write-Host "`n--- Starting: Service Auditing ---`n"

    # Define the services to audit and disable
    $servicesToAudit = @("RemoteRegistry", "Spooler", "SNMP", "Browser")

    # Display the current status of the services
    Write-Host "`nCurrent status of services:`n"
    Get-Service -Name $servicesToAudit -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table -AutoSize

    # Loop through each service and attempt to disable it
    foreach ($service in $servicesToAudit) {
        try {
            $svc = Get-Service -Name $service -ErrorAction Stop
            if ($svc.Status -ne "Stopped") {
                Stop-Service -Name $service -Force -ErrorAction Stop
                Write-Host "Stopped service: $service"
            }
            Set-Service -Name $service -StartupType Disabled -ErrorAction Stop
            Write-Host "Disabled service: $service"
        } catch {
            Write-Warning "Could not modify $service`: $($_.Exception.Message)"
        }
    }
    
    # Display the updated status of the services
    Write-Host "`nUpdated status of services:`n"
    Get-Service -Name $servicesToAudit -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType | Format-Table -AutoSize
}

function OS-Updates {
    Write-Host "`n--- Starting: OS Updates ---`n"
}

function Application-Updates {
    Write-Host "`n--- Starting: Application Updates ---`n"
}

function Prohibited-Files {
    Write-Host "`n--- Starting: Prohibited Files ---`n"
}

function Unwanted-Software {
    Write-Host "`n--- Starting: Unwanted Software ---`n"
}

function Malware {
    Write-Host "`n--- Starting: Malware ---`n"
}

function Application-Security-Settings {
    Write-Host "`n--- Starting: Application Security Settings ---`n"
}

# Menu loop
do {
    Write-Host "`nSelect an option:`n"
    for ($i = 0; $i -lt $menuOptions.Count; $i++) {
        Write-Host "$($i + 1). $($menuOptions[$i])"
    }

    $selection = Read-Host "`nEnter the number of your choice"

    switch ($selection) {
        "1"  { Document-System }
        "2"  { Enable-Updates }
        "3"  { User-Auditing }
        "4"  { Account-Policies }
        "5"  { Local-Policies }
        "6"  { Defensive-Countermeasures }
        "7"  { Uncategorized-OS-Settings }
        "8"  { Service-Auditing }
        "9"  { OS-Updates }
        "10" { Application-Updates }
        "11" { Prohibited-Files }
        "12" { Unwanted-Software }
        "13" { Malware }
        "14" { Application-Security-Settings }
        "15" { Write-Host "`nExiting..."; break menu }  # leave the do{} loop
        default { Write-Host "`nInvalid selection. Please try again." }
    }
} while ($true)
# End of script 
#Changed
