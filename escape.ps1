# Combined PIM to CyberArk SCA Migration Script
# This script exports Azure subscription PIM data and creates corresponding CyberArk SCA policies

param(
    [string]$ConfigFile = "cyberark-config.txt"
)

# Set up logging
$logFile = Join-Path (Get-Location) "logs.txt"
$logStartTime = Get-Date

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console (existing behavior)
    switch ($Level) {
        "ERROR" { Write-Error $Message }
        "WARNING" { Write-Warning $Message }
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "INFO" { Write-Host $Message -ForegroundColor White }
        "DEBUG" { Write-Host $Message -ForegroundColor Gray }
        default { Write-Host $Message }
    }
    
    # Write to log file
    Add-Content -Path $logFile -Value $logEntry
}

# Initialize log file
"=== PIM to CyberArk SCA Migration Script Started at $logStartTime ===" | Out-File -FilePath $logFile -Encoding UTF8
Write-Log "Starting PIM to CyberArk SCA migration script" "INFO"

# ========================================
# INSTALL REQUIRED MODULES
# ========================================

Write-Log "=== CHECKING AND INSTALLING REQUIRED MODULES ===" "INFO"

# Function to install module if not available
function Install-RequiredModule {
    param(
        [string]$ModuleName,
        [string]$MinimumVersion = $null
    )
    
    Write-Log "Checking module: $ModuleName" "DEBUG"
    
    $installedModule = Get-Module -ListAvailable -Name $ModuleName | Sort-Object Version -Descending | Select-Object -First 1
    
    if (!$installedModule) {
        Write-Log "Module $ModuleName not found. Installing..." "INFO"
        try {
            Install-Module -Name $ModuleName -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck
            Write-Log "Successfully installed module: $ModuleName" "SUCCESS"
        } catch {
            Write-Log "Failed to install module $ModuleName`: $($_.Exception.Message)" "ERROR"
            return $false
        }
    } else {
        Write-Log "Module $ModuleName already installed (Version: $($installedModule.Version))" "DEBUG"
    }
    
    # Import the module
    try {
        Import-Module -Name $ModuleName -Force
        Write-Log "Successfully imported module: $ModuleName" "DEBUG"
        return $true
    } catch {
        Write-Log "Failed to import module $ModuleName`: $($_.Exception.Message)" "WARNING"
        return $false
    }
}

# Install required modules
$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.Governance"
)

$moduleInstallSuccess = $true
foreach ($module in $requiredModules) {
    $result = Install-RequiredModule -ModuleName $module
    if (!$result) {
        $moduleInstallSuccess = $false
    }
}

if ($moduleInstallSuccess) {
    Write-Log "All required modules installed and imported successfully" "SUCCESS"
} else {
    Write-Log "Some modules failed to install. Graph API functionality may be limited." "WARNING"
}

# Function to read configuration file
function Read-ConfigFile {
    param([string]$FilePath)
    
    $config = @{}
    
    if (Test-Path $FilePath) {
        Write-Log "Reading configuration from: $FilePath" "INFO"
        $content = Get-Content $FilePath
        
        foreach ($line in $content) {
            if ($line -match '^([^#=]+)=(.*)$') {
                $key = $Matches[1].Trim()
                $value = $Matches[2].Trim()
                if ($value -ne '') {
                    $config[$key] = $value
                }
            }
        }
    } else {
        Write-Log "Configuration file not found: $FilePath" "WARNING"
        Write-Log "Creating sample configuration file..." "INFO"
        
        # Create sample config file
        $sampleConfig = @"
# CyberArk SCA Migration Configuration File
IDENTITY_TENANT_ID=
TENANT_NAME=
ORGANIZATION_ID=
IS_DIRECTORY_SERVICE=false
EXTERNAL_DIRECTORY_GUID=
USERNAME=
PASSWORD=
DEFAULT_TIMEZONE=America/New_York
DEFAULT_SESSION_DURATION_HOURS=1
TEST_MODE=false
BATCH_SIZE=10
BATCH_DELAY_SECONDS=2
"@
        $sampleConfig | Out-File -FilePath $FilePath -Encoding UTF8
        Write-Log "Sample configuration created at: $FilePath" "SUCCESS"
        Write-Log "Please edit the configuration file and run the script again." "INFO"
        exit 0
    }
    
    return $config
}

# Function to get configuration value or prompt user
function Get-ConfigValue {
    param(
        [string]$Key,
        [hashtable]$Config,
        [string]$Prompt,
        [switch]$Secure
    )
    
    if ($Config.ContainsKey($Key) -and $Config[$Key] -ne '') {
        return $Config[$Key]
    } else {
        if ($Secure) {
            $secureValue = Read-Host $Prompt -AsSecureString
            return [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue))
        } else {
            return Read-Host $Prompt
        }
    }
}

Write-Log "=== Combined PIM to CyberArk SCA Migration Script ===" "INFO"

# Read configuration
$config = Read-ConfigFile -FilePath $ConfigFile

# Get configuration values (prompt if not set)
$identityTenantId = Get-ConfigValue -Key "IDENTITY_TENANT_ID" -Config $config -Prompt "Enter CyberArk Identity Tenant ID (ABC1234 format from username -> about -> Identity Id)"
$tenantName = Get-ConfigValue -Key "TENANT_NAME" -Config $config -Prompt "Enter CyberArk Tenant Name"
$organizationId = Get-ConfigValue -Key "ORGANIZATION_ID" -Config $config -Prompt "Enter Azure AD/Entra ID Organization ID (Tenant ID)"
$username = Get-ConfigValue -Key "USERNAME" -Config $config -Prompt "Enter Username"
$password = Get-ConfigValue -Key "PASSWORD" -Config $config -Prompt "Enter Password" -Secure
$timezone = Get-ConfigValue -Key "DEFAULT_TIMEZONE" -Config $config -Prompt "Enter Timezone (default: America/New_York)"
$sessionDuration = Get-ConfigValue -Key "DEFAULT_SESSION_DURATION_HOURS" -Config $config -Prompt "Max Session Duration in Hours (default: 1)"
$isDirectoryService = ($config["IS_DIRECTORY_SERVICE"] -eq "true")
$externalDirectoryGuid = Get-ConfigValue -Key "EXTERNAL_DIRECTORY_GUID" -Config $config -Prompt "Enter CyberArk GUID for your external directory"
$testMode = ($config["TEST_MODE"] -eq "true")
$batchSize = if ($config["BATCH_SIZE"]) { [int]$config["BATCH_SIZE"] } else { 10 }
$batchDelay = if ($config["BATCH_DELAY_SECONDS"]) { [int]$config["BATCH_DELAY_SECONDS"] } else { 2 }

# Set defaults if empty
if (!$timezone) { $timezone = "America/New_York" }
if (!$sessionDuration) { $sessionDuration = "1" }

# Determine entity source ID based on directory service setting
$identityEntitySourceId = if ($isDirectoryService) { 
    Write-Log "Using Azure AD as external directory service" "INFO"
    if ($externalDirectoryGuid) {
        Write-Log "Using external directory GUID: $externalDirectoryGuid" "DEBUG"
        $externalDirectoryGuid
    } else {
        Write-Log "External directory GUID not provided, using organization ID" "WARNING"
        $organizationId 
    }
} else { 
    Write-Log "Using local CyberArk identities (not external directory)" "INFO"
    "00000000-0000-0000-0000-000000000000" 
}

# Build URLs from tenant information
$authBaseUrl = "https://$identityTenantId.id.cyberark.cloud"
$apiBaseUrl = "https://$tenantName.sca.cyberark.cloud"
$platformTokenEndpoint = "/oauth2/platformtoken"
$createPolicyEndpoint = "/api/policies/create-policy"

Write-Log "Configuration Summary:" "INFO"
Write-Log "Identity Tenant ID: $identityTenantId" "DEBUG"
Write-Log "Tenant Name: $tenantName" "DEBUG"
Write-Log "Auth URL: $authBaseUrl$platformTokenEndpoint" "DEBUG"
Write-Log "API URL: $apiBaseUrl$createPolicyEndpoint" "DEBUG"
Write-Log "Azure AD/Entra Organization ID: $organizationId" "DEBUG"
Write-Log "Directory Service Integration: $isDirectoryService" "DEBUG"
Write-Log "Identity Entity Source ID: $identityEntitySourceId" "DEBUG"
Write-Log "External Directory GUID: $externalDirectoryGuid" "DEBUG"
Write-Log "Username: $username" "DEBUG"
Write-Log "Timezone: $timezone" "DEBUG"
Write-Log "Session Duration: $sessionDuration hours" "DEBUG"
Write-Log "Test Mode: $testMode" "DEBUG"
Write-Log "Batch Size: $batchSize" "DEBUG"

if ($testMode) {
    Write-Log "*** RUNNING IN TEST MODE - NO POLICIES WILL BE CREATED ***" "WARNING"
}

# ========================================
# STEP 1: EXPORT PIM DATA FROM AZURE
# ========================================

Write-Log "=== STEP 1: EXPORTING PIM DATA FROM AZURE ===" "INFO"

# Connect to Azure
Write-Log "Connecting to Azure..." "INFO"
try {
    $azContext = Get-AzContext
    if (-not $azContext) {
        Connect-AzAccount
    }
    Write-Log "Connected to Azure as: $($azContext.Account.Id)" "SUCCESS"
} catch {
    Connect-AzAccount
}

# Get access token for Azure Resource Manager
Write-Log "Getting Azure Resource Manager access token..." "INFO"
$azToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, "Never", $null, "https://management.azure.com/").AccessToken

# Get access token for Microsoft Graph
Write-Log "Getting Microsoft Graph access token..." "INFO"
$graphToken = $null

# Try to connect using Microsoft Graph PowerShell (modern approach)
try {
    Write-Log "Connecting to Microsoft Graph with PIM scopes..." "DEBUG"
    
    # Connect with specific scopes needed for PIM
    $requiredScopes = @(
        "RoleManagement.Read.Directory",
        "RoleEligibilitySchedule.Read.Directory", 
        "Directory.Read.All",
        "User.Read.All",
        "Group.Read.All"
    )
    
    # Use the same tenant as Azure context for consistency
    Connect-MgGraph -Scopes $requiredScopes -TenantId $azContext.Tenant.Id -NoWelcome
    
    # Verify connection
    $mgContext = Get-MgContext
    if ($mgContext) {
        Write-Log "Successfully connected to Microsoft Graph" "SUCCESS"
        Write-Log "Account: $($mgContext.Account)" "DEBUG"
        Write-Log "Scopes: $($mgContext.Scopes -join ', ')" "DEBUG"
        
        # Get the access token using the correct method for the available Graph module version
        try {
            # Try the newer method first
            if (Get-Command "Get-MgAccessToken" -ErrorAction SilentlyContinue) {
                $graphToken = Get-MgAccessToken
                Write-Log "Got access token using Get-MgAccessToken" "DEBUG"
            } else {
                # Fallback to accessing the token from the context
                $authProvider = $mgContext | Get-Member -Name "AuthType" -ErrorAction SilentlyContinue
                if ($authProvider) {
                    # For newer versions, try to get token from internal session
                    $graphToken = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance.AuthenticationProvider.GetAccessToken()
                    Write-Log "Got access token from GraphSession" "DEBUG"
                } else {
                    # Alternative method for older versions
                    Write-Log "Using Connect-MgGraph session - token will be handled internally" "DEBUG"
                    $graphToken = "INTERNAL_MG_SESSION" # Special marker to indicate we have a valid session
                }
            }
        } catch {
            Write-Log "Could not extract access token, but connection exists: $($_.Exception.Message)" "DEBUG"
            # Still mark as having a graph connection even if we can't extract the token
            $graphToken = "INTERNAL_MG_SESSION"
        }
        
        # Test the connection with a simple API call (if we have an actual token)
        if ($graphToken -and $graphToken -ne "INTERNAL_MG_SESSION") {
            $testHeaders = @{
                'Authorization' = "Bearer $graphToken"
                'Content-Type' = 'application/json'
            }
            
            try {
                $testUrl = "https://graph.microsoft.com/v1.0/me"
                $testResponse = Invoke-RestMethod -Uri $testUrl -Headers $testHeaders -Method Get -ErrorAction SilentlyContinue
                Write-Log "Graph token test successful - authenticated as: $($testResponse.userPrincipalName)" "SUCCESS"
            } catch {
                Write-Log "Graph token test failed: $($_.Exception.Message)" "WARNING"
                Write-Log "Will try using PowerShell cmdlets instead of REST API" "INFO"
            }
        } else {
            Write-Log "Using Microsoft Graph PowerShell session (no direct token access)" "INFO"
        }
    } else {
        Write-Log "Failed to establish Microsoft Graph context" "ERROR"
    }
    
} catch {
    Write-Log "Microsoft Graph connection failed: $($_.Exception.Message)" "ERROR"
    Write-Log "Attempting fallback authentication method..." "DEBUG"
    
    # Fallback to Azure session authentication
    try {
        $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, "Never", $null, "https://graph.microsoft.com/").AccessToken
        Write-Log "Fallback Graph token method succeeded" "SUCCESS"
    } catch {
        Write-Log "Fallback Graph token method also failed: $($_.Exception.Message)" "ERROR"
    }
}

if (!$graphToken) {
    Write-Log "Could not obtain Graph API token using any method" "WARNING"
    Write-Log "UPN resolution and Entra PIM assignments will be skipped" "WARNING"
    Write-Log "" "INFO"
    Write-Log "To access Entra PIM assignments, ensure you have:" "INFO"
    Write-Log "1. Global Administrator or Privileged Role Administrator role in Entra ID" "INFO"
    Write-Log "2. Sufficient permissions to consent to Graph API scopes" "INFO"
    Write-Log "3. Access to Privileged Identity Management features" "INFO"
    Write-Log "" "INFO"
} else {
    Write-Log "Graph API authentication successful - Entra PIM assignments will be processed" "SUCCESS"
}

# Set up headers for REST API calls
$azHeaders = @{
    'Authorization' = "Bearer $azToken"
    'Content-Type' = 'application/json'
}

# Get all subscriptions
Write-Log "Retrieving subscriptions..." "INFO"
$subscriptions = Get-AzSubscription
Write-Log "Found $($subscriptions.Count) subscriptions" "INFO"

# Initialize PIM results array
$pimResults = @()

# Process Azure subscription PIM assignments
Write-Log "Processing Azure subscription PIM assignments..." "INFO"
foreach ($subscription in $subscriptions) {
    Write-Log "Processing subscription: $($subscription.Name)" "INFO"
    
    try {
        # Construct REST API URL for PIM eligible assignments
        $apiUrl = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Authorization/roleEligibilitySchedules?api-version=2020-10-01"
        
        Write-Log "Calling REST API: $apiUrl" "DEBUG"
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $azHeaders -Method Get
        
        $assignments = $response.value
        Write-Log "Found $($assignments.Count) eligible assignments in subscription $($subscription.Name)" "INFO"
        
        foreach ($assignment in $assignments) {
            try {
                # Extract information directly from REST response
                $props = $assignment.properties
                
                # Get principal information and resolve UPN
                $principalId = $props.principalId
                $principalType = $props.principalType
                $principalName = "Unknown"
                $principalUPN = "N/A"
                
                # Principal name might be in expandedProperties or we'll use the ID
                if ($props.expandedProperties -and $props.expandedProperties.principal) {
                    $principalName = $props.expandedProperties.principal.displayName
                } elseif ($props.expandedProperties -and $props.expandedProperties.principalDisplayName) {
                    $principalName = $props.expandedProperties.principalDisplayName
                } else {
                    $principalName = $principalId  # Fallback to ID
                }
                
                # Try to resolve UPN for users via Microsoft Graph API
                if ($principalType -eq "User" -and $principalId -and $graphToken) {
                    try {
                        if ($graphToken -ne "INTERNAL_MG_SESSION") {
                            # Use REST API with actual token
                            $graphUrl = "https://graph.microsoft.com/v1.0/users/$principalId"
                            $graphHeaders = @{
                                'Authorization' = "Bearer $graphToken"
                                'Content-Type' = 'application/json'
                            }
                            $userInfo = Invoke-RestMethod -Uri $graphUrl -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
                            if ($userInfo -and $userInfo.userPrincipalName) {
                                $principalUPN = $userInfo.userPrincipalName
                                if ($userInfo.displayName) {
                                    $principalName = $userInfo.displayName
                                }
                                Write-Log "Resolved UPN for user $principalName`: $principalUPN" "DEBUG"
                            }
                        } else {
                            # Use PowerShell cmdlets with internal session
                            $userInfo = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                            if ($userInfo) {
                                $principalUPN = $userInfo.UserPrincipalName
                                if ($userInfo.DisplayName) {
                                    $principalName = $userInfo.DisplayName
                                }
                                Write-Log "Resolved UPN for user via cmdlet $principalName`: $principalUPN" "DEBUG"
                            }
                        }
                    } catch {
                        Write-Log "Could not resolve UPN for user $principalId`: $($_.Exception.Message)" "DEBUG"
                    }
                } elseif ($principalType -eq "User" -and !$graphToken) {
                    Write-Log "Graph token not available, skipping UPN resolution for $principalId" "DEBUG"
                }
                
                # Get role information
                $roleDefinitionId = $props.roleDefinitionId
                $roleName = "Unknown"
                if ($props.expandedProperties -and $props.expandedProperties.roleDefinition) {
                    $roleName = $props.expandedProperties.roleDefinition.displayName
                } elseif ($props.expandedProperties -and $props.expandedProperties.roleDefinitionDisplayName) {
                    $roleName = $props.expandedProperties.roleDefinitionDisplayName
                } else {
                    # Try to get role definition via separate API call
                    try {
                        $roleDefUrl = "https://management.azure.com$roleDefinitionId" + "?api-version=2018-01-01-preview"
                        $roleDefResponse = Invoke-RestMethod -Uri $roleDefUrl -Headers $azHeaders -Method Get
                        $roleName = $roleDefResponse.properties.roleName
                    } catch {
                        $roleName = "Unknown Role"
                    }
                }
                
                # Parse scope information - ENHANCED WITH MANAGEMENT GROUP SUPPORT
                $scope = $props.scope
                $resourceGroupName = "N/A"
                $scopeType = "Subscription"
                $scopeName = $subscription.Name
                $resourceName = "N/A"
                $resourceType = "N/A"
                $managementGroupId = "N/A"
                
                if ($scope) {
                    if ($scope -match "/providers/Microsoft\.Management/managementGroups/([^/]+)") {
                        # Management Group level assignment
                        $managementGroupId = $Matches[1]
                        $scopeType = "Management Group"
                        $scopeName = $managementGroupId
                        Write-Log "Detected management group assignment: $managementGroupId" "DEBUG"
                    } elseif ($scope -match "/subscriptions/[^/]+/resourceGroups/([^/]+)/?$") {
                        # Resource Group level assignment
                        $resourceGroupName = $Matches[1]
                        $scopeType = "Resource Group"
                        $scopeName = $resourceGroupName
                    } elseif ($scope -match "/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/([^/]+)/([^/]+)/([^/]+)") {
                        # Specific resource assignment
                        $resourceGroupName = $Matches[1]
                        $resourceType = $Matches[2] + "/" + $Matches[3]
                        $resourceName = $Matches[4]
                        $scopeType = "Resource"
                        $scopeName = "$resourceType/$resourceName"
                    }
                }
                
                # Extract PIM-specific timing information from the assignment properties
                $eligibilityStartDate = if ($props.startDateTime) { $props.startDateTime } else { "Not set" }
                $eligibilityEndDate = if ($props.endDateTime) { $props.endDateTime } else { "Permanent" }
                
                # Calculate eligibility duration if both start and end dates exist
                $eligibilityDurationDays = "Permanent"
                if ($props.startDateTime -and $props.endDateTime) {
                    try {
                        $startDate = [DateTime]::Parse($props.startDateTime)
                        $endDate = [DateTime]::Parse($props.endDateTime)
                        $duration = $endDate - $startDate
                        $eligibilityDurationDays = $duration.Days
                    } catch {
                        $eligibilityDurationDays = "Unable to calculate"
                    }
                }
                
                # Create result object - ENHANCED WITH MANAGEMENT GROUP ID
                $result = [PSCustomObject]@{
                    AssignmentType = "Azure Subscription Role"
                    AssignmentId = $assignment.name
                    AssignmentName = $assignment.name
                    PrincipalId = $principalId
                    PrincipalType = $principalType
                    PrincipalName = $principalName
                    PrincipalUPN = $principalUPN
                    RoleDefinitionId = $roleDefinitionId
                    RoleName = $roleName
                    ScopeId = $scope
                    ScopeName = $scopeName
                    ScopeType = $scopeType
                    ManagementGroupId = $managementGroupId
                    SubscriptionId = $subscription.Id
                    SubscriptionName = $subscription.Name
                    ResourceGroupName = $resourceGroupName
                    ResourceName = $resourceName
                    ResourceType = $resourceType
                    Status = $props.status
                    EligibilityStartDate = $eligibilityStartDate
                    EligibilityEndDate = $eligibilityEndDate
                    EligibilityDurationDays = $eligibilityDurationDays
                    MaxActivationDuration = "Requires policy lookup"
                    MaxActivationDurationHours = "Requires policy lookup"
                    StartDateTime = $props.startDateTime  # Legacy field
                    EndDateTime = $props.endDateTime      # Legacy field
                    CreatedDateTime = $props.createdOn
                    UpdatedDateTime = $props.updatedOn
                    MemberType = $props.memberType
                    Condition = $props.condition
                    ConditionVersion = $props.conditionVersion
                }
                
                $pimResults += $result
                
            } catch {
                Write-Log "Error processing subscription assignment $($assignment.name): $($_.Exception.Message)" "ERROR"
            }
        }
        
    } catch {
        Write-Log "Could not retrieve PIM assignments for subscription $($subscription.Name): $($_.Exception.Message)" "ERROR"
    }
}

# ========================================
# DEDUPLICATION LOGIC FOR MANAGEMENT GROUPS
# ========================================

Write-Log "Deduplicating management group assignments..." "INFO"
$originalCount = $pimResults.Count

# Group by AssignmentId to find duplicates
$groupedAssignments = $pimResults | Group-Object AssignmentId

$deduplicatedResults = @()
$duplicatesRemoved = 0

foreach ($group in $groupedAssignments) {
    if ($group.Count -gt 1) {
        # Multiple entries with same AssignmentId - check if any are management group assignments
        $mgmtGroupAssignment = $group.Group | Where-Object { $_.ScopeType -eq "Management Group" }
        
        if ($mgmtGroupAssignment) {
            # Keep only the management group assignment
            $deduplicatedResults += $mgmtGroupAssignment[0]
            $duplicatesRemoved += ($group.Count - 1)
            Write-Log "Deduplicated management group assignment: $($mgmtGroupAssignment[0].PrincipalName) -> $($mgmtGroupAssignment[0].RoleName) on MG $($mgmtGroupAssignment[0].ManagementGroupId)" "DEBUG"
        } else {
            # No management group assignment found, keep all entries
            $deduplicatedResults += $group.Group
        }
    } else {
        # Single entry, keep it
        $deduplicatedResults += $group.Group
    }
}

$pimResults = $deduplicatedResults
Write-Log "Deduplication complete: Removed $duplicatesRemoved duplicate subscription entries from management group assignments" "SUCCESS"
Write-Log "PIM results count: $originalCount -> $($pimResults.Count)" "INFO"

# ========================================
# RESOLVE MANAGEMENT GROUP NAMES
# ========================================

Write-Log "Resolving management group names for policy naming..." "INFO"

# Get unique management group IDs that need resolution
$mgmtGroupIds = $pimResults | Where-Object { $_.ScopeType -eq "Management Group" -and $_.ManagementGroupId -ne "N/A" } | Select-Object -ExpandProperty ManagementGroupId -Unique

if ($mgmtGroupIds.Count -gt 0) {
    Write-Log "Found $($mgmtGroupIds.Count) unique management groups to resolve" "INFO"
    
    # Create a hashtable to cache management group names
    $mgmtGroupNames = @{}
    
    foreach ($mgId in $mgmtGroupIds) {
        try {
            Write-Log "Resolving management group: $mgId" "DEBUG"
            
            # Try using Azure PowerShell cmdlet first
            try {
                $mgInfo = Get-AzManagementGroup -GroupId $mgId -ErrorAction Stop
                if ($mgInfo -and $mgInfo.DisplayName) {
                    $mgmtGroupNames[$mgId] = $mgInfo.DisplayName
                    Write-Log "Resolved management group $mgId -> $($mgInfo.DisplayName)" "DEBUG"
                } else {
                    Write-Log "Management group $mgId found but no DisplayName available" "WARNING"
                    $mgmtGroupNames[$mgId] = $mgId  # Fallback to ID
                }
            } catch {
                Write-Log "Azure PowerShell cmdlet failed for $mgId, trying REST API..." "DEBUG"
                
                # Fallback to REST API
                try {
                    $mgApiUrl = "https://management.azure.com/providers/Microsoft.Management/managementGroups/$mgId" + "?api-version=2020-05-01"
                    $mgResponse = Invoke-RestMethod -Uri $mgApiUrl -Headers $azHeaders -Method Get
                    
                    if ($mgResponse -and $mgResponse.properties -and $mgResponse.properties.displayName) {
                        $mgmtGroupNames[$mgId] = $mgResponse.properties.displayName
                        Write-Log "Resolved management group via API $mgId -> $($mgResponse.properties.displayName)" "DEBUG"
                    } else {
                        Write-Log "Management group $mgId found via API but no displayName available" "WARNING"
                        $mgmtGroupNames[$mgId] = $mgId  # Fallback to ID
                    }
                } catch {
                    Write-Log "Could not resolve management group name for $mgId via REST API: $($_.Exception.Message)" "WARNING"
                    $mgmtGroupNames[$mgId] = $mgId  # Fallback to ID
                }
            }
            
        } catch {
            Write-Log "Could not resolve management group name for $mgId`: $($_.Exception.Message)" "WARNING"
            $mgmtGroupNames[$mgId] = $mgId  # Fallback to ID
        }
    }
    
    # Update PIM results with resolved management group names
    foreach ($result in $pimResults) {
        if ($result.ScopeType -eq "Management Group" -and $result.ManagementGroupId -ne "N/A") {
            if ($mgmtGroupNames.ContainsKey($result.ManagementGroupId)) {
                # Add a new property for the resolved name
                $result | Add-Member -NotePropertyName "ManagementGroupName" -NotePropertyValue $mgmtGroupNames[$result.ManagementGroupId] -Force
                Write-Log "Updated result for $($result.PrincipalName) with management group name: $($mgmtGroupNames[$result.ManagementGroupId])" "DEBUG"
            } else {
                # Fallback to ID if resolution failed
                $result | Add-Member -NotePropertyName "ManagementGroupName" -NotePropertyValue $result.ManagementGroupId -Force
                Write-Log "Using management group ID as fallback for $($result.PrincipalName): $($result.ManagementGroupId)" "DEBUG"
            }
        } else {
            # For non-management group assignments, set to N/A
            $result | Add-Member -NotePropertyName "ManagementGroupName" -NotePropertyValue "N/A" -Force
        }
    }
    
    Write-Log "Management group name resolution complete" "SUCCESS"
} else {
    Write-Log "No management group assignments found - skipping name resolution" "INFO"
    
    # Add the property to all results for consistency
    foreach ($result in $pimResults) {
        $result | Add-Member -NotePropertyName "ManagementGroupName" -NotePropertyValue "N/A" -Force
    }
}

# Process Entra (Azure AD) PIM assignments
Write-Log "Processing Entra (Azure AD) PIM directory role assignments..." "INFO"

if (!$graphToken) {
    Write-Log "No Graph token available - skipping Entra PIM assignments" "WARNING"
} else {
    Write-Log "Note: Entra PIM requires specific Graph API permissions or PowerShell cmdlets" "INFO"
    
    # Try using PowerShell cmdlets first (preferred method)
    $entraAssignments = @()
    $usingCmdlets = $false
    
    # Check if we have a valid MgGraph session (either with token or internal session)
    $mgContext = Get-MgContext
    if ($mgContext -and ($graphToken -eq "INTERNAL_MG_SESSION" -or $graphToken)) {
        try {
            Write-Log "Attempting to use Microsoft.Graph PowerShell cmdlets..." "DEBUG"
            
            # Try to get assignments using PowerShell cmdlets
            $entraAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
            
            if ($entraAssignments.Count -gt 0) {
                Write-Log "Successfully retrieved $($entraAssignments.Count) Entra PIM assignments using PowerShell cmdlets" "SUCCESS"
                $usingCmdlets = $true
            } else {
                Write-Log "PowerShell cmdlets returned no results" "INFO"
                $usingCmdlets = $true  # Still mark as using cmdlets even if no results
            }
        } catch {
            Write-Log "PowerShell cmdlets approach failed: $($_.Exception.Message)" "WARNING"
            
            # Check if it's a permissions issue
            if ($_.Exception.Message -like "*Forbidden*" -or $_.Exception.Message -like "*403*") {
                Write-Log "Access denied - insufficient permissions for Entra PIM" "ERROR"
                Write-Log "Required roles: Global Administrator, Privileged Role Administrator, or Security Administrator" "INFO"
            }
        }
    }
    
    # If cmdlets didn't work and we have an actual token, try REST API
    if (!$usingCmdlets -and $graphToken -and $graphToken -ne "INTERNAL_MG_SESSION") {
        Write-Log "Falling back to REST API approach..." "DEBUG"
        Write-Log "Required Graph API permissions:" "INFO"
        Write-Log "- RoleEligibilitySchedule.Read.Directory" "INFO"
        Write-Log "- RoleManagement.Read.Directory" "INFO"
        Write-Log "- Directory.Read.All" "INFO"
        
        try {
            $entraApiUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules"
            
            Write-Log "Calling Entra PIM API: $entraApiUrl" "DEBUG"
            $graphHeaders = @{
                'Authorization' = "Bearer $graphToken"
                'Content-Type' = 'application/json'
            }
            
            $entraResponse = Invoke-RestMethod -Uri $entraApiUrl -Headers $graphHeaders -Method Get
            $entraAssignments = $entraResponse.value
            Write-Log "Successfully retrieved $($entraAssignments.Count) Entra PIM assignments using REST API" "SUCCESS"
            
        } catch {
            Write-Log "Could not retrieve Entra PIM assignments via REST API: $($_.Exception.Message)" "ERROR"
            Write-Log "This is likely due to insufficient Graph API permissions" "ERROR"
            Write-Log "Required permissions: RoleEligibilitySchedule.Read.Directory, RoleManagement.Read.Directory, Directory.Read.All" "ERROR"
            
            if ($_.Exception.Response) {
                Write-Log "Status Code: $($_.Exception.Response.StatusCode)" "ERROR"
                Write-Log "Status Description: $($_.Exception.Response.StatusDescription)" "ERROR"
            }
            
            Write-Log "Continuing with subscription PIM assignments only..." "INFO"
            $entraAssignments = @()
        }
    }
    
    # Process the Entra assignments if we got any
    if ($entraAssignments.Count -gt 0) {
        Write-Log "Processing $($entraAssignments.Count) Entra directory role assignments..." "INFO"
        
        foreach ($assignment in $entraAssignments) {
            try {
                Write-Log "Processing Entra assignment: $($assignment.id)" "DEBUG"
                
                # Get principal information and resolve UPN for Entra assignments
                $principalId = $assignment.principalId
                $principalType = "Unknown"
                $principalName = "Unknown"
                $principalUPN = "N/A"
                
                Write-Log "Resolving principal $principalId" "DEBUG"
                
                # Resolve principal details - use cmdlets if available, otherwise REST API
                if ($principalId) {
                    try {
                        if ($usingCmdlets) {
                            # Try using PowerShell cmdlets
                            try {
                                $userInfo = Get-MgUser -UserId $principalId -ErrorAction SilentlyContinue
                                if ($userInfo) {
                                    $principalType = "User"
                                    $principalName = $userInfo.DisplayName
                                    $principalUPN = $userInfo.UserPrincipalName
                                    Write-Log "Resolved as user via cmdlet: $principalName ($principalUPN)" "DEBUG"
                                } else {
                                    $groupInfo = Get-MgGroup -GroupId $principalId -ErrorAction SilentlyContinue
                                    if ($groupInfo) {
                                        $principalType = "Group"
                                        $principalName = $groupInfo.DisplayName
                                        Write-Log "Resolved as group via cmdlet: $principalName" "DEBUG"
                                    } else {
                                        $spInfo = Get-MgServicePrincipal -ServicePrincipalId $principalId -ErrorAction SilentlyContinue
                                        if ($spInfo) {
                                            $principalType = "ServicePrincipal"
                                            $principalName = $spInfo.DisplayName
                                            $principalUPN = $spInfo.AppId
                                            Write-Log "Resolved as service principal via cmdlet: $principalName" "DEBUG"
                                        }
                                    }
                                }
                            } catch {
                                Write-Log "Cmdlet resolution failed for $principalId`: $($_.Exception.Message)" "DEBUG"
                            }
                        } elseif ($graphToken -and $graphToken -ne "INTERNAL_MG_SESSION") {
                            # Use REST API approach
                            $graphHeaders = @{
                                'Authorization' = "Bearer $graphToken"
                                'Content-Type' = 'application/json'
                            }
                            
                            # Try as user first
                            $userUrl = "https://graph.microsoft.com/v1.0/users/$principalId"
                            $userInfo = Invoke-RestMethod -Uri $userUrl -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
                            if ($userInfo) {
                                $principalType = "User"
                                $principalName = $userInfo.displayName
                                $principalUPN = $userInfo.userPrincipalName
                                Write-Log "Resolved as user via API: $principalName ($principalUPN)" "DEBUG"
                            } else {
                                # Try as group
                                $groupUrl = "https://graph.microsoft.com/v1.0/groups/$principalId"
                                $groupInfo = Invoke-RestMethod -Uri $groupUrl -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
                                if ($groupInfo) {
                                    $principalType = "Group"
                                    $principalName = $groupInfo.displayName
                                    Write-Log "Resolved as group via API: $principalName" "DEBUG"
                                } else {
                                    # Try as service principal
                                    $spUrl = "https://graph.microsoft.com/v1.0/servicePrincipals/$principalId"
                                    $spInfo = Invoke-RestMethod -Uri $spUrl -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
                                    if ($spInfo) {
                                        $principalType = "ServicePrincipal"
                                        $principalName = $spInfo.displayName
                                        $principalUPN = $spInfo.appId
                                        Write-Log "Resolved as service principal via API: $principalName" "DEBUG"
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Log "Could not resolve Entra principal $principalId`: $($_.Exception.Message)" "DEBUG"
                    }
                }
                
                # Get role definition information
                $roleDefinitionId = $assignment.roleDefinitionId
                $roleName = "Unknown"
                Write-Log "Resolving role definition $roleDefinitionId" "DEBUG"
                
                if ($roleDefinitionId) {
                    try {
                        if ($usingCmdlets) {
                            # Use cmdlet to get role definition
                            $roleDefInfo = Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleDefinitionId -ErrorAction SilentlyContinue
                            if ($roleDefInfo) {
                                $roleName = $roleDefInfo.DisplayName
                                Write-Log "Resolved role via cmdlet: $roleName" "DEBUG"
                            }
                        } elseif ($graphToken -and $graphToken -ne "INTERNAL_MG_SESSION") {
                            # Use REST API to get role definition
                            $roleDefUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/$roleDefinitionId"
                            $graphHeaders = @{
                                'Authorization' = "Bearer $graphToken"
                                'Content-Type' = 'application/json'
                            }
                            $roleDefInfo = Invoke-RestMethod -Uri $roleDefUrl -Headers $graphHeaders -Method Get -ErrorAction SilentlyContinue
                            if ($roleDefInfo) {
                                $roleName = $roleDefInfo.displayName
                                Write-Log "Resolved role via API: $roleName" "DEBUG"
                            }
                        }
                    } catch {
                        Write-Log "Could not resolve Entra role definition $roleDefinitionId`: $($_.Exception.Message)" "DEBUG"
                    }
                }
                
                # Extract timing information
                $eligibilityStartDate = if ($assignment.startDateTime) { $assignment.startDateTime } else { "Not set" }
                $eligibilityEndDate = if ($assignment.endDateTime) { $assignment.endDateTime } else { "Permanent" }
                
                # Calculate eligibility duration
                $eligibilityDurationDays = "Permanent"
                if ($assignment.startDateTime -and $assignment.endDateTime) {
                    try {
                        $startDate = [DateTime]::Parse($assignment.startDateTime)
                        $endDate = [DateTime]::Parse($assignment.endDateTime)
                        $duration = $endDate - $startDate
                        $eligibilityDurationDays = $duration.Days
                    } catch {
                        $eligibilityDurationDays = "Unable to calculate"
                    }
                }
                
                # Create result object for Entra assignment
                $result = [PSCustomObject]@{
                    AssignmentType = "Entra Directory Role"
                    AssignmentId = $assignment.id
                    AssignmentName = $assignment.id
                    PrincipalId = $principalId
                    PrincipalType = $principalType
                    PrincipalName = $principalName
                    PrincipalUPN = $principalUPN
                    RoleDefinitionId = $roleDefinitionId
                    RoleName = $roleName
                    ScopeId = $assignment.directoryScopeId
                    ScopeName = if ($assignment.directoryScopeId -eq "/") { "Directory" } else { $assignment.directoryScopeId }
                    ScopeType = "Directory"
                    ManagementGroupId = "N/A"
                    SubscriptionId = "N/A"
                    SubscriptionName = "N/A"
                    ResourceGroupName = "N/A"
                    ResourceName = "N/A"
                    ResourceType = "N/A"
                    Status = $assignment.status
                    EligibilityStartDate = $eligibilityStartDate
                    EligibilityEndDate = $eligibilityEndDate
                    EligibilityDurationDays = $eligibilityDurationDays
                    MaxActivationDuration = "Requires policy lookup"
                    MaxActivationDurationHours = "Requires policy lookup"
                    StartDateTime = $assignment.startDateTime
                    EndDateTime = $assignment.endDateTime
                    CreatedDateTime = $assignment.createdDateTime
                    UpdatedDateTime = $assignment.modifiedDateTime
                    MemberType = $assignment.memberType
                    Condition = $null
                    ConditionVersion = $null
                }
                
                $pimResults += $result
                Write-Log "Added Entra assignment: $principalName -> $roleName" "DEBUG"
                
            } catch {
                Write-Log "Error processing Entra assignment $($assignment.id): $($_.Exception.Message)" "ERROR"
            }
        }
    } else {
        Write-Log "No Entra PIM assignments found or accessible" "WARNING"
    }
}

Write-Log "=== PIM EXPORT SUMMARY ===" "INFO"
Write-Log "Total PIM assignments found: $($pimResults.Count)" "SUCCESS"

if ($pimResults.Count -eq 0) {
    Write-Log "No PIM assignments found. Exiting." "ERROR"
    exit 1
}

# Display summary statistics
Write-Log "`nAssignment Types:" "INFO"
$pimResults | Group-Object AssignmentType | Sort-Object Count -Descending | ForEach-Object {
    Write-Log "$($_.Name): $($_.Count)" "INFO"
}

Write-Log "`nPrincipal Types:" "INFO"
$pimResults | Group-Object PrincipalType | Sort-Object Count -Descending | ForEach-Object {
    Write-Log "$($_.Name): $($_.Count)" "INFO"
}

Write-Log "`nScope Types:" "INFO"
$pimResults | Group-Object ScopeType | Sort-Object Count -Descending | ForEach-Object {
    Write-Log "$($_.Name): $($_.Count)" "INFO"
}

# ========================================
# STEP 2: AUTHENTICATE WITH CYBERARK
# ========================================

Write-Log "=== STEP 2: AUTHENTICATING WITH CYBERARK SCA ===" "INFO"

$authUrl = "$authBaseUrl$platformTokenEndpoint"

# Build form data for OAuth2 client credentials flow
# First try with scope parameter
$authBody = @{
    grant_type = "client_credentials"
    client_id = $username
    client_secret = $password
    scope = "sca"
}

$authHeaders = @{
    'Content-Type' = 'application/x-www-form-urlencoded'
}

Write-Host "Calling: $authUrl" -ForegroundColor Gray
Write-Host "Trying with scope parameter first..." -ForegroundColor Gray

try {
    $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -Headers $authHeaders
    $accessToken = $authResponse.access_token
    Write-Host "Authentication successful!" -ForegroundColor Green
} catch {
    Write-Host "First attempt failed, trying without scope..." -ForegroundColor Yellow
    
    # Try without scope
    $authBody = @{
        grant_type = "client_credentials"
        client_id = $username
        client_secret = $password
    }
    
    try {
        $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -Headers $authHeaders
        $accessToken = $authResponse.access_token
        Write-Host "Authentication successful without scope!" -ForegroundColor Green
    } catch {
        Write-Host "Second attempt failed, trying username/password format..." -ForegroundColor Yellow
        
        # Try original username/password format
        $authBody = @{
            grant_type = "password"
            username = $username
            password = $password
        }
        
        try {
            $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -Body $authBody -Headers $authHeaders
            $accessToken = $authResponse.access_token
            Write-Host "Authentication successful with password grant!" -ForegroundColor Green
        } catch {
            Write-Error "All authentication attempts failed!"
            Write-Error "Last error: $($_.Exception.Message)"
            
            if ($_.Exception.Response) {
                Write-Error "Status Code: $($_.Exception.Response.StatusCode)"
                Write-Error "Status Description: $($_.Exception.Response.StatusDescription)"
                
                # Try to read the response content for more details
                try {
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $responseContent = $reader.ReadToEnd()
                    Write-Error "Response Content: $responseContent"
                } catch {
                    Write-Error "Could not read response content"
                }
            }
            
            Write-Host "`nPlease verify your credentials and tenant information:" -ForegroundColor Yellow
            Write-Host "- Identity Tenant ID: $identityTenantId" -ForegroundColor Yellow
            Write-Host "- Username/Client ID: $username" -ForegroundColor Yellow
            Write-Host "- URL being called: $authUrl" -ForegroundColor Yellow
            
            exit 1
        }
    }
}

# Set up headers for API calls
$apiHeaders = @{
    'Authorization' = "Bearer $accessToken"
    'Content-Type' = 'application/json'
}

# ========================================
# STEP 3: CREATE CYBERARK SCA POLICIES
# ========================================

Write-Log "=== STEP 3: CREATING CYBERARK SCA POLICIES ===" "INFO"

$successCount = 0
$errorCount = 0
$migrationResults = @()
$processedCount = 0

foreach ($assignment in $pimResults) {
    try {
        $processedCount++
        
        # Skip ServicePrincipal assignments
        if ($assignment.PrincipalType -eq "ServicePrincipal") {
            Write-Log "[$processedCount/$($pimResults.Count)] Skipping ServicePrincipal: $($assignment.PrincipalName) -> $($assignment.RoleName)" "INFO"
            continue
        }
        
        Write-Log "[$processedCount/$($pimResults.Count)] Processing: $($assignment.PrincipalName) -> $($assignment.RoleName) on $($assignment.ScopeName)" "INFO"
        
        # Build policy name with enhanced logic for management groups
        $policyNamePrefix = ""
        if ($assignment.AssignmentType -eq "Entra Directory Role") {
            $policyNamePrefix = "Entra"
        } elseif ($assignment.ScopeType -eq "Management Group") {
            # Use the resolved management group name instead of the GUID
            $mgName = if ($assignment.ManagementGroupName -and $assignment.ManagementGroupName -ne "N/A") { 
                $assignment.ManagementGroupName 
            } else { 
                $assignment.ManagementGroupId 
            }
            $policyNamePrefix = "MG-$mgName"
        } else {
            $policyNamePrefix = $assignment.SubscriptionName
        }
        
        $policyName = "$policyNamePrefix-$($assignment.PrincipalName)-$($assignment.RoleName)"
        if ($config["POLICY_NAME_PREFIX"]) { 
            $policyName = "$($config["POLICY_NAME_PREFIX"])$policyName" 
        }
        if ($config["POLICY_NAME_SUFFIX"]) { 
            $policyName = "$policyName$($config["POLICY_NAME_SUFFIX"])" 
        }
        
        # Build description with today's date
        $todayDate = Get-Date -Format "yyyy-MM-dd"
        $description = "Migrated from PIM on $todayDate"
        
        # Convert dates to ISO format with past date handling
        $startDate = $null
        $endDate = $null
        $currentDateTime = Get-Date
        
        # Only set dates if the assignment is not permanent
        if ($assignment.EligibilityEndDate -and $assignment.EligibilityEndDate -ne "Permanent") {
            # Handle start date
            if ($assignment.EligibilityStartDate -and $assignment.EligibilityStartDate -ne "Not set") {
                try {
                    $parsedStartDate = [DateTime]$assignment.EligibilityStartDate
                    
                    # Check if start date is in the past
                    if ($parsedStartDate -lt $currentDateTime) {
                        Write-Log "Original start date $($assignment.EligibilityStartDate) is in the past. Using current date instead." "WARNING"
                        $startDate = $currentDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    } else {
                        $startDate = $parsedStartDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    }
                } catch {
                    Write-Log "Could not parse start date: $($assignment.EligibilityStartDate)" "WARNING"
                    # If we can't parse the start date, use current date as fallback
                    Write-Log "Using current date as fallback for start date" "INFO"
                    $startDate = $currentDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
            }
            
            # Handle end date
            try {
                $parsedEndDate = [DateTime]$assignment.EligibilityEndDate
                
                # Ensure end date is after start date (if start date exists)
                if ($startDate) {
                    $startDateParsed = [DateTime]::Parse($startDate)
                    if ($parsedEndDate -le $startDateParsed) {
                        Write-Log "End date $($assignment.EligibilityEndDate) is not after start date. Adjusting end date to be 1 year from start date." "WARNING"
                        $adjustedEndDate = $startDateParsed.AddYears(1)
                        $endDate = $adjustedEndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    } else {
                        $endDate = $parsedEndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    }
                } else {
                    $endDate = $parsedEndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                }
                
            } catch {
                Write-Log "Could not parse end date: $($assignment.EligibilityEndDate)" "WARNING"
            }
        } else {
            Write-Log "Assignment is permanent - setting both startDate and endDate to null" "DEBUG"
        }
        
        # Enhanced entity configuration based on scope type
        $isDirectoryRole = ($assignment.AssignmentType -eq "Entra Directory Role")
        $isManagementGroup = ($assignment.ScopeType -eq "Management Group")
        
        if ($isDirectoryRole) {
            # For Entra directory roles: entityId is the role definition ID
            $entityId = $assignment.RoleDefinitionId
            $workspaceType = "directory"
            $entitySourceId = $organizationId  # Azure tenant ID (same as organization_id)
            $roleOrganizationId = $organizationId  # Azure tenant ID
        } elseif ($isManagementGroup) {
            # For management group assignments: entityId is just the role definition, not the full path
            $entityId = $assignment.RoleDefinitionId
            $workspaceType = "management_group"
            $entitySourceId = "providers/Microsoft.Management/managementGroups/$($assignment.ManagementGroupId)"
            $roleOrganizationId = $organizationId  # Azure tenant ID
        } else {
            # For subscription roles: entityId includes full subscription path
            $entityId = "/subscriptions/$($assignment.SubscriptionId)$($assignment.RoleDefinitionId)"
            $workspaceType = "subscription"
            $entitySourceId = "subscriptions/$($assignment.SubscriptionId)"
            $roleOrganizationId = $organizationId  # Azure tenant ID
        }
        
        Write-Log "Assignment type: $($assignment.AssignmentType), Scope type: $($assignment.ScopeType), Workspace type: $workspaceType" "DEBUG"
        Write-Log "Entity ID: $entityId" "DEBUG"
        Write-Log "EntitySourceId: $entitySourceId" "DEBUG"
        
        # Convert principal type to lowercase (handle null values)
        $entityClass = if ($assignment.PrincipalType) { $assignment.PrincipalType.ToLower() } else { "unknown" }
        
        # Build the policy JSON to match CyberArk API format
        $policyJson = @{
            csp = "AZURE"
            name = $policyName
            description = $description
            startDate = $startDate
            endDate = $endDate
            roles = @(
                @{
                    entityId = $entityId
                    workspaceType = $workspaceType
                    entitySourceId = $entitySourceId
                    organization_id = $roleOrganizationId
                }
            )
            identities = @(
                @{
                    entityName = if ($assignment.PrincipalUPN -and $assignment.PrincipalUPN -ne "N/A") { $assignment.PrincipalUPN } else { $assignment.PrincipalName }
                    entitySourceId = $identityEntitySourceId
                    entityClass = $entityClass
                }
            )
            accessRules = @{
                days = @(
                    "Sunday",
                    "Monday", 
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday"
                )
                fromTime = $null
                toTime = $null
                maxSessionDuration = [int]$sessionDuration
                timeZone = $timezone
            }
        }
        
        # Convert to JSON
        $policyBody = $policyJson | ConvertTo-Json -Depth 10
        
        Write-Log "Policy JSON for $($policyName):" "DEBUG"
        Write-Log $policyBody "DEBUG"
        
        if ($testMode) {
            Write-Log "Test Mode: Policy JSON generated successfully for $($policyName)" "SUCCESS"
            Write-Log "Entity ID: $entityId" "DEBUG"
            Write-Log "Identity: $($assignment.PrincipalName) ($entityClass)" "DEBUG"
            $successCount++
        } else {
            # Create the policy via API
            $createPolicyUrl = "$apiBaseUrl$createPolicyEndpoint"
            
            Write-Log "Creating policy: $($policyName) at URL: $createPolicyUrl" "DEBUG"
            
            try {
                $policyResponse = Invoke-RestMethod -Uri $createPolicyUrl -Method Post -Body $policyBody -Headers $apiHeaders
                
                # The expected response field is job_id
                $jobId = if ($policyResponse.job_id) {
                    $policyResponse.job_id
                } else {
                    "UNKNOWN_JOB_ID_FORMAT"
                    Write-Log "API response does not contain expected job_id field. Available fields: $($policyResponse.PSObject.Properties.Name -join ', ')" "WARNING"
                }
                
                Write-Log "Policy created successfully - Job ID: $jobId" "SUCCESS"
                $successCount++
            } catch {
                Write-Log "Failed to create policy $($policyName): $($_.Exception.Message)" "ERROR"
                if ($_.Exception.Response) {
                    Write-Log "Policy creation status code: $($_.Exception.Response.StatusCode)" "ERROR"
                    Write-Log "Policy creation status description: $($_.Exception.Response.StatusDescription)" "ERROR"
                    
                    # Try to read the response content for more details
                    try {
                        $responseStream = $_.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($responseStream)
                        $reader.BaseStream.Position = 0
                        $responseContent = $reader.ReadToEnd()
                        Write-Log "Policy creation response content: $responseContent" "ERROR"
                        $reader.Close()
                    } catch {
                        Write-Log "Could not read policy creation response content: $($_.Exception.Message)" "ERROR"
                    }
                }
                throw  # Re-throw to be caught by outer catch block
            }
        }
        
        # Store migration result
        $migrationResults += [PSCustomObject]@{
            OriginalAssignmentId = $assignment.AssignmentId
            PrincipalName = $assignment.PrincipalName
            PrincipalType = $assignment.PrincipalType
            RoleName = $assignment.RoleName
            SubscriptionName = $assignment.SubscriptionName
            PolicyName = $policyName
            CyberArkJobId = if ($testMode) { "TEST_MODE" } else { $jobId }
            StartDate = $startDate
            EndDate = $endDate
            EntityId = $entityId
            Status = "Success"
            Error = $null
        }
        
        # Batch processing delay
        if ($processedCount % $batchSize -eq 0 -and $processedCount -lt $pimResults.Count) {
            Write-Log "Processed $processedCount assignments. Pausing for $batchDelay seconds..." "INFO"
            Start-Sleep -Seconds $batchDelay
        }
        
    } catch {
        Write-Log "Failed to create policy for $($assignment.PrincipalName): $($_.Exception.Message)" "ERROR"
        $errorCount++
        
        # Store error result
        $migrationResults += [PSCustomObject]@{
            OriginalAssignmentId = $assignment.AssignmentId
            PrincipalName = $assignment.PrincipalName
            PrincipalType = $assignment.PrincipalType
            RoleName = $assignment.RoleName
            SubscriptionName = $assignment.SubscriptionName
            PolicyName = $policyName
            CyberArkPolicyId = $null
            StartDate = $startDate
            EndDate = $endDate
            EntityId = $entityId
            Status = "Failed"
            Error = $_.Exception.Message
        }
    }
}

# ========================================
# STEP 4: FINAL SUMMARY
# ========================================

Write-Log "=== MIGRATION SUMMARY ===" "INFO"
Write-Log "Total PIM assignments processed: $($pimResults.Count)" "INFO"
Write-Log "Successful policy creations: $successCount" "SUCCESS"
Write-Log "Failed policy creations: $errorCount" "$(if ($errorCount -gt 0) { 'ERROR' } else { 'INFO' })"

if ($testMode) {
    Write-Log "*** Test mode completed - no actual policies were created ***" "WARNING"
}

if ($errorCount -gt 0) {
    Write-Log "Failed migrations:" "ERROR"
    $migrationResults | Where-Object { $_.Status -eq "Failed" } | ForEach-Object {
        Write-Log "Failed: $($_.PrincipalName) - $($_.RoleName) - Error: $($_.Error)" "ERROR"
    }
}

# Store results in global variables
$Global:PIMExportData = $pimResults
$Global:MigrationResults = $migrationResults

Write-Log "Results available in global variables:" "INFO"
Write-Log "`$Global:PIMExportData - Original PIM data ($($pimResults.Count) records)" "DEBUG"
Write-Log "`$Global:MigrationResults - Migration results ($($migrationResults.Count) records)" "DEBUG"

# Show successful policies summary
$successfulPolicies = $migrationResults | Where-Object { $_.Status -eq "Success" }
if ($successfulPolicies.Count -gt 0) {
    Write-Log "Successful policy creations:" "SUCCESS"
    $successfulPolicies | Select-Object -First 5 | ForEach-Object {
        Write-Log "Success: $($_.PolicyName) - Job ID: $($_.CyberArkJobId)" "SUCCESS"
    }
    
    if ($successfulPolicies.Count -gt 5) {
        Write-Log "... and $($successfulPolicies.Count - 5) more policies created successfully" "SUCCESS"
    }
}

$logEndTime = Get-Date
$totalDuration = $logEndTime - $logStartTime
Write-Log "=== MIGRATION COMPLETE ===" "INFO"
Write-Log "Total execution time: $($totalDuration.ToString('hh\:mm\:ss'))" "INFO"
Write-Log "Log file saved to: $logFile" "INFO"