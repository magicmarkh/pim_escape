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
try {
    $graphToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($azContext.Account, $azContext.Environment, $azContext.Tenant.Id, $null, "Never", $null, "https://graph.microsoft.com/").AccessToken
    Write-Log "Successfully obtained Graph API token" "DEBUG"
} catch {
    Write-Log "Could not obtain Graph API token: $($_.Exception.Message)" "WARNING"
    Write-Log "UPN resolution will be skipped" "WARNING"
    $graphToken = $null
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
                
                # Parse scope information
                $scope = $props.scope
                $resourceGroupName = "N/A"
                $scopeType = "Subscription"
                $scopeName = $subscription.Name
                $resourceName = "N/A"
                $resourceType = "N/A"
                
                if ($scope) {
                    if ($scope -match "/subscriptions/[^/]+/resourceGroups/([^/]+)/?$") {
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
                
                # Create result object
                $result = [PSCustomObject]@{
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
                Write-Log "Error processing assignment $($assignment.name): $($_.Exception.Message)" "ERROR"
            }
        }
        
    } catch {
        Write-Log "Could not retrieve PIM assignments for subscription $($subscription.Name): $($_.Exception.Message)" "ERROR"
    }
}

Write-Log "=== PIM EXPORT SUMMARY ===" "INFO"
Write-Log "Total PIM assignments found: $($pimResults.Count)" "SUCCESS"

if ($pimResults.Count -eq 0) {
    Write-Log "No PIM assignments found. Exiting." "ERROR"
    exit 1
}

# Display summary statistics
Write-Host "`nPrincipal Types:" -ForegroundColor Cyan
$pimResults | Group-Object PrincipalType | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor White
}

Write-Host "`nScope Types:" -ForegroundColor Cyan
$pimResults | Group-Object ScopeType | Sort-Object Count -Descending | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor White
}

Write-Host "`nTop 5 Most Common Roles:" -ForegroundColor Cyan
$pimResults | Group-Object RoleName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
    Write-Host "$($_.Name): $($_.Count)" -ForegroundColor White
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
        Write-Log "[$processedCount/$($pimResults.Count)] Processing: $($assignment.PrincipalName) -> $($assignment.RoleName) on $($assignment.SubscriptionName)" "INFO"
        
        # Build policy name with optional prefix/suffix
        $policyName = "$($assignment.SubscriptionName)-$($assignment.PrincipalName)-$($assignment.RoleName)"
        if ($config["POLICY_NAME_PREFIX"]) { $policyName = "$($config["POLICY_NAME_PREFIX"])$policyName" }
        if ($config["POLICY_NAME_SUFFIX"]) { $policyName = "$policyName$($config["POLICY_NAME_SUFFIX"])" }
        
        # Build description with today's date
        $todayDate = Get-Date -Format "yyyy-MM-dd"
        $description = "Migrated from PIM on $todayDate"
        
        # Convert dates to ISO format
        $startDate = $null
        $endDate = $null
        
        if ($assignment.EligibilityStartDate -and $assignment.EligibilityStartDate -ne "Not set") {
            try {
                $startDate = ([DateTime]$assignment.EligibilityStartDate).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            } catch {
                Write-Log "Could not parse start date: $($assignment.EligibilityStartDate)" "WARNING"
            }
        }
        
        if ($assignment.EligibilityEndDate -and $assignment.EligibilityEndDate -ne "Permanent") {
            try {
                $endDate = ([DateTime]$assignment.EligibilityEndDate).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            } catch {
                Write-Log "Could not parse end date: $($assignment.EligibilityEndDate)" "WARNING"
            }
        }
        
        # Build entityId - combine subscription path with role definition
        $entityId = "/subscriptions/$($assignment.SubscriptionId)$($assignment.RoleDefinitionId)"
        
        # Build entitySourceId for subscription
        $entitySourceId = "subscriptions/$($assignment.SubscriptionId)"
        
        # Convert principal type to lowercase
        $entityClass = $assignment.PrincipalType.ToLower()
        
        # Build entitySourceId for subscription
        $entitySourceId = "subscriptions/$($assignment.SubscriptionId)"
        
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
                    workspaceType = "subscription"
                    entitySourceId = $entitySourceId
                    organization_id = $organizationId  # Azure AD/Entra ID Tenant ID
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