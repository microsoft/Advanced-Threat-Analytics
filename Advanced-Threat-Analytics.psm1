
<#
.Synopsis
Set-ATACenterURL is for setting the the URL to be used for the rest of the cmdlets.

.DESCRIPTION
By default, this module uses localhost as the URL. This can be overwritten with Set-ATACenterURL. It is recommended to run this cmdlet in your profile to prevent having to set it for each new session.

.EXAMPLE
Set-ATACenterURL -URL atacenter.contoso.com

The above cmdlet sets $ATACenter as a global variable in the current session. This variable is used for other cmdlets in this module.
#>
function Set-ATACenterURL {
    [CmdletBinding()]
    Param
    (
        # ATA Center URL. Located in ATA Center Configuration. (Example: atacenter.mydomain.com)
        [Parameter(Mandatory = $true,
                    Position = 0)]
        [string]$URL
    )
    $Global:ATACenter = "$URL"
}

<#
.Synopsis
Resolve-ATASelfSignedCert is used if you are having SSL/TLS tunnel issues with this module and know you are using a self signed certificate for your ATA Center.

.DESCRIPTION
Credit to railroadmanuk for most of this code.
https://virtualbrakeman.wordpress.com/2016/03/20/powershell-could-not-create-ssltls-secure-channel/

.EXAMPLE
Resolve-ATASelfSignedCert

The above cmdlet attempts to remediate the SSL error received from using a self-signed certificate.
#>
function Resolve-ATASelfSignedCert {
    try {
        Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy
{
public bool CheckValidationResult(
ServicePoint srvPoint, X509Certificate certificate,
WebRequest request, int certificateProblem)
{
return true;
}
}
"@
    }
    catch {
        Write-Error $_
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    }

<#
.Synopsis
    Get-ATASuspiciousActivity is used to retrieve suspicious activities triggered in ATA.
.DESCRIPTION
    Running just Get-ATASuspiciousActivity will return a full listing of all SA's. You may also pass in a unique SA ID to fetch information around a single SA. The 'Profile' switch may be used to get more information around the context of the attack.
.EXAMPLE
    Get-ATASuspiciousActivity


    WindowsEventId              : 2007
    ExclusionUniqueEntityId     : computer 10.1.2.7
    SourceComputerId            : computer 10.1.2.7
    DestinationComputerIds      : {ff336d33-81f4-458c-b70b-33f0070ffb20}
    RelatedUniqueEntityIds      : {computer 10.1.2.7, ff336d33-81f4-458c-b70b-33f0070ffb20}
    IsAdditionalDataAvailable   : False
    SystemCreationTime          : 2017-04-17T23:16:49.6943463Z
    SystemUpdateTime            : 2017-05-18T16:22:08.9346648Z
    ReasonKey                   : DnsReconnaissanceSuspiciousActivityReason
    EvidenceKeys                : {}
    HasDetails                  : True
    RelatedActivityCount        : 1
    SourceIpAddresses           : {10.1.2.7}
    Id                          : 58f54ce12aaea50ff89b38a7
    StartTime                   : 2017-04-17T23:16:33.4600665Z
    EndTime                     : 2017-04-17T23:16:33.4600665Z
    Severity                    : Medium
    Status                      : Open
    StatusUpdateTime            : 2017-05-18T16:22:08.9346648Z
    TitleKey                    : DnsReconnaissanceSuspiciousActivityTitle
    DescriptionFormatKey        : DnsReconnaissanceSuspiciousActivityDescription
    DescriptionDetailFormatKeys : {}
    Type                        : DnsReconnaissanceSuspiciousActivity

    The above command retrieves a listing of all Suspicious Activities.

.EXAMPLE
    Get-ATASuspiciousActivity -Id 58f54ce12aaea50ff89b38a7 -Details


    Query                  : contoso.com
    RecordType             : Axfr
    ResponseCode           : ConnectionRefused
    AttemptCount           : 1
    DestinationComputerIds : {ff336d33-81f4-458c-b70b-33f0070ffb20}
    StartTime              : 2017-04-17T23:16:33.4600665Z
    EndTime                : 2017-04-17T23:16:33.4600665Z

    The above example retrieves the details around a specified suspicious activity.

.EXAMPLE
    Get-ATASuspiciousActivity -Id 58f54ce12aaea50ff89b38a7 -Export C:\Temp

    The above example downloads the Excel file for the specified suspicious activity to the C:\Temp folder.
#>
function Get-ATASuspiciousActivity {
    [CmdletBinding()]
    Param
    (
        # Unique Id of Suspicious Activity.
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Fetch')]
        [ValidatePattern('^[a-f0-9]{24}$')]
        [string]$Id,

        # Retrieves more details for the suspicious activity, such as time, query, attempts, result, response, etc.
        [Parameter(Mandatory = $false,
            ParameterSetName = 'Fetch')]
        [switch]$Details,

        # Downloads the suspicious activity Excel export to the specified folder path. Example: 'C:\temp'
        [Parameter(Mandatory = $false,
            ParameterSetName = 'Fetch')]
        [string]$Export
    )
    begin {
        if (!$Global:ATACenter) {$Script:ATACenter = 'localhost'}
        if ($Details -and $Excel) {Write-Error "You may not select both 'Excel' and 'Details' switch parameters."}
    }
    Process {
        try{
            if ($PSCmdlet.ParameterSetName -eq 'Fetch' -and !$Details -and !$Export) {
                $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities/$id" -Method Get -UseDefaultCredentials
                $result
            }
            if ($PSCmdlet.ParameterSetName -eq 'Fetch' -and $Details) {
                $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities/$id/details" -Method Get -UseDefaultCredentials
                $result.DetailsRecords
            }
            if ($Details -and !$Id) {
                Write-Error "You must specify a suspicious activity ID when using the 'details' switch."
            }
            if ($PSCmdlet.ParameterSetName -eq 'Fetch' -and $Export) {
                try {
                    $ExcelFilePath = $Export + "/SA_$Id" + '.xlsx'
                    $ExcelLocale = 'excel?localeId=en-us'
                    $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities/$Id/$ExcelLocale" -OutFile $ExcelFilePath -Method Get -UseDefaultCredentials
                    $result
                }
                catch {
                    $_
                }
            }
            if ($PSCmdlet.ParameterSetName -ne 'Fetch') {
                $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities" -Method Get -UseDefaultCredentials
                $result
            }
        }
        catch{
            if ($_.Exception.Message -match 'SSL/TLS secure channel'){
                Write-Error "Could not establish trust relationship for the SSL/TLS secure channel. Please run Resolve-ATASelfSignedCert and try again." -ErrorAction Stop
            }
            if ($_.Exception.Message -match 'unable to connect'){
                Write-Error "Unable to connect to remote server. Your ATACenter url is set to $ATACenter. Run Set-ATACenterURL '<url>' if this is incorrect." -ErrorAction Stop
            }
            else {
                Write-Error $_ -ErrorAction Stop
            }
        }
    }
    end {
    }
}

<#
.Synopsis
    Set-ATASuspiciousActivity is used to update the status of a suspcious activity.
.DESCRIPTION
    This cmdlet requires a suspicious activity ID and a status. Available status types are Open, Closed, and Suppressed.
.EXAMPLE
    Set-ATASuspiciousActivity -Id 58f54ce12aaea50ff89b38a7 -Status Closed; Get-ATASuspiciousActivity | select Id, Status | ft

    Id                             Status
    --                             ------
    58f54ce12aaea50ff89b38a7       Closed

    The above command sets the specified Suspicious Activity to a Closed state, then displays the current status for the SA.
#>
function Set-ATASuspiciousActivity {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    Param
    (
        # Unique Id of the Suspicious Activity
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Fetch')]
        [ValidatePattern('^[a-f0-9]{24}$')]
        [string]$Id,

        # The specified status to update the Suspicious Activity. (Open, Closed, Suppressed)
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1,
            ParameterSetName = 'Fetch')]
        [ValidateSet('Open', 'Closed', 'CloseAndExclude', 'Suppressed', 'Delete', 'DeleteSameType')]
        [string]$Status,

        # Suppress 'Confirm' dialogue
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $false)]
        [switch]$Force
    )
    Begin{
        if (!$Global:ATACenter) {$Script:ATACenter = 'localhost'}
    }
    Process {
        try{
            if ($PSCmdlet.ParameterSetName -eq 'Fetch' -and $Status -ne 'Delete' -and $Status -ne 'DeleteSameType') {
                if ($Force -or $PSCmdlet.ShouldProcess($Id, "Changing status to $Status")) {
                    $body = @{}
                    if ($Status) {$body += @{Status = $Status}
                    }
                    if ($Status -eq 'Closed') {$body += @{ShouldExclude = $false}
                    }
                    if ($Status -eq 'CloseAndExclude') {$body += @{ShouldExclude = $true}
                    }
                    $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities/$id" -Method Post -Body $body -UseDefaultCredentials
                }
            }

            if ($PSCmdlet.ParameterSetName -eq 'Fetch' -and $Status -eq 'Delete') {
                if ($Force -or $PSCmdlet.ShouldProcess($Id, "Changing status to $Status")) {
                    $ShouldDelete = '?shouldDeleteSameType=false'
                    $body = @{}
                    $body += @{shouldDeleteSametype = $false}
                    $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities/$id$ShouldDelete" -Method Delete -UseDefaultCredentials
                }
            }

            if ($PSCmdlet.ParameterSetName -eq 'Fetch' -and $Status -eq 'DeleteSameType' -and $PSCmdlet.ShouldProcess($Id, "Changing status to $Status")) {
                if ($Force -or $PSCmdlet.ShouldProcess($Id, "Changing status to $Status")) {
                    $ShouldDelete = '?shouldDeleteSameType=true'
                    $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/suspiciousActivities/$id$ShouldDelete" -Method Delete -UseDefaultCredentials
                }
            }
        }
        catch{
            if ($_.Exception.Message -match 'SSL/TLS secure channel'){
                Write-Error "Could not establish trust relationship for the SSL/TLS secure channel. Please run Resolve-ATASelfSignedCert and try again." -ErrorAction Stop
            }
            if ($_.Exception.Message -match 'unable to connect'){
                Write-Error "Unable to connect to remote server. Your ATACenter url is set to $ATACenter. Run Set-ATACenterURL '<url>' if this is incorrect." -ErrorAction Stop
            }
            else {
                Write-Error $_ -ErrorAction Stop
            }
        }
    }
    end {
        $result
    }
}

#region Get-ATAStatus
<#
.Synopsis
    Get-ATAStatus retrieves status information for ATA.
.DESCRIPTION
    This cmdlet displays a wide range of information around your current ATA Center components, such as the Center, Gateways, and License.
.EXAMPLE
    Get-ATAStatus -Center | Select -ExpandProperty Configuration

    AbnormalBehaviorDetectorConfiguration                                          : @{BuildModelsConfiguration=; CreateSuspiciousActivitiesConfiguration=;
                                                                                     MinActiveAccountCount=50; SuspiciousActivityCreationDataMaxCount=1000;
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    AbnormalKerberosDetectorConfiguration                                          : @{ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    AbnormalSensitiveGroupMembershipChangeDetectorConfiguration                    : @{LearningPeriod=70.00:00:00; ExcludedSourceAccountIds=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    AbnormalSmbDetectorConfiguration                                               : @{OperationRetentionPeriod=00:03:00; RemoveOldOperationsConfiguration=;
                                                                                     ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    AbnormalVpnDetectorConfiguration                                               : @{ProfileCommonGeolocationsAndCarriesAsyncConfiguration=; BlockConfiguration=;
                                                                                     IsEnabled=True; UpsertProfileConfiguration=}
    AccountEnumerationDetectorConfiguration                                        : @{ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    ActivityProcessorConfiguration                                                 : @{ActivityBlockConfiguration=; ActivityPostponeBlockConfiguration=;
                                                                                     PostponedActivityBlockConfiguration=}
    ActivitySimulatorConfiguration                                                 : @{DatabaseServerEndpoint=; DelayInterval=00:00:15; SimulationState=Disabled}
    AppDomainManagerConfiguration                                                  : @{GcCollectConfiguration=; UpdateExceptionStatisticsConfiguration=}
    BruteForceDetectorConfiguration                                                : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    CenterTelemetryManagerConfiguration                                            : @{IsEnabled=True; ServiceUrl=https://dc.applicationinsights.microsoft.com/v2/track;
                                                                                     ClientInstrumentationKey=fd3f5bd1-3d71-44a3-9209-d94633544903; ClientBufferMaxSize=450;
                                                                                     ClientSendInterval=00:10:00; UnsentTelemetrySampleInterval=01:00:00;
                                                                                     UnsentTelemetryRetentionPeriod=7.00:00:00; SendSystemTelemetryConfiguration=;
                                                                                     SendPerformanceCounterTelemetryConfiguration=; SendAlertTelemetryConfiguration=;
                                                                                     SendExceptionStatisticsTelemetryConfiguration=; SendUnsentTelemetriesConfiguration=;
                                                                                     UnsentTelemetryBatchSize=20}
    CenterWebApplicationConfiguration                                              : @{ServiceListeningIpEndpoint=; CommunicationCookieExpiration=00:20:00}
    CenterWebClientConfiguration                                                   : @{RetryDelay=00:00:01; ServiceEndpoints=System.Object[];
                                                                                     ServiceCertificateThumbprints=System.Object[]}
    ComputerPreauthenticationFailedDetectorConfiguration                           : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    ConfigurationManagerConfiguration                                              : @{UpdateConfigurationConfiguration=}
    DatabaseConfiguration                                                          : @{ServerEndpoint=; ClientConnectTimeout=00:00:30; ClientServerSelectionTimeout=00:00:30;
                                                                                     ConnectionPoolMaxSize=100; WaitQueueSize=1000; ActivityBlockConfiguration=;
                                                                                     BackupSystemProfileMaxCount=10; CappedActivityCollectionHighActivityMaxCount=50000000;
                                                                                     CappedActivityCollectionLowActivityMaxCount=1000000;
                                                                                     CappedActivityCollectionUpdateCurrentCollectionActivityCountConfiguration=;
                                                                                     DataDriveFreeSpaceCriticalPercentage=0.05; DataDriveFreeSpaceCriticalSize=50 GB;
                                                                                     DataDriveFreeSpaceLowPercentage=0.2; DataDriveFreeSpaceLowSize=200 GB;
                                                                                     WorkingSetPercentage=0.25; LogFileMaxSize=50 MB; LogFileMaxCount=10;
                                                                                     BackupSystemProfileConfiguration=; DeleteOldCappedCollectionsConfiguration=;
                                                                                     MonitorDatabaseConfiguration=}
    DetectionConfiguration                                                         : @{AlertConfiguration=; NotificationVerbosity=Low}
    DirectoryServicesReplicationDetectorConfiguration                              : @{OperationRetentionPeriod=00:03:00; RemoveOldOperationsConfiguration=;
                                                                                     ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    DnsReconnaissanceDetectorConfiguration                                         : @{ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    EncryptedTimestampEncryptionDowngradeDetectorConfiguration                     : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    EntityProfilerConfiguration                                                    : @{UpdateDetectionProfileConfiguration=;
                                                                                     UpdateDirectoryServicesTrafficSystemProfileConfiguration=;
                                                                                     EventActivityBlockConfiguration=; NetworkActivityBlockConfiguration=}
    EntityReceiverConfiguration                                                    : @{ActivitiesDroppingEnabled=False; EntityBatchBlockConfiguration=;
                                                                                     EntityBatchBlockSizeAccumulationQueueConfiguration=; GatewayInactivityTimeout=00:15:00}
    EnumerateSessionsDetectorConfiguration                                         : @{OperationRetentionPeriod=00:03:00; RemoveOldOperationsConfiguration=;
                                                                                     ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    ExternalIpAddressResolverConfiguration                                         : @{CacheConfiguration=; FailedResolutionsAccumulationQueueConfiguration=}
    ForgedPacDetectorConfiguration                                                 : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    GoldenTicketDetectorConfiguration                                              : @{KerberosTicketLifetime=10:00:00; ExcludedSourceAccountIds=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    HoneytokenActivityDetectorConfiguration                                        : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    HttpClientConfiguration                                                        : @{BufferMaxSize=128 MB; Timeout=00:10:00}
    IntelligenceProxyConfiguration                                                 : @{ConnectionLimit=50; WebClientConfiguration=}
    LdapBruteForceDetectorConfiguration                                            : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    LdapCleartextPasswordDetectorConfiguration                                     : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    LoadSimulatorRecorderConfiguration                                             : @{IsEnabled=False; UniqueEntityBatchBlockConfiguration=; EntityBatchBlockConfiguration=;
                                                                                     FileSegmentSize=5 MB}
    LocalizerConfiguration                                                         : @{LocaleId=en-us}
    MailClientConfiguration                                                        : @{IsEnabled=False; From=; ServerEndpoint=; ServerSslEnabled=False;
                                                                                     ServerSslAcceptAnyServerCertificate=False; AuthenticationEnabled=False;
                                                                                     AuthenticationAccountName=; AuthenticationAccountPasswordEncrypted=}
    MassiveObjectDeletionDetectorConfiguration                                     : @{DetectMassiveObjectDeletionConfiguration=; BlockConfiguration=; IsEnabled=True;
                                                                                     UpsertProfileConfiguration=}
    MemoryStreamPoolConfiguration                                                  : @{BlockSize=128 KB; LargeBlockMultipleSize=1 MB; BufferMaxSize=128 MB}
    MonitoringClientConfiguration                                                  : @{AlertConfiguration=; MonitoringAlertTypeNameToIsEnabledMapping=;
                                                                                     RenotificationInterval=7.00:00:00}
    MonitoringEngineConfiguration                                                  : @{CenterNotReceivingTrafficTimeout=01:00:00; GatewayInactivityTimeout=00:05:00;
                                                                                     GatewayStartFailureTimeout=00:30:00; MonitoringAlertExpiration=30.00:00:00;
                                                                                     DeleteOldMonitoringAlertsConfiguration=; MonitoringCycleConfiguration=}
    NetworkActivityProcessorConfiguration                                          : @{ParentKerberosResponseTicketHashKeyToParentKerberosDataMappingConfiguration=;
                                                                                     SaveParentKerberosBloomFiltersConfiguration=}
    NotificationEngineConfiguration                                                : @{NotificationCycleConfiguration=}
    PassTheHashDetectorConfiguration                                               : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    PassTheTicketDetectorConfiguration                                             : @{HandleInvisibleSuspiciousActivitiesConfiguration=;
                                                                                     ValidateInvisibleSuspiciousActivitiesTimeout=02:00:00;
                                                                                     ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    RemoteExecutionDetectorConfiguration                                           : @{OperationRetentionPeriod=00:03:00; RemoveOldOperationsConfiguration=;
                                                                                     ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    ReporterConfiguration                                                          : @{ReportTypeToConfigurationMapping=; SendPeriodicReportsConfiguration=}
    RetrieveDataProtectionBackupKeyDetectorConfiguration                           : @{OperationRetentionPeriod=00:03:00; RemoveOldOperationsConfiguration=;
                                                                                     ExcludedSourceComputerIds=System.Object[]; ExcludedSubnets=System.Object[];
                                                                                     BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    SamrReconnaissanceDetectorConfiguration                                        : @{HandleInvisibleSuspiciousActivitiesConfiguration=; OperationRetentionPeriod=00:03:00;
                                                                                     RemoveOldOperationsConfiguration=; ExcludedSourceComputerIds=System.Object[];
                                                                                     ExcludedSubnets=System.Object[]; BlockConfiguration=; IsEnabled=True;
                                                                                     UpsertProfileConfiguration=}
    SecretManagerConfiguration                                                     : @{CertificateThumbprint=217562C96ECAF3A574303629848640F556A253FB}
    ServiceSystemProfileConfiguration                                              : @{Id=58f53fded8c26706b8ebb122}
    SoftwareUpdaterConfiguration                                                   : @{IsEnabled=True; IsGatewayAutomaticSoftwareUpdateEnabled=True;
                                                                                     IsLightweightGatewayAutomaticRestartEnabled=False;
                                                                                     MicrosoftUpdateCategoryId=6ac905a5-286b-43eb-97e2-e23b3848c87d;
                                                                                     CheckSoftwareUpdatesConfiguration=}
    SourceAccountSupportedEncryptionTypesEncryptionDowngradeDetectorConfiguration  : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    SourceComputerSupportedEncryptionTypesEncryptionDowngradeDetectorConfiguration : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    SyncManagerConfiguration                                                       : @{UpdateClientsConfiguration=}
    SyslogClientConfiguration                                                      : @{IsEnabled=False; ServerEndpoint=; ServerTransport=Udp;
                                                                                     ServerTransportTimeout=00:00:10; Serializer=Rfc5424}
    TgtEncryptionDowngradeDetectorConfiguration                                    : @{BlockConfiguration=; IsEnabled=True; UpsertProfileConfiguration=}
    UniqueEntityCacheConfiguration                                                 : @{CacheConfiguration=}
    UniqueEntityProcessorConfiguration                                             : @{HoneytokenAccountIds=System.Object[]; UniqueEntityBlockParallelismDegree=100;
                                                                                     UpdateSecurityPrincipalsSensitivityConfiguration=;
                                                                                     GetHighFunctionalityDomainControlerIdsConfiguration=;
                                                                                     GetHoneytokenAccountIdsConfiguration=}
    UniqueEntityProfileCacheConfiguration                                          : @{CacheConfiguration=; UniqueEntityProfileBlockConfiguration=;
                                                                                     StoreUniqueEntityProfilesConfiguration=}
    UserAccountClusterDetectorConfiguration                                        : @{ClusterUserAccountsConfiguration=}
    WindowsEventLogClientConfiguration                                             : @{IsEnabled=True}

    The above command retrieves the current configuration for the ATA Center.

.EXAMPLE
    Get-ATAStatus -Gateway | Select ServiceStatus, Status, Version, NetBiosName | fl

    ServiceStatus : Stopped
    Status        : StartFailure
    Version       : 1.8.6229.4854
    NetbiosName   : 2012R2-DC1

    The above example retrieves a list of information for all gateways and displays the ServiceStatus, Status, Version, and NetBiosName of the server.
#>
function Get-ATAStatus {
    [CmdletBinding()]
    Param
    (
        # Retrieves ATA Center status information.
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Center')]
        [switch]$Center,
        # Retrieves ATA Gateway status information.
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Gateway')]
        [switch]$Gateway,
        # Retrieves information around the current ATA License.
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'License')]
        [switch]$License
    )
    if (!$Global:ATACenter) {$Script:ATACenter = 'localhost'}
    try {
        if ($Center) {$foo = "center"}
        if ($Gateway) {$foo = "gateways"}
        if ($License) {$foo = "license"}

        $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/systemProfiles/$foo" -Method Get -UseDefaultCredentials
        $result
    }
    catch{
        if ($_.Exception.Message -match 'SSL/TLS secure channel'){
            Write-Error "Could not establish trust relationship for the SSL/TLS secure channel. Please run Resolve-ATASelfSignedCert and try again." -ErrorAction Stop
        }
        if ($_.Exception.Message -match 'unable to connect'){
            Write-Error "Unable to connect to remote server. Your ATACenter url is set to $ATACenter. Run Set-ATACenterURL '<url>' if this is incorrect." -ErrorAction Stop
        }
        else {
            Write-Error $_ -ErrorAction Stop
        }
    }
}

<#
.Synopsis
    Get-ATAMonitoringAlert retrieves all health alerts in ATA.
.DESCRIPTION
    This cmdlet is used to retrieve a list of all health alerts in ATA. Filtering of these alerts can be done post-query.
.EXAMPLE
    Get-ATAMonitoringAlert -Status Open | select Id, TitleKey, Severity, Status, StartTime

    Id        : 59046d2bb5487a052cd5381e
    TitleKey  : GatewayDirectoryServicesClientAccountPasswordExpiryMonitoringAlertTitleNearExpiry
    Severity  : Medium
    Status    : Open
    StartTime : 2017-04-29T10:38:35.9741496Z

    Id        : 5911f086b5487a052c205f69
    TitleKey  : GatewayStartFailureMonitoringAlertTitle
    Severity  : Medium
    Status    : Open
    StartTime : 2017-05-09T16:38:30.5274492Z

    The above example retrieves a list of Open monitoring alerts and displays the Id, TitleKey, Severity, Status, and StartTime for the alerts.
#>
function Get-ATAMonitoringAlert {
    [CmdletBinding()]
    Param
    (
        # Status to update the monitoring alert. (Open, Closed, Suppressed)
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'Fetch')]
        [ValidateSet('Open', 'Closed', 'Suppressed')]
        [string]$Status
    )
    Begin{
        if (!$ATACenter) {$ATACenter = 'localhost'}
    }
    Process {
        try{
            $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/monitoringAlerts" -Method Get -UseDefaultCredentials
        }
        catch{
            if ($_.Exception.Message -match 'SSL/TLS secure channel'){
                Write-Error "Could not establish trust relationship for the SSL/TLS secure channel. Please run Resolve-ATASelfSignedCert and try again." -ErrorAction Stop
            }
            if ($_.Exception.Message -match 'unable to connect'){
                Write-Error "Unable to connect to remote server. Your ATACenter url is set to $ATACenter. Run Set-ATACenterURL '<url>' if this is incorrect." -ErrorAction Stop
            }
            else {
                Write-Error $_ -ErrorAction Stop
            }
        }
    }
    end {
        if ($Status) {
            $result | Where-Object {$_.status -eq $Status}
        }

        if (!$Status) {
            $result
        }
    }
}

<#
.Synopsis
    Get-ATAUniqueEntity is used to retrieve information around unique entities in ATA.
.DESCRIPTION
    This cmdlet retrieves detialed information around users and computers. The 'Profile' flag can be used to see more detailed information built by ATA.
.EXAMPLE
    Get-ATAUniqueEntity -Id ff336d33-81f4-458c-b70b-33f0070ffb20

    DnsName                    : 2012R2-DC1.contoso.com
    DomainController           : @{IsGlobalCatalog=True; IsPrimary=True; IsReadOnly=False}
    IpAddress                  :
    IsDomainController         : True
    IsServer                   : True
    OperatingSystemDisplayName : Windows Server 2012 R2 Datacenter, 6.3 (9600)
    SystemDisplayName          : 2012R2-DC1
    BadPasswordTime            :
    ConstrainedDelegationSpns  : {}
    ExpiryTime                 :
    IsDisabled                 : False
    IsExpired                  : False
    IsHoneytoken               : False
    IsLocked                   : False
    IsPasswordExpired          : False
    IsPasswordFarExpiry        : False
    IsPasswordNeverExpires     : False
    IsPasswordNotRequired      : False
    IsSmartcardRequired        : False
    PasswordExpiryTime         :
    PasswordUpdateTime         : 2017-04-17T17:59:57.0826645Z
    Spns                       : {Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/2012R2-DC1.contoso.com, ldap/2012R2-DC1.contoso.com/ForestDnsZones.contoso.com,
                                 ldap/2012R2-DC1.contoso.com/DomainDnsZones.contoso.com, TERMSRV/2012R2-DC1...}
    UpnName                    :
    Description                :
    IsSensitive                : True
    SamName                    : 2012R2-DC1$
    DomainId                   : 7c915dca-0591-4abe-84c6-2522466bed4d
    CanonicalName              : contoso.com/Domain Controllers/2012R2-DC1
    CreationTime               : 2017-04-17T17:59:40Z
    DistinguishedName          : CN=2012R2-DC1,OU=Domain Controllers,DC=contoso,DC=com
    IsDeleted                  : False
    IsNew                      : False
    Sid                        : S-1-5-21-3599243929-1086515894-1402892407-1001
    SystemSubDisplayName       :
    Id                         : ff336d33-81f4-458c-b70b-33f0070ffb20
    IsPartial                  : False
    Type                       : Computer

    The above example retrieves information about the specified unique entity.

.EXAMPLE
    Get-ATAUniqueEntity -Id ff336d33-81f4-458c-b70b-33f0070ffb20 -ParentGroupId | foreach {Get-ATAUniqueEntity -Id $_}

    GroupType            : {Global, Security}
    SystemDisplayName    : Domain Controllers
    SystemSubDisplayName : All domain controllers in the domain
    Description          : All domain controllers in the domain
    IsSensitive          : True
    SamName              : Domain Controllers
    DomainId             : 7c915dca-0591-4abe-84c6-2522466bed4d
    CanonicalName        : contoso.com/Users/Domain Controllers
    CreationTime         : 2017-04-17T17:59:41Z
    DistinguishedName    : CN=Domain Controllers,CN=Users,DC=contoso,DC=com
    IsDeleted            : False
    IsNew                : False
    Sid                  : S-1-5-21-3599243929-1086515894-1402892407-516
    Id                   : 9c7c6002-d192-48e8-99c2-1205cbd5f2c9
    IsPartial            : False
    Type                 : Group

    The above example extracts the parentgroupid from the unique entity and passes it back into Get-ATAUniqueEntity to see the group's information.

.EXAMPLE
    Get-ATASuspiciousActivity | select SourceComputerId | Get-ATAUniqueEntity

    The above example pipes the SourceComputerId property directly into Get-ATAUniqueEntity to retrieve the entity information for the source computer.
#>
function Get-ATAUniqueEntity {
    [CmdletBinding()]
    Param
    (
        # Unique Id of Unique Entity
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0,
            ParameterSetName = 'Fetch')]
        [Alias('SourceComputerId', 'ExclusionUniqueEntityId')]
        [string]$Id,

        # Retrieves the profile for the unique entity.
        [Parameter(Mandatory = $false,
            ParameterSetName = 'Fetch')]
        [switch]$Profile,

        # Retrieves the parent group Id for the unique entity.
        [Parameter(Mandatory = $false,
            ParameterSetName = 'Fetch')]
        [switch]$ParentGroupId

    )
    begin {
        if (!$Global:ATACenter) {$Script:ATACenter = 'localhost'}
        if ($Profile -and $ParentGroupId) { Write-Error "You may not set both Profile and ParentGroupId."}
    }
    Process {
        try{
            if ($Id -and !$Profile -and !$ParentGroupId) {
                $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/uniqueEntities/$Id" -Method Get -UseDefaultCredentials

                $result
            }
            if ($Id -and $Profile) {
                $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/uniqueEntities/$Id/profile" -Method Get -UseDefaultCredentials

                $result
            }
            if ($Id -and $ParentGroupId) {
                $result = Invoke-RestMethod -Uri "https://$ATACenter/api/management/uniqueEntities/$Id/parentGroupIds" -Method Get -UseDefaultCredentials

                $result
            }
            if (!$Id -and $Profile) {
                Write-Error "You must specify a unique entity ID when using the 'Profile' switch."
            }
        }
        catch{
            if ($_.Exception.Message -match 'SSL/TLS secure channel'){
                Write-Error "Could not establish trust relationship for the SSL/TLS secure channel. Please run Resolve-ATASelfSignedCert and try again." -ErrorAction Stop
            }
            if ($_.Exception.Message -match 'unable to connect'){
                Write-Error "Unable to connect to remote server. Your ATACenter url is set to $ATACenter. Run Set-ATACenterURL '<url>' if this is incorrect." -ErrorAction Stop
            }
            else {
                Write-Error $_ -ErrorAction Stop
            }
        }
    }
    end {
    }
}

# SIG # Begin signature block
# MIIkAQYJKoZIhvcNAQcCoIIj8jCCI+4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBBIgerxYUnKUpe
# xirNnImhyt0q1syEeqJsbBeSAOJ8WKCCDY8wggYNMIID9aADAgECAhMzAAAAqCr3
# qQEuG5yRAAAAAACoMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTcwNTA0MTgxODU2WhcNMTgwODAyMTgxODU2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDJ1ZCOb18/3WhwblYqaW5h66pkaKnksWQXgPSyuBn9EVQxQaJP0upExDVwogET
# JEaVvRXC+fLxdZ1dbL432s9s18PuWXkI26DFOSQ+/FWVEN3g1M89qiWg5zcCpSQZ
# i5gtLPlWB3vT1voR7uP+Jy+5EQuq263n3iwRfH8z07QfMFC2MtNk0oHUUgC7lFjQ
# kSNDAu/QVzOXQAU7zrAy7uBP6aJhpI2EOfmCfPc9AKCaSS9aXNTU6MnIXgi0sZjt
# OeXZfz4EeNOMWKmZL1FUs6Xs6LJkWz/HFGkKRxAY8WvIA82ePCxTJtr5G9x5cA2t
# pMX+WzpnL9kzKC9fMDD9Q5ybAgMBAAGjggGMMIIBiDArBgNVHSUEJDAiBgorBgEE
# AYI3TAgBBggrBgEFBQcDAwYKKwYBBAGCN0wbATAdBgNVHQ4EFgQUP4nKqgd1uegU
# Glba44CWZfbI0IEwUgYDVR0RBEswSaRHMEUxDTALBgNVBAsTBE1PUFIxNDAyBgNV
# BAUTKzIzMzg5Mys1ZmE4ZGIyMy1hODJmLTRkOWMtOWIyMy01NmE3YzA5NGNiNmYw
# HwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJoEeg
# RYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29kU2ln
# UENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYBBQUH
# MAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljQ29k
# U2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3
# DQEBCwUAA4ICAQAqfBbEfoXHQT1/QzjVfMaa5IMR5cG4uyw8R8Buh9zrWlpaPKpE
# eYiFox9FEU4oD2OpV0/b/rIv1jVgEtIhjLpZElWVfYqE3zGW/zOI9YEmHqQGISGf
# MLMbOdjHOZ3FQ5zC4gsxvs9pDv9GJOub1avwOLXBIfrAnweahzrd2emsIRGAWZBL
# sGLLDo1Tl484EFbJNSNK5q84xis0Dcnd2jFNo/5Hk8aEhhjJhuofsMmZbmOJ9s6V
# qXB96fbMskO90M6nP7GI1X1lZ/Sjx+VP2ov8sQzC6XBIF1WVNdI2c9JlX76/wGj8
# RtRUzQkfhHMCFleYp3bd7c81UXQVoB0Of9bShGmzzC9VbZO4jkiNr/x0r4i5jBiI
# cAlADHrQcUcB56pg9L17hRhdQiCmknppA3sRSpY+H3s2XE7KOYDeMm8v72osGwuh
# chDu2dQNi0KBKqgidFtHvOfqQaN0zC78gHITMxpVT5W0xebqdA2SxRl1EbEdmoH2
# JCG945VVjt0yayiAqEtmB2REAm/iwnN0AJ5a07sg6EU39qA/V8W3yZ3Umekb2Txh
# va5NReyQOv09j4X9coAzw4ILL7TmoDL4DowThtccOElFB6ouTvthgahpxJ2gmzLs
# m61NfFBfyPJvSD2/6Fu64/ckHCq5qV2U5V9XLvieRT90LtoQk5wYcIH8KDCCB3ow
# ggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkwOVoX
# DTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMTCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBNNLry
# tlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJDXlk
# h36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv56sI
# UM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN1Vx5
# pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+sYxd
# 6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzluZH9T
# upwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKuHCOn
# qWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8rAKC
# X9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43sTUkw
# p6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/dygo
# 8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCIF96e
# TvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIBADAd
# BgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAweCgBT
# AHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0
# MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUHMAKG
# Qmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0
# MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3LgMw
# gYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# ZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwA
# XwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0B
# AQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw++MNy
# 0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS0LD9
# a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELukqQUM
# m+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q3fMO
# r5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgycSca
# f7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8VfUWn
# duVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbRBrF1
# HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/QACnF
# sZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL/9az
# I2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9BCrE/
# +6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghXIMIIV
# xAIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgw
# JgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAAqCr3
# qQEuG5yRAAAAAACoMA0GCWCGSAFlAwQCAQUAoIG2MBkGCSqGSIb3DQEJAzEMBgor
# BgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3
# DQEJBDEiBCDgMOvnrWzU7nrI4mgbeEvQfX8AU8wwM5E8YYlTzOfqZjBKBgorBgEE
# AYI3AgEMMTwwOqAcgBoATQBpAGMAcgBvAHMAbwBmAHQAIABBAFQAQaEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAKGveRpHOoA69
# EMkmvXnbL14MtGYn7mIQR0ZtVOb/eHWntU+Ip9VKr8syD2KyasmB8Tp+/mpmZoxi
# DRAD6ca+WVI6dYOdC98yw38E04llnI85SujMKGxD1ULgb2b8WiqWV0nuv2X9q4pY
# Wq8EunN3Barfm/Fhp3S+s7uxjjguntLurTnYxAFjzQvjiXt8w9VRN2WmyKiImeU5
# hUztYhOFz3QbPu4wvK7LsqY1JNyMaBJHyib/luSuCC/L2PeBlnpE7GnlioeFljPJ
# GtaDiImsMp6E2gJBfLjuZAAMdW/UWDdP67eiri2/fEtYq3+DUFjx170Qrax5Ktbb
# 63LX/pBVfKGCE0owghNGBgorBgEEAYI3AwMBMYITNjCCEzIGCSqGSIb3DQEHAqCC
# EyMwghMfAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggE9BgsqhkiG9w0BCRABBKCCASwE
# ggEoMIIBJAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCA+ga5TAlPC
# N/aA6nlepoIVe2CFzz5Wr+atUSgCUEKb2QIGWXoh/4U8GBMyMDE3MDgwMjE5NDky
# Mi4wOTlaMAcCAQGAAgH0oIG5pIG2MIGzMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMQ0wCwYDVQQLEwRNT1BSMScwJQYDVQQLEx5uQ2lwaGVyIERT
# RSBFU046OThGRC1DNjFFLUU2NDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2Wggg7NMIIGcTCCBFmgAwIBAgIKYQmBKgAAAAAAAjANBgkqhkiG
# 9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEy
# MDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
# MTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2tz5mK1vw
# FVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAizQt2TrNZzMFcmgqNF
# DdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSmXdFhE24oxhr5hoC7
# 32H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5nf/VmwAOW
# RH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn9NxkvaQBwSAJ
# k3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsGAQQBgjcVAQQDAgEA
# MB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3FAIEDB4K
# AFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSME
# GDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRw
# Oi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJB
# dXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8y
# MDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEw
# PQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9D
# UFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABv
# AGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQAD
# ggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76V20ZMLPCxWbJat/1
# 5/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5Xhc1mCRW
# S3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1a+THzvbKegBvSzBE
# JCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplmkIz/amJ/
# 3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd/DjYlPTGpQqWhqS9
# nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGnEcua2A5H
# moDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd46PioSKv3
# 3nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1VmXqHczsI
# 5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN4Ib5KpqjEWYw07t0
# MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA/czmTfsNv11P6Z0e
# GTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSMIIE2jCCA8KgAwIB
# AgITMwAAAJ0gnFZ3VdQomgAAAAAAnTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0xNjA5MDcxNzU2NDFaFw0xODA5MDcxNzU2
# NDFaMIGzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQ0wCwYD
# VQQLEwRNT1BSMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046OThGRC1DNjFFLUU2
# NDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSRJicEVoqGi6qn1NdbV28tll2kcAm
# WwPmyGxfoyrrTABGdDgUvyp4XbAjTOxuYEjsSeRbdaZw/fPUrlVujr0EH2c9Gf0x
# coKUoXOxLrzwHNTb7yG4xqm0xsJGBy6ZzD4hC8MuSN8ManXFNY7XWZyrO0h+nrLg
# /FSW3hNHOULQbtZL/b8MpPAL5froyIiL7pz7deHES+jLDmTOV95gqHpKzmUcuGWW
# I2I7fwVPWWbd6Q3V+Hy+wEzeewqWG8xVOQRvBghBOLv1Gd+1egR3BRzi7IzH8bGa
# XkduzLIeo9qWeIHu8AeYgFG+ugoUHn6eOlkkoVdzDP5BRE6WwlRRD6nFAgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUvIYIyltqWsrkvczLgrQVSOqH5aEwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAf94kIb1Z77TWi3HKWZG+LqhGgruP32QdfeYqC7wo
# Z0v++Xe/tfROpP3oSg8+ZyKzVoltlwha7CMU9XkqE1eMkhedBiHq86jqGzvc24Sa
# S/dyFfafjyeo/6Xi1iCJlU1AqRVgXrmXAdcwC/9CamtW2exaXDYDgMwWLWrBuTNk
# T9tea3/Yb8CugaU47TrOXXIajEwVy1+TjLLdqgAt4/1kKKmpvhAd/hXcJ48fjqQD
# 6o432wQlUx/hMnr3OyKQzNwqDcFehgnVPlbvqyWgessyQFj2vQlbtsn/e0d5dIal
# hp3YIg1XXuGoDcYmTgL2/Tr2Aaz3l7y5kQ5h253T76Y2aaGCA3YwggJeAgEBMIHj
# oYG5pIG2MIGzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMQ0w
# CwYDVQQLEwRNT1BSMScwJQYDVQQLEx5uQ2lwaGVyIERTRSBFU046OThGRC1DNjFF
# LUU2NDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiJQoB
# ATAJBgUrDgMCGgUAAxUAGA2ss4xoMLP4dBmyeM6AKzUvCPqggcIwgb+kgbwwgbkx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1P
# UFIxJzAlBgNVBAsTHm5DaXBoZXIgTlRTIEVTTjo0REU5LTBDNUUtM0UwOTErMCkG
# A1UEAxMiTWljcm9zb2Z0IFRpbWUgU291cmNlIE1hc3RlciBDbG9jazANBgkqhkiG
# 9w0BAQUFAAIFAN0sgrswIhgPMjAxNzA4MDIxNjU2MjdaGA8yMDE3MDgwMzE2NTYy
# N1owdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA3SyCuwIBADAHAgEAAgIjGDAHAgEA
# AgIaNjAKAgUA3S3UOwIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMB
# oAowCAIBAAIDFuNgoQowCAIBAAIDB6EgMA0GCSqGSIb3DQEBBQUAA4IBAQAJ0l2b
# Swt1i7GL7HldAXTQwGBdd7iSNjPGmbdKttip/QOc00zamibhAD0d8MApXKL+2R8k
# 6BdvSA5ftnOR+TKk75P4YMDYJhsXEGQNOQJN5vsIw3rldlc1iAE2EC0U4nF/tsy2
# tqcJUAa5plSgmXuo7g1U+SZP4RwXWTs8o6ZxnWYp/kvtOrbrqrb7qhwtOE3KsbpZ
# R30pcZWrNDG9k9NyOTiZDN0eAK7DO2Uj4kW0Dr64/e7DdgGvnvCDLtZOAp6EY9Zs
# Mso9JaQoqT0PJysbWcKl2GGYHQGD2PmplTkhnFhJyDfme8z4lniRvTSmTqd0sNYj
# kyrjvqsz6Qk8i34UMYIC9TCCAvECAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTACEzMAAACdIJxWd1XUKJoAAAAAAJ0wDQYJYIZIAWUDBAIBBQCgggEy
# MBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgRGdL
# J40A4FEU3fRh35eJJzBJGyt81wab8Of3+2qfdwkwgeIGCyqGSIb3DQEJEAIMMYHS
# MIHPMIHMMIGxBBQYDayzjGgws/h0GbJ4zoArNS8I+jCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAAnSCcVndV1CiaAAAAAACdMBYEFDf0
# srG60LO684YEBJFDQk6zGSfJMA0GCSqGSIb3DQEBCwUABIIBAL3ab03XzC1PIuT6
# wMcDmxJUjDsVxVmjs/Z6IVtkyNMswd3Y1O276/1f4do0VLrZUvLEbjrxhpIWVy62
# eqLqrGQ64hlHSMfLXu/TUf8oWCGZiMBih3UynQQ1ZdZw33Kwpn24uFlkIXgaBG4s
# tURXeR2wuE2EgA5LJR+v//Z72FnpFuvUl7kNO71z5t30K7iJYFw1CBl6sFyYK0FE
# xjv4ek1QeQoegKUdLuLm7JHdLv604SDOI35CXw/SySrjM8clHXjTp6nLs71A/uwb
# eHvKEH+2UWmYBC8CbvjXYILOBwr4pyIxsZlnSGKL/xUE1LiofI7l05J5wgCX8oN8
# bCOoJLU=
# SIG # End signature block
