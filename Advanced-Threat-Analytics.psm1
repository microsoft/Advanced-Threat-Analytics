
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
        [ValidatePattern('[a-z0-9].[a-z0-9].[a-z0-9]')]
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
