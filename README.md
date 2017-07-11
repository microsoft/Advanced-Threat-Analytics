# About This Module
Note! This module requires ATA 1.8.   
  
The Advanced-Threat-Analytics PowerShell module was designed to make it easy for customers to interface with the ATA Center through a simple set of cmdlets.  
While this module is signed by Microsoft, it should be made very clear that it is not a formal part of the ATA product and there is no warranty of any kind or guaranteed support.

# Installation
  
## ATA Center vs. Management Server
It is recommended to install the module either directly on the ATA Center or on a domain joined PC. The module uses the credentials of the signed in Windows user to authenticate to the ATA Center. This means that you will not be able to use the module with a user that cannot also log into the ATA Center.  
  
If you install the module on the ATA Center, you can either log into the ATA Center to execute commands or use 'Import-PSSession -Module Advanced-Threat-Analytics' to import the module into a temporary session on a management PC. By default the module is looking for the ATA Center via localhost, so if you choose to install the module on a domain-joined management PC, you will need to run Set-ATACenterURL and specify the ATA Center URL. (example: atacenter.contoso.com)  
  
## Windows Server 2016
   
### Internet Connectivity
Run PowerShell as an administrator and execute the below command:  
Install-Module Advanced-Threat-Analytics  
  
The module should install from the PowerShell gallery. If localhost resolves to your ATACenter, you should be all set to start using the cmdlets. If not, you will want to run Set-ATACenterURL and specify the URL for your ATA Center. This can be found in the configuration.  
  
### No Internet Connectivity  
Download the zip file from technet (URL coming) and place the contained Azure-Security-Center folder in any approved modules path.  
For more information on installing modules see: https://msdn.microsoft.com/en-us/library/dd878350(v=vs.85).aspx 
  
## Windows Server 2012R2
  
### Internet Connectivity
Install the Package Manager MSI to enable Module and Package cmdlets on the server: https://www.microsoft.com/en-us/download/details.aspx?id=51451 
  
Run PowerShell as an administrator and execute the below command:  
Install-Module Advanced-Threat-Analytics  
  
The module should install from the PowerShell gallery. If localhost resolves to your ATACenter, you should be all set to start using the cmdlets. If not, you will want to run Set-ATACenterURL and specify the URL for your ATA Center. This can be found in the configuration.  
  
### No Internet Connectivity
Download the zip file from technet (URL coming) and place the contained Azure-Security-Center folder in any approved modules path.  
For more information on installing modules see: https://msdn.microsoft.com/en-us/library/dd878350(v=vs.85).aspx 
    
# First steps  
  
## Set your ATA Center URL
Step #1 after installing the module will be to set your ATA Center URL. This is simply a global variable $ATACenter that should reflect the URL you set in the ATA Center configuration page. (example: atacenter.mydomain.com or 10.2.3.5) Do not use "https://". To assist with setting the variable, I added a simple function that sets it for you called Set-ATACenterURL.  
  
## Self Signed Certificates
If you are using a self-signed certificate in your ATA Center, there is a good chance you will see an error when using the module that says something about inability to create a secure SSL/TLS channel. If you get this error, please run the Resolve-ATASelfSignedCert cmdlet and try again.

## Looking at the list of cmdlets  
Get-Command -Module Advanced-Threat-Analytics  
  
This command will show you the available functions in the module.  
  
# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
