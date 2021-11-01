############################################################################################################################################################################
# The purpose of this script is to carry out automatically RDS Session Standard Deployment 
#
# 11/04/2017  Version 1.3 --> Improvements on Error handling and fine tunning.
# 03/23/2018  Version 1.4 --> Proxy section configured to consider OPCSVC, UKGOV and USGOV. All the Entities in general.
#                         --> Added the functionality to the script where it can be re-executed without doing anything in the Server Manager. For intance IF the targeted 
#                             servers are already part of the All Server pool in Server Manager then continue smoothly.
#                         --> Replaced New-SessionDeployment to New-RDSessionDeployment since the current PS version should support *RD* name only
#
# Author : Victor Jimenez 
#
############################################################################################################################################################################


############################################################################################################################################################################
# Part # 1
# Is required to add the RDS Session Host servers to the Local Servers of the RDS Connection Broker server in the Server Manager Dashboard  before start the deployment.
############################################################################################################################################################################
 

Set-executionpolicy -ExecutionPolicy Bypass -Force
start-process –filepath C:\Windows\System32\ServerManager.exe –WindowStyle Minimized
start-sleep 10

cd C:\cs_pkgs
Import-Module C:\cs_pkgs\loginfos.psm1 -ErrorAction SilentlyContinue
open-log

$AppendLog = getLogFilePath
#$LogsFile = "\\$SourceServer\C$\cs_pkgs"+$AppendLog.Substring(2)
$LogsFile = "\\$SourceServer\C$"+$AppendLog.Substring(2)
 
$ThisServer = $env:computername

$BrokerServer = Get-ADComputer $ThisServer

$BrokerServer.DNSHostName

    ############################################################################################################################################################################
    # Collect RDS Connection Broker server's name and RDS Session Hosts. Validation part at the time to input.
    ############################################################################################################################################################################
[string]$Server3 = Read-host "Input RDS Connection Broker FQDN (This one will RDS Licesing too)"
                        while ($Server3 -ne $BrokerServer.DNSHostName){
                            Write-log "RDS Connection Broker needs to be this one you are logged in" -Type ERROR
                            [string]$Server3 = Read-host "Input RDS Connection Broker FQDN again"
                        }
                   
#[string]$Server1 = Read-host "Input 1st RDS Session Host FQDN"     ### Inpur RDS Sssion host # 1
                        Do{
                            [string]$Server1 = Read-host "Input 1st RDS Session Host FQDN"
                            Write-log "Testing connectivity" -Type INFO
                            $PingOK1 = Test-Connection $Server1 -Quiet
                                        If ($PingOK1 -eq $false){
                                            Write-log "Name is not rechable make sure it is OK" -Type ERROR
                                            Clear-Variable -name Server1
                                        }
                            
                        } While (!($PingOK1 -eq $true))
                        #Clear-Variable -name PingOK1   -> Testing Purposes

#[string]$Server2 = Read-host "Input 2nd RDS Session Host FQDN"     ### Inpur RDS Session host # 2
                        Do{
                            [string]$Server2 = Read-host "Input 2nd RDS Session Host FQDN"
                            Write-log "Testing connectivity" -Type INFO
                            $PingOK2 = Test-Connection $Server2 -Quiet
                                        If ($PingOK2 -eq $false){
                                            Write-log "Name is not rechable make sure it is OK" -Type ERROR
                                            Clear-Variable -name Server2
                                        }
                            
                        } While (!($PingOK2 -eq $true))
                        #Clear-Variable -name PingOK2   -> Testing Purposes






Write-log "Names Typed: `r`n RDS Connection Broker -  $Server3 `r`n 1st RDS Session Host -  $Server1 `r`n 2nd RDS Session Host - $Server2 `r`n" -Type INFO
write-host "##########################################################################################################################"

# At this point the excution needs to be set to Unrestricted: set-executionpolicy -ExecutionPolicy Unrestricted -Force


                                                      
                           get-process ServerManager | stop-process –force
                          <#  $SMStatus = Get-WmiObject win32_process -Filter "name='ServerManager.exe'" -ErrorAction SilentlyContinue
                        If ($SMStatus -eq $null)
                            {
                                Write-log "Server Manager Service is now Stop" -Type INFO
                                
                            }
                        Else
                            {
                                write-log "Server Manager Service stills started ... Closing" -Type INFO
                                get-process ServerManager | stop-process -ErrorAction SilentlyContinue
                                #Write-log "Cancel script to review connectivity to the remote server: Ctrl + Break" -Type INFO
                                start-sleep 10
                            }
                       #>
                            #Set path of existing ServerList.xml file
                            $file = get-item “$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\ServerManager\ServerList.xml”
                        
                            #Backup ServerList.xml
                            $date = Get-Date -Displayhint Date -Format o
                            $DateName = $date.Substring(0,10)
                            $BKFile = "$file-BK$DateName"
                            copy-item –path $file –destination $BKFile –force
                            Write-log "Backup File is $file-BK$DateName" -Type INFO
                            
                            # Get content from ServerList.xml file in XML format
                            $xml = [xml] (get-content $file)
                            write-log "Adding $Server1, and $Server2" -Type INFO

                            #  Clone an existing managed server element to a new XML element
                            $newserver = @($xml.ServerList.ServerInfo)[0].clone()
                            
                            #Update the new cloned element with new servers information
                            $newserver.name = "$Server1"
                            $newserver.lastUpdateTime = “0001-01-01T00:00:00”    
                            $newserver.status = “2”
                                        
                            #Append the new cloned element inside the ServerList node
                            $xml.ServerList.AppendChild($newserver)

                            #Save the updated XML elements to ServerList.xml
                            $xml.Save($file.FullName)

                            #  Clone an existing managed server element to a new XML element
                            $newserver = @($xml.ServerList.ServerInfo)[0].clone()

                            #Add the second server:
                            $newserver.name = "$Server2"
                            $newserver.lastUpdateTime = “0001-01-01T00:01:00”    
                            $newserver.status = “2”
                            
                            #Append again the new cloned element inside the ServerList node
                            $xml.ServerList.AppendChild($newserver)
 
                            #Save the updated XML elements to ServerList.xml
                            $xml.Save($file.FullName)

                            Start-Sleep 20

                            # Comparation to know if the servers were input properly to the Server manager list
                            $ServerUno = @($xml.ServerList.ServerInfo)[1].name                            
                            $ServerDos = @($xml.ServerList.ServerInfo)[2].name

                            If  ($ServerUno -match $Server1)
                                { Write-log "RDS Session Host Server was successfully added $Server1" -Type INFO}
                            Elseif($Server1 -eq $null){
                                 Write-log "First server is empty, can't continue Script will be canceled in 60 seconds automatically or hit Ctrl + C to quit" -Type INFO
                                  Start-Sleep 60
                                  Exit
                            }
                            Else
                                { Write-log "RDS Session Host Server was NOT successfully added $Server1" -Type ERROR
                                  write-log "Verify the full connectivity is working from $Server3 to $Server1 Script will be canceled in 60 seconds automatically or hit Ctrl + C to quit" -Type INFO
                                  Start-Sleep 60
                                  Exit
                                }

                             If  ($ServerDos -match $Server2)
                                { Write-log "RDS Session Host Server was successfully added $Server2" -Type INFO}
                             Elseif($Server2 -eq $null){
                                 Write-log "Second server is empty, can't continue Script will be canceled in 60 seconds automatically or hit Ctrl + C to quit" -Type INFO
                                  Start-Sleep 60
                                  Exit
                            }
                            Else
                                { Write-log "RDS Session Host Server was NOT successfully added $Server2" -Type ERROR
                                  write-log "Verify the full connectivity is working from $Server3 to $Server2 Script will be canceled in 60 seconds automatically or hit Ctrl + C to quit" -Type INFO
                                  Start-Sleep 60
                                  Exit
                                }
                            
                            #
                            
                            
                            #Re-launch Server Manager to see the results
                            start-process –filepath C:\Windows\System32\ServerManager.exe –WindowStyle Maximized                            

                            
Write-log "Part #1 is now completed" -Type INFO

Start-sleep 10






############################################################################################################################################################################
# Part # 2
# Standard RDS deployment with no RDS Web server. 
# Details on: https://blogs.technet.microsoft.com/askperf/2015/04/07/remote-desktop-services-rds-2012-session-deployment-scenarios-standard-deployment/
############################################################################################################################################################################

Write-log "########################################################################################################################################"
Write-log "Starting part # 2 `r `n Standard RDS deployment with no RDS Web server" -Type INFO

Write-log "Loading RemoteDesktop Module in the Windows 2012 where this script is running" -Type INFO
    Import-Module RemoteDesktop
    $ModStatus = Get-module -Listavailable| where Name -eq RemoteDesktop
    If ($ModStatus -ne $null)
                            {
                                
                                write-log "$ModStatus Module is OK, ready to continue" -Type INFO
                            }
                        Else
                            {
                                Write-log "The RDS Module is not present in the RDS Connection Broker server $Server3 Make sure the RDS Role is installed. Cancelling"   -Type ERROR                             
                                start-sleep 120
                                [Environment]::Exit(1)
                            }

#Starting a new RDS deployment process installing the RDS Connection Broker in the CSMG server and the Session Host role in set in the first *SMTS* server
Write-log "Starting a new RDS deployment process installing the RDS Connection Broker in the CSMG server and the Session Host role in set in the first *SMTS* server" -Type INFO

#New-RDSessionDeployment –ConnectionBroker $Server3 –Sessionhost $Server1
New-RDSessionDeployment -ConnectionBroker $Server3 -SessionHost $Server1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
Write-log "New RDS Deployments is in progress, check loginfos file for details" -Type INFO
    Start-sleep 20   # Check how to log this command

#Then the RDS Session Host #1 will be rebooted automatically
$Path1 = "\\$Server1\C$\Windows"
    If ($Status = Test-Path -path $Path1)
    {
        Write-log "The RDS Session Host  $Server1 is now back" -Type INFO
        Start-Sleep 10      
    }
    Else
    {
        do {
        Write-log "$Server1 Reboot in progress" -Type WARNING
        $Status = Test-Path -path $Path1
        Start-Sleep 10
        } While ($Status -ne 'False')      
    }

Write-log "$server1 is OK, ready to continue" -Type INFO

    clear-variable -name Status



#Add the 2nd “RDS Session Host” server to the current deployment. Where is the “RDSConnection Broker”
Write-log "Adding the 2nd RDS Session Host server to the current deployment $Server2" -Type INFO

#Add-RDServer -Server $Server2 -Role RDS-RD-SERVER -ConnectionBroker $Server3 -ErrorAction SilentlyContinue
Add-RDServer -Server $Server2 -Role RDS-RD-SERVER -ConnectionBroker $Server3
write-log "Hit Enter to continue" -type INFO
pause

Write-log "Added $Server2 to the RDS-RD-SERVER -ConnectionBroker $Server3 `r `n"  -Type INFO

#Then the RDS Session Host #2 will be rebooted automatically

$Path2 = "\\$Server2\C$\Windows"
    If ($Status = Test-Path -path $Path2)
    {
        Write-log "The RDS Session Host  $Server2 is now back" -Type INFO
        Start-Sleep 10      
    }
    Else
    {
        do {
        Write-log "$Server2 Reboot in progress" -Type WARNING
        $Status = Test-Path -path $Path1
        Start-Sleep 10
        } While ($Status -ne 'False')      
    }
    clear-variable -name Status

#Once the servers get back online verify the roles on each server | First display on screen and then saves to the logfile
Get-RDServer $Server3
$RDS_Status = Get-RDServer $Server3  -ErrorAction SilentlyContinue
$RDS_Status | Out-File -FilePath $AppendLog -Append -Encoding ASCII 
Write-log "Current RDS Deployment Status is  `r `n "  -Type INFO
$RDS_Status
Start-Sleep 10

            If ($RDS_Status -eq $null){
                Write-log "Since the current RDS deployments status is as below you need to review the Connection Broker server `r `n - Verify the Connectivity to the RDS Session Hosts  $RDS_Status"  -Type INFO
                Write-log "Script execution will be cancelled"  -Type INFO
                Start-sleep 60
                Exit
                }

Clear-variable -name RDS_Status
Start-Sleep 10



# Install the “RDS Licensing” role on the same server with RDS connection broker role $Server3
Write-log "Installing RDS Licensing role on $Server3"  -Type INFO
Add-RDServer -Server $Server3 -Role RDS-LICENSING –ConnectionBroker $Server3 -ErrorAction SilentlyContinue


# Verify the roles on each server (No reboot is expected at this point)
write-host "############################################################################################################"
Get-RDServer $server3
$RDS_Status = Get-RDServer $server3
get-date | Out-File -FilePath $AppendLog -Append -Encoding ASCII -Force
$RDS_Status | Out-File -FilePath $AppendLog -Append -Encoding ASCII 

Write-log "Current Licesing status is the default:"
Get-RDLicenseConfiguration -ConnectionBroker "$Server3" -ErrorAction SilentlyContinue
$RDS_LicStatus = Get-RDLicenseConfiguration -ConnectionBroker "$Server3"
get-date | Out-File -FilePath $AppendLog -Append -Encoding ASCII -Force
$RDS_LicStatus | Out-File -FilePath $AppendLog -Append -Encoding ASCII 

Clear-variable -name RDS_Status
Clear-variable -name RDS_LicStatus
Start-Sleep 10


#Time to activate the RDS Licensing role with “Per-User” Mode. First is shown in the screen then saved to the log file.

Write-log "#Time to activate the RDS Licensing role with Per-User Mode. on $Server3"  -Type INFO
Set-RDLicenseConfiguration -LicenseServer $Server3 -Mode PerUser -ConnectionBroker $Server3 -Force -ErrorAction SilentlyContinue

Get-RDLicenseConfiguration -ConnectionBroker "$Server3"
$RDS_LicStatus = Get-RDLicenseConfiguration -ConnectionBroker "$Server3"
get-date | Out-File -FilePath $AppendLog -Append -Encoding ASCII -Force
$RDS_LicStatus | Out-File -FilePath $AppendLog -Append -Encoding ASCII 


clear-variable -name RDS_LicStatus
Start-Sleep 10



#Create the RDS Collection to host the “RDS Session Host” servers. This below command will make that possible adding the two “RDS Session Host” servers.
#First we need to ask for the Collection Name
write-log "Time to create the new Collection" -Type INFO

[String]$CollectionName = Read-host "Please type the collection Name"
New-RDSessionCollection –CollectionName "$CollectionName" –SessionHost @("$Server1","$Server2") –CollectionDescription “This Collection is for Desktop Sessions” –ConnectionBroker $Server3  -ErrorAction SilentlyContinue


write-log "CollectionName is $CollectionName with members $Server1 and $Server2" -Type INFO
Start-Sleep 10

#Now we query the RDS Collection Settings and display and log such information. First display on screen then save in the log file.
Get-RDSessionCollectionConfiguration -CollectionName "$CollectionName" -Connection -ConnectionBroker "$Server3"
$QueryCollection = Get-RDSessionCollectionConfiguration -CollectionName "$CollectionName" -Connection -ConnectionBroker "$Server3"
get-date | Out-File -FilePath $AppendLog -Append -Encoding ASCII -Force
$QueryCollection | Out-File -FilePath $AppendLog -Append -Encoding ASCII -Force

    If ($CollectionName)
        {
            Write-log "The $CollectionName Collection has been created successfully" -Type INFO
            Start-Sleep 10
        }
        Else
        {    
            Write-log "Check the Windows Events in $server3 and $AppendLog on this server for details" -Type INFO
        }





Start-sleep 10


############################################################################################################################################################################
# Part # 3 Additional configurations
# 
############################################################################################################################################################################

# Add *MG* liscensing server to the "Terminal Server License Servers" AD group so that it can issue user CALs

Import-Module Activedirectory
pushd

$Server3Short = $Server3.Substring(0,12)
$Server3Dis = get-adcomputer -Filter * | where {$_.Name -eq $Server3Short}
$Domain = ($Server3Dis.DistinguishedName).Substring(16)

$MGDomain = $Server3.Substring(13)
cd ad:
dir 

cd ".\$Domain"

$Computer = Get-ADComputer -Identity $Server3Short 
$group = Get-ADGroup -Identity "Terminal Server License Servers"  # The running account needs to have permission on this group
Add-ADGroupMember -Identity $group -Member $computer
write-log "$Server3 has been added to the Terminal Server License Servers group" -Type INFO
C:
Start-Sleep 10



############################################################################################################################################################################
# Part # 4 RDS  collections Settings to replace GPO
# #Get-help Set-RDSessionCollectionConfiguration -showwindow
############################################################################################################################################################################
# Configuring the Collection settings to point the profile settings to a File Share
[string]$ProfileShare = Read-Host "Input the File share that will host the Users Profile un UNC Format \\FileServer\Share"
#$Server3 = 'UCCSMG100131.infra.taleocloud.dev'
#$CollectionName = 'OJETE_COLL'

 # Here we create a subfolder on the $CollectionName, where the profile share will be hosted
 $ProfileFolder = "$ProfileShare\$CollectionName"
 $TestProfile = Test-Path $ProfileFolder

If ($TestProfile -ne $true){

    $FolderCreation = @{}
    $FolderCreation = New-Item $ProfileFolder -ItemType Dir
    write-log "$CollectionName Folder was created successfully `n `r $($FolderCreation[1])" -Type INFO
    Write-Log "Configuring the Collection settings on Collection $CollectionName to point the profile settings to a File Share $ProfileShare" -Type INFO
    #$ProfileEnabledOK = Set-RDSessionCollectionConfiguration -CollectionName "$CollectionName" -EnableUserProfileDisk -MaxUserProfileDiskSizeGB 10 -DiskPath "$ProfileShare" -ConnectionBroker "$Server3"  -ErrorAction SilentlyContinue
    $ProfileEnabledOK = Set-RDSessionCollectionConfiguration -CollectionName "$CollectionName" -EnableUserProfileDisk -MaxUserProfileDiskSizeGB 10 -DiskPath "$ProfileFolder"  -ConnectionBroker "$Server3" -ErrorAction SilentlyContinue

    Set-RDSessionCollectionConfiguration -CollectionName "$CollectionName" -ClientDeviceRedirectionOptions Clipboard -IdleSessionLimitMin 10 -ClientPrinterRedirected $false -MaxRedirectedMonitors 2 -ErrorAction SilentlyContinue

    Write-Log "Configuring the Collection Client Settings" -Type INFO
    Start-Sleep 10
    Set-RDSessionCollectionConfiguration –CollectionName "$CollectionName"  -CustomRdpProperty "drivestoredirect:s:0: `n redirectprinters:i:0 `n redirectsmartcards:i:0 `n devicestoredirect:s:0 `n redirectdrives:i:0 `n audiocapturemode:i:0"
    
}Else{
    write-log "$CollectionName Folder ALREADY Exist at path $ProfileShare SO doublecheck your deployment. Script will continue anyways since this does not affects the current deployment" -Type INFO
    Start-Sleep 10
}   


 If ($ProfileEnabledOK -eq $null)
        {
            Write-log "The $CollectionName Collection has been created successfully" -Type INFO
            #Write-host "The $CollectionName Collection has been created successfully"
            Start-Sleep 10
        }
        Else
        {    
            Write-log "Check the Windows Events in $server3 and $AppendLog on this server for details" -Type INFO
        }

<#
 # Here we create a subfolder on the $CollectionName, where the profile share will be hosted
 $ProfileFolder = "$ProfileShare\$CollectionName"
 $TestProfile = Test-Path $ProfileFolder

 If($TestProfile){
    write-log "$CollectionName already exist, please input a new one" -Type ERROR
    }Else{
    $FolderCreation = @{}
    $FolderCreation = New-Item $ProfileFolder -ItemType Dir
    write-log "$CollectionName Folder was created successfully `n `r $($FolderCreation[1])" -Type INFO
    }

    #    $($FolderCreation[0])
#>
#Set-RDSessionCollectionConfiguration –CollectionName "$CollectionName" -ConnectionBroker "$Server3" -CustomRdpProperty "drivestoredirect:s:0: `n redirectprinters:i:0 `n redirectsmartcards:i:0 `n devicestoredirect:s:0 `n redirectdrives:i:0 `n audiocapturemode:i:0 `n use multimon:i:0"
#Set-RDSessionCollectionConfiguration –CollectionName "$CollectionName"  -CustomRdpProperty "drivestoredirect:s:0: `n redirectprinters:i:0 `n redirectsmartcards:i:0 `n devicestoredirect:s:0 `n redirectdrives:i:0 `n audiocapturemode:i:0 `n use multimon:i:0"
#Get-RDSessionCollectionConfiguration -CollectionName "$CollectionName" -Connection -ConnectionBroker "$Server3"

############################################################################################################################################################################
# Part # 5 Proxy configuration
# 
############################################################################################################################################################################

Write-log "Starting Proxy Configuration to allow access to Web Licensing Activation" -Type INFO
Start-Sleep 10

Import-module ActiveDirectory

#Write-host "This is for testing purposes"
# clear-variable -name clientdomainfqdn
# $clientdomainfqdn = "CHTEFSS00992.TEE-PP.TALEOCLOUD.PRDUSY"
# $Domain = "TEE-PP.TALEOCLOUD.PRDUSY"


# Partial code to create the Proxy string on any Taleo Entity

$ServerName = get-content env:computername
$Datacenter = $ServerName.substring(0,2).ToLower()
$clientenv = $ServerName.substring(7,2)
$client = [System.Net.Dns]::GetHostByName(($env:computerName))
$clientdomainfqdn = $client.hostname
$Domain = (Get-WmiObject Win32_ComputerSystem).Domain



$clientdomainnet = $clientdomainfqdn.Split(".")[1] + "." + $clientdomainfqdn.Split(".")[2]
      $clientdomaingroup = $ServerName + "$"
        $Podid = $ServerName.substring(6,1).ToLower()


$proxy = $Datacenter + $Podid +"proxy." + $clientdomainnet.ToLower()
$proxyServerToDefine = $proxy +".NET" +":3128"
$proxyServerToDefine


#ADD-ADGroupMember “Terminal Server License Servers” –members “$clientdomaingroup” -ErrorAction SilentlyContinue

Write-log $proxyServerToDefine -Type INFO
Start-Sleep 5

$regKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$regKeycomp="HKCU:\Software\Microsoft\Internet Explorer\BrowserEmulation"
$proxyServer = ""

Write-log "Retrieve the proxy server $proxyServerToDefine" -Type INFO
$proxyServer = Get-ItemProperty -path $regKey ProxyServer -ErrorAction SilentlyContinue
Write-log $proxyServerToDefine -Type INFO
Start-Sleep 5

if([string]::IsNullOrEmpty($proxyServer))
{
    Write-Host "Proxy is actually disabled"
    Set-ItemProperty -path $regKey ProxyEnable -value 1
    Set-ItemProperty -path $regKey ProxyServer -value $proxyServerToDefine
    Set-ItemProperty -path $regKeycomp MSCompatibilityMode -value 1
    Write-log "Proxy is now enabled" -Type INFO
}
else
{
    Write-log "Proxy is actually enabled" -type INFO
    Set-ItemProperty -path $regKey ProxyEnable -value 0
    Remove-ItemProperty -path $regKey -name ProxyServer
    Write-log "Proxy is now disabled" -Type INFO
}

$proxyServerToDefine2 = "http=" + $proxyServerToDefine
netsh winhttp set proxy proxy-server="$proxyServerToDefine2;$proxyServerToDefine"
C:
Start-Sleep 10


############################################################################################################################################################################
# Part # 6 License Activation
# 
############################################################################################################################################################################

Start-Transcript -path .\OVM_MG_RDS_licenses.log

Import-Module RemoteDesktopServices
#net start termservlicensing
get-service -Name TermServLicensing | Start-Service
cd RDS:\
set-item -path rds:\licenseserver\configuration\Firstname -value Oracle
set-item -path rds:\licenseserver\configuration\Lastname -value Cloud
set-item -path rds:\licenseserver\configuration\Company -value Oracle
set-item -path rds:\licenseserver\configuration\CountryRegion -value "United States"
set-item -path rds:\licenseserver\configuration\eMail -value taleo_cloud_infra_support_ww_grp@oracle.com
Start-Sleep -s 10
Set-Item -path RDS:\LicenseServer\ActivationStatus -Value 1 -ConnectionMethod AUTO -Reason 5 -Force
Start-Sleep -s 30
New-Item -path RDS:\LicenseServer\LicenseKeyPacks -InstallOption INSTALL -ConnectionMethod AUTO -LicenseType AGREEMENT -AGREEMENTTYPE 0 -AGREEMENTNUMBER 6133673 -PRODUCTVERSION 4 -PRODUCTTYPE 1 -LICENSECOUNT 10
Write-log "For Licensing logs refer to the file OVM_MG_RDS_licenses.log" -Type INFO
Start-Sleep -s 10

netsh winhttp reset proxy

Stop-Transcript

get-process ServerManager -ErrorAction SilentlyContinue | stop-process -ErrorAction SilentlyContinue -Force 
Write-log "Finishing... check log file in $server3 at path C:\cs_pks for details if needed"  -Type INFO

Close-log 
Exit 
