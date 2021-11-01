"# Powershell_Remote_Desktop_Services_Automation_Code" 

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

"# Powershell_File_server_Cluster_Automation_Code"
