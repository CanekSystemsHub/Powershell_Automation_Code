@echo off
c:
c: \

cd C:\cs_pkgs

Echo Starting the RDS Roles deployment and configurations
PowerShell.exe -NoProfile -Command "& {Start-Process PowerShell.exe -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File .\OVM_MG_Deploy.ps1' -Verb RunAs}"
Echo Deployment completed check logs to review C:\cs_pkgs
Pause

@echo on
@echo off