#Written by Alex McCrobie
#4/14/2021
#Please read through before running :)

function ADATMain-Menu{
    
    param (
        [string]$Title = 'Active Directory Auditing Tool'
    )

    Clear-Host
    Write-Host "`n###################################################################"
    Write-Host "# $Title                                  #"
    Write-Host "# 1. Generate Reports                                             #"
    Write-Host "# 2. Enabling Auditing                                            #"
    Write-Host "###################################################################"
}
function Invoke-Reports{
    $clientName = read-host "`nEnter a client name: "
    $pathName = ("c:\temp\ADAT\")
    if(!(Test-Path -path $pathName)) {  
        New-Item -ItemType directory -Path $pathName
        } 
    Clear-Host
    
    Write-Host "Generating AD User List..." -NoNewLine
    $reportPath = $pathName + $clientName + "-ADUserReport.csv"
    Get-ADUser -Filter * -Properties * | Select-Object Name, SamAccountName, LastLogonDate, Enabled | Export-csv -path $reportPath
    Write-Host "Done" 

    Write-Host "Generating AD Group List..." -NoNewLine
    $reportPath = $pathName + $clientName + "-ADGroupReport.csv"
    Get-ADGroup -Filter * -Properties GroupCategory | Format-Table name,groupcategory | Export-csv -path $reportPath
    Write-Host "Done" 

    Write-Host "Generating Password Verification List..." -NoNewLine
    $reportPath = $pathName + $clientName + "- PasswordReport.csv"
    Get-ADUser -Filter * -Properties passwordlastset, passwordneverexpires | Format-Table Name, passwordlastset, Passwordneverexpires | Export-csv -path $reportPath
    Write-Host "Done" 

    Write-Host "Generating Scheduled Tasks list..." -NoNewLine
    $reportPath = $pathName + $clientName + "- TaskReport.csv"
    Get-ScheduledTask | Where-Object state -EQ 'ready' | Get-ScheduledTaskInfo | Export-Csv -NoTypeInformation -Path $reportPath
    Write-Host "Done" 

    
}

function Invoke-AuditToggle{
    #Show hidden files and file extensions 
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name Hidden -value 1 | out-null
    Set-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name HideFileExt -value 0 | out-null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -name ShowSuperHidden -value 1 | out-null
    
    #Setting auditing policies
    auditpol /set /subcategory:"directory service changes" /success:enable
    auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable 
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable 
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable 
    auditpol /set /subcategory:"IPsec Driver" /success:disable /failure:disable 
    auditpol /set /subcategory:"Other System Events" /success:disable /failure:enable 
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable 
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 
    auditpol /set /subcategory:"IPsec Main Mode" /success:disable /failure:disable 
    auditpol /set /subcategory:"IPsec Quick Mode" /success:disable /failure:disable 
    auditpol /set /subcategory:"IPsec Extended Mode" /success:disable /failure:disable 
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable 
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable 
    auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable 
    auditpol /set /subcategory:"File System" /success:enable /failure:enable 
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable 
    auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable 
    auditpol /set /subcategory:"SAM" /success:disable /failure:disable
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable 
    auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable 
    auditpol /set /subcategory:"Handle Manipulation" /success:disable /failure:disable 
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable 
    auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable 
    auditpol /set /subcategory:"Filtering Platform Connection" /success:disable /failure:disable 
    auditpol /set /subcategory:"Other Object Access Events" /success:disable /failure:disable 
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:disable /failure:disable
    auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:disable /failure:disable 
    auditpol /set /subcategory:"Other Privilege Use Events" /success:disable /failure:disable 
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 
    auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable 
    auditpol /set /subcategory:"DPAPI Activity" /success:disable /failure:disable 
    auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable 
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable 
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable 
    auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable 
    auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:disable /failure:disable
    auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable 
    auditpol /set /subcategory:"Other Policy Change Events" /success:disable /failure:enable 
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable 
    auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable 
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable 
    auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable 
    auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable 
    auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable 
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable 
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable 
    auditpol /set /subcategory:"Directory Service Replication" /success:disable /failure:disable 
    auditpol /set /subcategory:"Detailed Directory Service Replication" /success:disable /failure:disable 
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable 
    auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable 
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    }

function Invoke-SecurityChanges{
    #Enable Structured Exception Handling Overwrite Protection
    Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -name DisableExceptionChainValidation -value 0 | out-null
    Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -name LocalAccountTokenFilterPolicy -value 0 | out-null
    #Disable IPv6
    New-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" -name DisabledComponents -value 0xff | out-null

}

do{
    ADATMain-Menu 
    $userInput = Read-Host "Please make a selection"
    switch ($userInput){
        '1' {Invoke-Reports}
        '2' {"whatever you want here"}

    }
    pause
    
} 
until ($userInput -eq "x")
