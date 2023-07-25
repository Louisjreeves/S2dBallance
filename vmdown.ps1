 

#$cred = Get-Credential

 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
 Set-ExecutionPolicy Unrestricted -scope Process 



$mydownloads = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path

$MyTemp =(Get-Item $mydownloads).fullname

 
 
$response = Invoke-WebRequest -Uri https://raw.githubusercontent.com/Louisjreeves/S2dBallance/main/3Prod_VMBAM7.24.ps1 -OutFile $mytemp\Prod_VMBAM.ps1

 
set-location $mydownloads

  .\Prod_VMBAM.ps1 

 





  
