 

#$cred = Get-Credential

 

 

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

 


$mydownloads = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path

$MyTemp =(Get-Item $mydownloads).fullname

$myuser=  $myuser=  $env:USERDOMAIN + "\" + $env:USERNAME


 

   $response = Invoke-WebRequest -Uri https://raw.githubusercontent.com/Louisjreeves/S2dBallance/main/3Prod_VMBAM7.24.ps1 -OutFile $mytemp\Prod_VMBAM.ps1


 $activedirectory = "C:\Users\$myuser\Downloads\"

set-location $activedirectory

  .\Prod_VMBAM.ps1 

 





  
