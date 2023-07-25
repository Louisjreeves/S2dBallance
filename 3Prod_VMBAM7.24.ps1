

  [CmdletBinding(SupportsShouldProcess = $true,ConfirmImpact='High')] 
    param (
        [alias("CimSession ")]
        [Parameter(Position = 0)][String]$Clustername = "localhost",
        [switch]$QuickMigration,
        [int]$Global:NodePhysicalmemorybufferGB = 64
       

    )

          
$Global:NodePhysicalmemorybufferGB =64
$global:readit =$null
$global:readitnow = $null
$global:dedup2 = $null
$global:dedup1 = $null
 $global:mydom 
  $global:myuser
  $global:creds
 $ErrorActionPreference = 'SilentlyContinue'
   $VerbosePreference = "silentlycontinue"
   $warningactionPreference = "SilentlyContinue"

# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 $global:RunTime
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
 
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
 
   }
else
   {
   # We are not running "as Administrator" - so relaunch as administrator
 
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
 
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
 
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
 
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
 
   # Exit from the current, unelevated, process
   exit
 
   }
   Set-ExecutionPolicy Unrestricted -scope Process -Confirm:false
  $global:Start_Time = get-date 
  $global:end_time
  $global:finsh_time


 
 #Choice 1 basic report
Function mycol
{

 [CmdletBinding(SupportsShouldProcess = $false,ConfirmImpact='High')] 
    param (
          [Alias("CimSession")]
        [Parameter(Position = 0)]
        [String]$Clustername = "localhost"
               )
 

  clear-host
 #region VMDistributionPernode
 echo off
 #Report title and set Gui menu message

   
  $results2 = @()
 write-host "------------------------------------------------------------------"  -ForegroundColor Green
write-host "----------------S2d Balance Report Begin-------------------------" 
write-host "------------------------------------------------------------------" -ForegroundColor Green 

write-output "==============================================================="  
Write-output "          Disproportionate VM count per volume by Percentage   " 

 

   

#getcusteredvms
 #region cut
#Theoretical perfection calculation
$vmcount= 0
$TOTVM=0
$pernodePerCsv = 0
$clusterNodes = Get-ClusterNode 
$totalSharedVolumes = (Get-ClusterSharedVolume).Count
#$TOTVM = Get-ClusterNode | ForEach-Object { Get-VM -ComputerName $_ } | Measure-Object | Select-Object -ExpandProperty Count
$totnodes = (Get-ClusterNode).count
$vmcount = Invoke-Command -ComputerName (Get-ClusterNode) -ScriptBlock {Get-VM | Measure-Object | Select-Object -ExpandProperty Count}
#get nonclusteredvms
$totalvmsincluster = Get-VM –ComputerName (Get-ClusterNode –Cluster (get-cluster)) | where { $_.IsClustered –eq $false }
$totvmsinclusterCT = ($totalvmsincluster).count

$totTurnedonVmsIncluster = Get-VM –ComputerName (Get-ClusterNode –Cluster (get-cluster)) |Where-Object { $_.IsClustered -eq $false -and $_.MemoryAssigned -gt 0 }
######################################################################
#Calculate Perfect balanced
  
 
$csvs = @{}
$combinedArray = @()
$csvSummary = @{}
$combinedEntry = [PSCustomObject]@{}

foreach ($node in $clusterNodes) {
    $csvs = Get-ClusterSharedVolume -Cluster $node.Name | Where-Object {$_.FriendlyName -notlike "ClusterPerformanceHistory" -and $_.FriendlyName -notlike "Cluster Group" -and $_.FriendlyName -notlike "Available Storage"}
    foreach ($csv in $csvs) {
        $csvPath = $csv.SharedVolumeInfo.FriendlyVolumeName
        $vhdxCount = (Get-ChildItem -Path $csvPath -Filter *.vhdx -File -Recurse).Count

        if ($csvSummary.ContainsKey($csv.SharedVolumeInfo.FriendlyVolumeName)) {$csvSummary[$csv.SharedVolumeInfo.FriendlyVolumeName] += $vhdxCount} 
        if (!($csvSummary.ContainsKey($csv.SharedVolumeInfo.FriendlyVolumeName))) {$csvSummary[$csv.SharedVolumeInfo.FriendlyVolumeName] = $vhdxCount}
        
     }

$counter = 0
$totalVMhomes =0
foreach ($csv in $csvSummary.GetEnumerator()) {
    $fileName = Split-Path -Path $csv.Key -Leaf
    $count = $csv.Value

    $combinedEntry = [PSCustomObject]@{
        Disk = $fileName
        Count = $count
    }
    $combinedArray += @($combinedEntry)
}
 
}
    
#(Number of VMs for Respondent / Total Number of VMs for all disks) * 100

foreach ($entry in $combinedArray) {
If ($entry.count -ne 0)
{
#totalvmhomes counts the total vms of responding vd
$totalVMhomes += $entry.Count
$counter++
# nonresponds counts the total disks that have 0 vms
}else {$nonresponds ++}



}

#endregion

 #endregion

 ###################################All calcs from this section on are for output B ################################################


#Collect Info from other nodes 
#region outputb
#138 to 146
Write-host "============================================="
write-output "Volume            Vms  Percent vm to total"
write-host "============================================"
foreach ($entry in $combinedArray) {
    $percentbyVD = [math]::Round(($entry.count / $totalVMhomes) * 100)
    
    write-output ("{0,-18} {1,-6} {2}" -f $entry.Disk, $entry.Count, $percentbyVD)
}
write-output "---------------------------------------"


 $results2 = @()
 $results3=@()
$nodeResult= @()
$results2 = Invoke-Command -ComputerName (Get-ClusterNode) -ScriptBlock {
    $my32ProcInfo = Get-WmiObject Win32_Processor
    $my32OSInfo = Get-WmiObject Win32_OperatingSystem

    $my1name = $my32ProcInfo.SystemName
    $Corecount = $my32ProcInfo.NumberOfCores
    $totalCorecount = 0
    foreach ($core in $Corecount) {
        $totalCorecount += $core
    }
    $mynumLogicProcs = $my32ProcInfo.NumberOfLogicalProcessors
    $totalmynumLogicProcs = 0
    foreach ($proc in $mynumLogicProcs) {
        $totalmynumLogicProcs += $proc
    }
    $totMemory = [math]::round($my32OSInfo.TotalVisibleMemorySize / 1MB, 0)

    # 8GB of 16GB of memory is RESERVED for the host
     
    $availVMMemory = $totMemory - $Global:MinRamHost
    $frMemory = [math]::round($my32OSInfo.FreePhysicalMemory / 1MB, 0)
$vmMemory = Get-VM | Measure-Object -Property MemoryAssigned -Sum
$totalRAMUsed = [math]::round($vmMemory.Sum / 1GB, 2)
$vmProcessors = Get-VM | Measure-Object -Property ProcessorCount -Sum
$totalVMprocused = [math]::round($vmProcessors.Sum, 2) 
## ############
#Disks section
###############
                $vmDisks = Get-VM -ComputerName $env:COMPUTERNAME | Get-VMHardDiskDrive

                foreach ($disk in $vmDisks) {
                        $vmName = $disk.VMName
                        $diskName = $disk.Path
                        $vmdiskname +=$diskName
                        $counterName = "\Processor(_Total)\% Processor Time"
                        #$vmcountername += $counterName
                        $counterValue = (Get-Counter -ComputerName $env:COMPUTERNAME -Counter $counterName).CounterSamples.CookedValue
                        $vmcountervalue += $counterValue

                      

                      }


                    # Return the values as a custom object
                    [PSCustomObject]@{
                        Name = $name
                        TotalCoreCount = $totalCorecount
                        TotalLogicalProcessors = $totalmynumLogicProcs
                        TotalMemory = $totMemory
                        AvailableVMMemory = $availVMMemory
                        FreePhysicalMemory = $frMemory
                        totalRAMUsed = $totalRAMUsed
                        totalVMprocused = $totalVMprocused
                        vmName = $vmName
                        diskName = $diskName
                        counterValue = $countervalue
                        vmdiskname = $vmdiskname
                        vmcountername= $vmcountername
                        vmcountervalue=$vmcountervalue

                    }
} -OutVariable outputb


 $outputb | ForEach-Object {

                   $Name = $_.Name
    $totalCoreCount = $_.TotalCoreCount
    $clusterCoreCount +=$totalCoreCount
    $totalLogicalProcessors = $_.TotalLogicalProcessors
     $totalMemory = $_.TotMemory
     $grtotalmem+=$_.TotMemory
    $availableVMMemory = $_.AvailableVMMemory
    $clusterVMMemory +=$availableVMMemory
    $freePhysicalMemory = $_.FreePhysicalMemory
    $ClusterFreePhyMem +=$freePhysicalMemory
    $totalRAMUsed = $_.totalRAMUsed
    $ClustTotRamUsed += $totalRAMUsed
    $netAvailVMRam= ($availableVMMemory -$totalRAMUsed)
   $clusterNetVmAvailRam += $netAvailVMRam
    $totalVMprocused = $_.totalVMprocused
    $clusterTotVMProUsed += $totalVMprocused 
    $Vmname =$_vmname
    $diskname = $_.diskname
    $countervalue = $_.countervalue
     $vmdiskname = $_.vmdiskname
    $vmcountername= $_.vmcountername
    $vmcountervalue=$_.vmcountervalue
 

 Write-host "======================================" -ForegroundColor Green
Write-host "Cross checked Values "                  -ForegroundColor Green
Write-host "======================================" -ForegroundColor Green
#endregion
Write-output  "Total Core Count:  $totalCoreCount "
 Write-output "Total clusterCoreCount  $clusterCoreCount"
 Write-output "Total totalLogicalProcessors $totalLogicalProcessors"
 Write-output "Total totalMemory  $totalMemory" 
 Write-output "Total grtotalmem $grtotalmem"
 Write-output "Total clusterVMMemory  $clusterVMMemory" 
 Write-output "Total freePhysicalMemory $freePhysicalMemory"
 Write-output "Total ClusterFreePhyMem  $ClusterFreePhyMem"
 Write-output "Total availableVMMemory  $availableVMMemory"
 Write-output "Total availableVMMemory  $availableVMMemory"
 
 Write-output  "Total totalRAMUsed $totalRAMUsed"
  Write-output "Total ClustTotRamUsed $ClustTotRamUsed" 
  Write-output "Total netAvailVMRam  $netAvailVMRam"
  Write-output "Total lusterNetVmAvailRam  $lusterNetVmAvailRam"
  Write-output "Total totalVMprocused  $totalVMprocused"
  Write-output "Total clusterTotVMProUsed $clusterTotVMProUsed"
  Write-output "Total Vmname  $Name"
  Write-output "Total diskname  $diskname" 
  Write-output "Total countervalue $countervalue"
  #Write-output "Total vmdiskname   $vmdiskname "
  #Write-output "Total vmcountername  $vmcountername"
  Write-output "Total vmcountervalue  $vmcountervalue"
 #########status update######

 
    
 
 
 

 
}




#region clustercollection


 foreach ($node in $clusterNodes) {
    $sharedVolumes = Get-ClusterSharedVolume | Where-Object { $_.OwnerNode -eq $node.Name }
    $nodeResult = New-Object PSObject -Property @{
        NodeName = $node.Name
        VolumeCount = $sharedVolumes.Count
        FractionOfTotal =  [math]::Round(($sharedVolumes.Count / $totalSharedVolumes)*100)
    }
    $results3 += @($nodeResult)
} 

# write-host  "=================================================="
# Write-host " Csv/Node  Cvs min per node    nodes getting another volume          " -ForegroundColor Green
#Write-host "    $roughcountVolperNode         " -Nonewline 
#write-host "$baseVolumesPerNode" -nonewline
#write-host  $nodesWithExtraVolume
 
 
$roughcountVolperNode = $totalSharedVolumes / $clusterNodes.Count

# How many volumes each node will get at minimum
$baseVolumesPerNode = [Math]::Floor($totalSharedVolumes / $clusterNodes.Count)

# How many nodes will get an extra volume
$nodesWithExtraVolume = $totalSharedVolumes % $clusterNodes.Count

$resultdist = New-Object PSObject -Property @{
    BaseVolumesPerNode = $baseVolumesPerNode
    NodesWithExtraVolume = $nodesWithExtraVolume
}

if((($baseVolumesPerNode | Get-Unique).Count -eq 1) -and ((($nodesWithExtraVolume -eq 0))))
 {

#$resultdist
Write-output "===============================================================" 
Write-output "Virtual disks are in Balance  "
Write-output "===============================================================" 
write-output $results2 | fl name,PSComputerName,Totalcorecount,CoreCount,clusterCoreCount,totalLogicalProcessors,totalMemory,grtotalmem,clusterVMMemory,freePhysicalMemory,ClusterFreePhyMem,availableVMMemory,
availableVMMemory,totalRAMUsed,ClustTotRamUsed,netAvailVMRam,lusterNetVmAvailRam,totalVMprocused,clusterTotVMProUsed,vmname
    
} else
{
 
write-output "===============================================================" 
write-output "Virtual disk out of Balance  "
write-output "===============================================================" 
#write-output $resultdist 
    write-output $results2 | fl name, PSComputerName,Totalcorecount,CoreCount,clusterCoreCount,totalLogicalProcessors,totalMemory,grtotalmem,clusterVMMemory,freePhysicalMemory,ClusterFreePhyMem,availableVMMemory,availableVMMemory,
    ClustTotRamUsed,netAvailVMRam,lusterNetVmAvailRam,totalVMprocused,clusterTotVMProUsed,vmname
 
  

}
#endregion

write-output "Each node should own an equal number of CSV." 

write-output "Each node should own $baseVolumesPerNode CSV then Nodes with an extra volume will be: $nodesWithExtraVolume volumes" 
 
#write-output $results2
#write-output $resultdist 
Write-host "================================================" -ForegroundColor Green
Write-output "---------------CSV volume per Node report-----------"
Write-host "================================================" -ForegroundColor Green

Write-Host ("{0,-8} {1,12} {2,12}" -f "% of vms", "   NodeName " , " volumeCount")
Foreach ($res in $results3)
{

write-host ("{0,-8} {1,12} {2,12}" -f $res.fractionoftotal, $res.nodename, $res.Volumecount )
#Write-Host ("{0,-14} {1,-8} {2}" -f $res.fractionoftotal, $res.nodename, $res.Volumecount)}


 
 }




 #$resultdist not much data
#endregion
                
   # Waiting for the "TaskComplete" event before exiting the script
 read-Host "Hit enter to close report. Thank you For using this tool today!"  
Write-host "=========================================================="        
 
 } 

#2 checks alignment and shows how to ballance and what vms to move
 Function Alignvmtest
{
     [CmdletBinding(SupportsShouldProcess = $true,ConfirmImpact='High')] 
    param (
        [alias("CimSession ")]
        [Parameter(Position = 0)][String]$Clustername = "localhost",
        [switch]$QuickMigration,
        [int]$Global:NodePhysicalmemorybufferGB = 64
    

    )
    begin{
        #region:Helper Functions
        Function GetCSVIDbyPath {
            param ($CSVpath)

            Begin {
                Write-Verbose -Message "Trying to find CSV ID with path $CSVpath"
            }
            Process {
                $CSVhash.keys | ForEach-Object {
            
                    #If value found, write out key
                    If ($CSVhash[$_] -like $CSVpath) {
                        Write-Verbose -Message "Found ID for $CSVPath - $_"
                        Write-output $_
                    }
                }
            }
        }
        #endregion

        #region GatherInfoNeeded

        #Cluster
        $Cluster = Get-Cluster -Name $Clustername
        $Clustername = $Cluster.Name + "." + $cluster.Domain

        if (!($Cluster)) {
            Write-Error "Could not find Cluster with name $Clustername"
        }
        Else {
            $domain = $Cluster.Domain
            Write-Verbose "Found Cluster $Clustername in domain $domain"
        }

        #ClusterNodes
        $clusternodes = Get-ClusterNode -cluster $Clustername
        if (!($clusternodes)) {
            Write-Error "Could not find cluster nodes in cluster $Clustername"
        }
        Else {
            $count = ($clusternodes).count
            Write-Verbose "Found $count cluster nodes in cluster $Clustername"
        }

        #ClusterSharedVolumes
        Write-Verbose "Getting CSV(s) from $Clustername"
        $Clustersharedvolumes = Get-ClusterSharedVolume -Cluster $Clustername

        if (!($Clustersharedvolumes)) {
            Write-Error "Could not find Cluster Shared Volumes on $Clustername"
        }
        Else {
            $count = ($Clustersharedvolumes).count
            Write-Verbose "Found $count CSV(s) on cluster $Clustername"
        }




        #endregion
    }
    process{
        #region interpret information
        $ErrorActionPreference = 'SilentlyContinue'
        $CSVhash = @{}
        $WarningActionPreference = 'SilentlyContinue'
clear-host
$Global:NodePhysicalmemorybufferGB= 64
$cusram= 64
    #  $custram=  read-host "Enter the Amount of Memory you need to keep for Cluster Node Memory. Enter = 32 "
      
      #  if (!($custram.Length)) {$Global:NodePhysicalmemorybufferGB = 64}
     #   else {$Global:NodePhysicalmemorybufferGB =$custram}
        Write-host " This is a test to see how far out of alignment your cluster ownership is"
        Write-host "The definition of aligned is when your vms are owned by the CSV owner."
        Read-host "Hit enter to begin test"
        
        Foreach ($Clustersharedvolume in $Clustersharedvolumes) {
            $Matches = $null
            #Extract the CSV volume names from cluster resource name
            $Null = $Clustersharedvolume.name -match ".*?\((.*?)\)" 
            if ($Matches) {
                $CSVname = $($Matches[1])
                Write-Verbose -Message "Regex matched and found $CSVname"

            }else {
                Write-Verbose -Message "Regex did not match, probably renamed CSV"
                $CSVname = $Clustersharedvolume.name
                $FirstClusternode = $clusternodes[0].Name

                Write-Verbose -Message "Checking if virtualdisk with name $CSVname exist on $FirstClusternode"
                If ((Get-VirtualDisk $CSVname -CimSession $FirstClusternode -ErrorAction SilentlyContinue -WarningAction SilentlyContinue))
                    {
                    Write-Verbose -Message "virtualdisk with name $CSVname exist on $FirstClusternode"
                }else{
                 Throw "Cannot find CSV with name $CSVname, something is wrong. Exiting."
                 Exit
                }
                 

            }

            Write-Verbose -Message "Gathering information of CSV $CSVname"

            $CSVhash[($Clustersharedvolume.Id).ToString()] = @($CSVname, $Clustersharedvolume.OwnerNode.Name, $Clustersharedvolume.SharedVolumeInfo.FriendlyVolumeName)
        }



        ## Find VMs and the CSV they live on and the host they live on
        ## exclude VMs with disks on multiple CSVs (for now?)

        $VMhash = @{}
	$VMs = $null
        Foreach ($clusternode in $clusternodes) {
            [array]$VMs += (Get-VM -ComputerName $clusternode -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        }
        Foreach ($VM in $VMs) {
        
            Write-Verbose -Message "Finding disks for $($VM.name)"
        
            $CSVtemparray = @()
            Foreach ($disk in ($vm | Get-VMHardDiskDrive -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            
                $diskpathsplit = $disk.path -split '\\' 
                $diskpathsplit2 = split-path $disk.path -leaf
                $CSVpath = $diskpathsplit[0] + "\" + $diskpathsplit[1] + "\" + $diskpathsplit[2]
                 $fileName = Split-Path $csvpath -Leaf
              
                Write-host  "Candidate VM  $diskpathsplit2 disk on $Filename" -ForegroundColor Green
              #  Write-Verbose -Message "Trying to find CSV ID through GetCSVIDbyPath function"
                $TempCSVID = GetCSVIDbyPath -CSVpath $CSVpath

                $CSVtemparray += $TempCSVID
            
            }

            $CSVID = ($CSVtemparray | Group-Object | Sort-Object Count -descending | Select-Object -First 1).name

           # Write-host "Adding $($VM.Name) to hash table " -ForegroundColor Yellow
            #Write-Verbose -Message "Adding $($VM.Name) to hash table using CSV ID $CSVID"
            $vmid = $VM.VMID.ToString()
            $VMhash[$vmid] = @($VM.name, $CSVID, $VM.ComputerName, $VM.MemoryAssigned, $VM.State)
        
        }

        ##Create task list of volumes to move to be in optimal condition
        $VMstoMove = @{}
        $vmnot2move= @()
        #Check if VM is on same disk as node
        $VMhash.Keys | ForEach-Object {
         $VMOwner = $VMhash[$_][2]
            $CSVOwner = $CSVhash[$VMhash[$_][1]][1]
            

            if ($VMOwner -eq $CSVOwner) {
             $vmid = $_.ToString()
             $notmoving= @($VMhash[$_][0])
                Write-Host "VM  $notmoving is on same host as CSV" -ForegroundColor Magenta
            $vmnot2move = @($VMhash[$_][0], $CSVOwner, $VMhash[$_][3], $VMhash[$_][4])
            }
            else {
                #Write-Verbose -Message "VM with ID $_ is on different host as CSV and can be optimized"
            
                $vmid = $_.ToString()  
                $movingvm = @($VMhash[$_][0])  
                $VMstoMove[$vmid] = @($VMhash[$_][0], $CSVOwner, $VMhash[$_][3], $VMhash[$_][4])
                
               # Write-Output "========================================================================="
               # Write-output " Final approved move list after compute analysis complete" 
               # Write-output "========================================================================="
                Write-Host "VM  $movingvm is on Final move list unless problems with VM" -ForegroundColor cyan
              

            }



        }

       # $($VMstoMove)
        #endregion 

        #region Move VMs


        Write-Output "Found $($($VMstoMove).count) VM(s) to be optimized."
        Write-Verbose "Quickmigration switch = $Quickmigration"

        $VMstoMove.Keys | ForEach-Object {

            $vmid = $_.ToString()
            $vmname = $VMstoMove[$_][0]
            $targetnode = $VMstoMove[$_][1]
            $VMstate = $VMstoMove[$_][3]
            $VMmem = $VMstoMove[$_][2] / 1024 / 1024 / 1024
        

            Write-Verbose -Message "Intent to move $vmname to $targetnode"
          

            $NodeFreeMem = ((Get-WMIObject Win32_OperatingSystem -computername $targetnode).FreePhysicalMemory / 1024 / 1024)
             Write-host "======================================"
            write-host "$targetnode has $NodeFreeMem of free physical memory,$VMname needs $VMmem"

            If (($NodeFreeMem + $Global:NodePhysicalmemorybufferGB) -gt $VMmem) {
                write-host "$targetnode has enough resources to host $VMname"
                        Write-host "vmstate $VMstate" -ForegroundColor Green
                if ($VMstate -eq "Off" -or $Quickmigration -eq $true) {
                    Write-host "vmstate $VMstate" -ForegroundColor Green
                     # Write-Output "VM $vmname is $VMstate and would be moved to $targetnode using quick migration"
                       $MoveAction = "Move-ClusterVirtualMachineRole -Cluster $Clustername -VMId $vmid -Node $targetnode -MigrationType Quick"
                      # Write-Output "An Aligned VM $vmname would move to $targetnode"
                        Write-host "The String to move would be the following:" 
                        Write-host $MoveAction                    
                        
                    }
                ElseIf ($VMstate -eq "Running") {
                    
                        Write-host "VM $vmname is running and would be moved to $targetnode using live migration"
                       # $MoveAction = "Move-ClusterVirtualMachineRole -Cluster $Clustername -VMId $vmid -Node $targetnode" 
                        Write-host " The move string is below is you decide to perform manually is : " -ForegroundColor Green
                        Write-host $MoveAction
                        }        
                #############278
                Elseif ($VMstate -ne "Running") { 
                    Write-host "Status of VM $vmname is $VMstate" -ForegroundColor Red

                    Write-host "Status of VM $vmname is other then Running or Off, skipping VM."
                    Write-host "If you can fix this VM, move it manually with steps below" -ForegroundColor Green
                    Write-host "vmstate $VMstate" -ForegroundColor Red
                      #Write-Output "VM $vmname is $VMstate and Should be moved to $targetnode using quick migration"
                       $MoveAction = "Move-ClusterVirtualMachineRole -Cluster $Clustername -VMId $vmid -Node $targetnode -MigrationType Quick"
                       Write-host "An Alligned VM $vmname would move to $targetnode"
                            Write-host "The String to move would be the folowing: $MoveAction" 

                
            }
            
             }

        #endregion
  
    }
      read-Host "Hit enter to close report. Thank you for using this tool today!"  
Write-host "=========================================================="
} 

}


 #3 Uses diag-v to compute the vm to memory ratio etc...
Function remote-Vmcalc {
    Write-Host "Function remote-VMcalc Remote Statistics"
  
 ################
# Initialize Variable 
########################
$clusterCoreCount = $null 
$ClusterLogicalProcCount = $null
$clusterMemory =$null
$clusterVMMemory=$null
$ClusterFreePhyMem =$null
$ClustTotRamUsed =$null
$clusterTotVMProUsed =$null
$netAvailVMRam = $null
$clusterNetVmAvailRam = $null 
$nodeName= $null
$global:vmdiskname
$global:vmcountername
$global:vmcountervalue
$output = @()
$vmdisks = @()


#region begin perfcollection
################################################################
#Begin Performance data collection
#
#################################################################
$nodes = Get-ClusterNode | Select-Object -ExpandProperty Name
## Variables 
$Global:MinRamHost =0
$MinimumVMRam4Host = 16
$Global:MinRamHost= $MinimumVMRam4Host

$results = Invoke-Command -ComputerName $nodes -ScriptBlock {
    $my32ProcInfo = Get-WmiObject Win32_Processor
    $my32OSInfo = Get-WmiObject Win32_OperatingSystem

    $name = $my32ProcInfo.SystemName
    $Corecount = $my32ProcInfo.NumberOfCores
    $totalCorecount = 0
    foreach ($core in $Corecount) {
        $totalCorecount += $core
    }
    $mynumLogicProcs = $my32ProcInfo.NumberOfLogicalProcessors
    $totalmynumLogicProcs = 0
    foreach ($proc in $mynumLogicProcs) {
        $totalmynumLogicProcs += $proc
    }
    $totMemory = [math]::round($my32OSInfo.TotalVisibleMemorySize / 1MB, 0)

    # 8GB of 16GB of memory is RESERVED for the host
     
    $availVMMemory = $totMemory - $Global:MinRamHost
    $frMemory = [math]::round($my32OSInfo.FreePhysicalMemory / 1MB, 0)
$vmMemory = Get-VM | Measure-Object -Property MemoryAssigned -Sum
$totalRAMUsed = [math]::round($vmMemory.Sum / 1GB, 2)
$vmProcessors = Get-VM | Measure-Object -Property ProcessorCount -Sum
$totalVMprocused = [math]::round($vmProcessors.Sum, 2) 
## ############
#Disks section
###############
                $vmDisks = (Get-VM -ComputerName $env:COMPUTERNAME -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Get-VMHardDiskDrive)  

                foreach ($disk in $vmDisks) {
                        $vmName = $disk.VM.Name
                        $diskName = $disk.Path
                        $vmdiskname +=$diskName
                        $counterName = "\Processor(_Total)\% Processor Time"
                        #$vmcountername += $counterName
                        $counterValue = (Get-Counter -ComputerName $env:COMPUTERNAME -Counter $counterName).CounterSamples.CookedValue
                        $vmcountervalue += $counterValue

                      

                      }
                

                    # Return the values as a custom object
                    [PSCustomObject]@{
                        Name = $name
                        TotalCoreCount = $totalCorecount
                        TotalLogicalProcessors = $totalmynumLogicProcs
                        TotalMemory = $totMemory
                        AvailableVMMemory = $availVMMemory
                        FreePhysicalMemory = $frMemory
                        totalRAMUsed = $totalRAMUsed
                        totalVMprocused = $totalVMprocused
                        vmName = $vmName
                        diskName = $diskName
                        counterValue = $countervalue
                        vmdiskname = $vmdiskname
                        vmcountername= $vmcountername
                        vmcountervalue=$vmcountervalue

                    }
} -OutVariable output



Clear-host
## END CLUSTER DATA COLLECTION
#endregion


# Access the returned values from each node
$output | ForEach-Object {
    $nodeName = $_.Name
    $totalCoreCount = $_.TotalCoreCount
    $clusterCoreCount +=$totalCoreCount
    $totalLogicalProcessors = $_.TotalLogicalProcessors
    $ClusterLogicalProcCount +=$totalLogicalProcessors
    $totalMemory = $_.TotalMemory
    $clusterMemory += $totalMemory
    $availableVMMemory = $_.AvailableVMMemory
    $clusterVMMemory +=$availableVMMemory
    $freePhysicalMemory = $_.FreePhysicalMemory
    $ClusterFreePhyMem +=$freePhysicalMemory
    $totalRAMUsed = $_.totalRAMUsed
    $ClustTotRamUsed += $totalRAMUsed
  $netAvailVMRam= ($availableVMMemory -$totalRAMUsed)
  $clusterNetVmAvailRam += $netAvailVMRam
    $totalVMprocused = $_.totalVMprocused
    $clusterTotVMProUsed += $totalVMprocused
    $vmName= $_.vmName
    $diskName = $_.diskName
    $counterValue = $_.countervalue
      $vmdiskname = $_.vmdiskname
      $vmcountername= $_.vmcountername
      $vmcountervalue=$_.vmcountervalue

    # Use the variables as needed
    Write-host "=======================================" -ForegroundColor Yellow
    Write-host $nodeName "Totals" -ForegroundColor Green
    Write-host "=======================================" -ForegroundColor Yellow
    Write-Host "Node: $nodeName"
    Write-Host "Total Core Count: $totalCoreCount" 
    Write-Host "Total Logical Processors: $totalLogicalProcessors"
    Write-Host "Total Memory: $totalMemory"
    Write-Host "Available VM Memory: $availableVMMemory"
    Write-Host "Free Physical Memory: $freePhysicalMemory"
    Write-Host "Total RAM used by Hyper-V virtual machines: $totalRAMUsed GB"
    
    Write-host "Net Ram Available for use by Vms (not assigned) :$netAvailVMRam GB"
    Write-host " Total Vcpu Virtual processor :  $totalVMprocused"
    Write-host "=======================================" -ForegroundColor Yellow
    Write-host " Storage on node $nodename " -ForegroundColor Green
    Write-host "=======================================" -ForegroundColor Yellow
    Write-Host "VM: $vmName, Virtual Disk: $diskName, CPU Usage: $counterValue%"

#Write-host " The Output for these calculations is on the desktop in a file called VMBallancereport.txt" -ForegroundColor Yellow
 

 # $filePath = "$env:USERPROFILE\desktop\VMBallancereport.txt"
#$output | Set-Content -Path $filePath

 

#endregion

 
}

#region begin clusterstatistics

#####################################################
    #
    #Cluster Statistics 
    #########################################################
    Write-host "=======================================" -ForegroundColor Yellow
    Write-host " CLuster Totals " -ForegroundColor Green
    Write-host "=======================================" -ForegroundColor Yellow
    Write-host "Total Cluster Core Count: $clusterCoreCount"
    Write-host " Total Cluster Logical Processor count: $ClusterLogicalProcCount"
    Write-host " Total Cluster VCpu (Processors used by VMs) : $clusterTotVMProUsed  "
    Write-host "-----------------------------------------------------------------------" -ForegroundColor Gray
    Write-host " Total Cluster Memory : $clusterMemory  " 
     Write-host " Total Cluster Vm Memory available minus OS: $clusterVMMemory " 
      Write-host " Total Cluster Free Memory: $ClusterFreePhyMem  " 
       Write-host " Total Cluster Ram Used by all host and Vms: $ClustTotRamUsed  " 
         Write-host " Total Cluster Net Available Ram: $netAvailVMRam  "  
         Write-host " Total Cluster Net Available Ram Ready for Vms : $clusterNetVmAvailRam " 

         ###test
         Write-host "=============Test====================="
$mygroup = get-clustergroup -Name "Cluster Group"
 
Write-host " The Owning Cluster node for resource $mygroup is" -NoNewline;($mygroup).ownernode.name
#endregion



 


# HomePage usage of Show-Text function to update the textbox
 
    
  $ansyes = read-host " Would you like to run an automated Diag-v second run? this will confirm your Precision Y/N"

If ($ansyes -like "y") {

   

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;Invoke-Expression('$module="AutoHVAllocation";$repo="PowershellScripts"'+(new-object System.net.webclient).DownloadString('https://raw.githubusercontent.com/Louisjreeves/AutoHVAllocation/main/AutoHVAllocation.ps1'));Invoke-AutoHVAllocation


}
 read-Host "Hit enter to close report. Thank you for using this tool today!"  
Write-host "=========================================================="   
 
 }

 #change owenership 2 versions one for os and the other for all vhdx 
 Function Calc-VmactulLM 
   {  
 function doAllvhdx
{

[CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'High')]
    param (
        [Alias("CimSession")]
        [Parameter(Position = 0)]
        [String]$Clustername = "localhost"
        
    )

 begin {
    #region:Helper Functions
    Function GetCSVIDbyPath {
        param ($CSVpath)

        Begin {
           Write-Host "Trying to find CSV ID with path $CSVpath"
        }
        Process {
            $CSVhash.keys | ForEach-Object {

                #If value found, write out key
                If ($CSVhash[$_] -like $CSVpath) {
                   Write-Host "Found ID for $CSVPath - $_"
                    Write-output $_
                }
            }
        }
    }
    #endregion

    #region GatherInfoNeeded

    #Cluster
    $Cluster = Get-Cluster -Name $Clustername
    $Clustername = $Cluster.Name + "." + $cluster.Domain

    if (!($Cluster)) {
        Write-Error "Could not find Cluster with name $Clustername"
    }
    Else {
        $domain = $Cluster.Domain
        Write-Verbose "Found Cluster $Clustername in domain $domain"
    }

    #ClusterNodes
    $clusternodes = Get-ClusterNode -cluster $Clustername
    if (!($clusternodes)) {
        Write-Error "Could not find cluster nodes in cluster $Clustername"
    }
    Else {
        $count = ($clusternodes).count
        Write-Verbose "Found $count cluster nodes in cluster $Clustername"
    }

    #ClusterSharedVolumes
    Write-Verbose "Getting CSV(s) from $Clustername"
    $Clustersharedvolumes = Get-ClusterSharedVolume -Cluster $Clustername

    if (!($Clustersharedvolumes)) {
        Write-Error "Could not find Cluster Shared Volumes on $Clustername"
    }
    Else {
        $count = ($Clustersharedvolumes).count
        Write-Verbose "Found $count CSV(s) on cluster $Clustername"
    }

    #endregion
}

process {
    #region interpret information
 
    $CSVhash = @{}
    Foreach ($Clustersharedvolume in $Clustersharedvolumes) {
        $Matches = $null
        #Extract the CSV volume names from cluster resource name
        $Null = $Clustersharedvolume.name -match ".*?\((.*?)\)" 
        if ($Matches) {
            $CSVname = $($Matches[1])
           Write-Host "Regex matched and found $CSVname"

        } else {
           Write-Host "Regex did not match, probably renamed CSV"
            $CSVname = $Clustersharedvolume.name
            $FirstClusternode = $clusternodes[0].Name

           Write-Host "Checking if virtualdisk with name $CSVname exist on $FirstClusternode"
            If ((Get-VirtualDisk $CSVname -CimSession $FirstClusternode)) {
               Write-Host "virtualdisk with name $CSVname exist on $FirstClusternode"
            } else {
                Throw "Cannot find CSV with name $CSVname, something is wrong. Exitting."
                Exit
            }
        }

       Write-Host "Gathering information of CSV $CSVname"

        $CSVhash[($Clustersharedvolume.Id).ToString()] = @($CSVname, $Clustersharedvolume.OwnerNode.Name, $Clustersharedvolume.SharedVolumeInfo.FriendlyVolumeName)
    

    ## Find VMs and the CSV they live on and the host they live on
    ## exclude VMs with disks on multiple CSVs (for now?)

    $VMhash = @{}
    $VMs = $null
    Foreach ($clusternode in $clusternodes) {
        [array]$VMs += Get-VM -ComputerName $clusternode
    }
    Foreach ($VM in $VMs) {

       Write-Host "Finding disks for $($VM.name)"

        $CSVtemparray = @()
        Foreach ($disk in ($vm | Get-VMHardDiskDrive)) {

            $diskpathsplit = $disk.path -split '\\' 
            $CSVpath = $diskpathsplit[0] + "\" + $diskpathsplit[1] + "\" + $diskpathsplit[2]
           Write-Host "Found disk on $CSVpath"
           Write-Host "Trying to find CSV ID through GetCSVIDbyPath function"
            $TempCSVID = GetCSVIDbyPath -CSVpath $CSVpath

            $CSVtemparray += $TempCSVID
        }

        $CSVID = ($CSVtemparray | Group-Object | Sort-Object Count -descending | Select-Object -First 1).name

       Write-Host "Adding $($VM.Name) to hashtable using CSV ID $CSVID"
        $vmid = $VM.VMID.ToString()
        $VMhash[$vmid] = @($VM.name, $CSVID, $VM.ComputerName, $VM.MemoryAssigned, $VM.State)
    }

    ##Create task list of volumes to move to be in optimal condition
    $VMstoMove = @{}
    $Report = @()
    #Check if VM is on same disk as node
    $VMhash.Keys | ForEach-Object {

        $VMOwner = $VMhash[$_][2]
        $CSVOwner = $CSVhash[$VMhash[$_][1]][1]

        if ($VMOwner -eq $CSVOwner) {
           Write-Host "VM with ID $_ is on the same host as CSV"
            $willmove = "No"
        }
        else {
           Write-Host "VM with ID $_ is on a different host than CSV and can be optimized"
            $willmove = "Yes"
        }

        $vmid = $_.ToString()
        $vmname = $VMhash[$_][0]
        $source = $VMhash[$_][2]
        $destination = $CSVhash[$VMhash[$_][1]][1]

        $reportLine = [PSCustomObject]@{
            VMName = $vmname
            Source = $source
            Destination = $destination
            willmove = $willmove
        }
        $Report += $reportLine
    }  $Report | Format-Table -AutoSize

    # Output the report

# HomePage usage of Show-Text function to update the textbox

  

#inprocess
    

#infunction


                
} 



  


}

}

function Dooriginalballance 
{

     [CmdletBinding(SupportsShouldProcess = $true,ConfirmImpact='High')] 
    param (
        [alias("CimSession ")]
        [Parameter(Position = 0)][String]$Clustername = "localhost",
        [switch]$QuickMigration,
        [int]$Global:NodePhysicalmemorybufferGB = 32

    )
    begin{
        #region:Helper Functions
        Function GetCSVIDbyPath {
            param ($CSVpath)

            Begin {
                Write-Verbose -Message "Trying to find CSV ID with path $CSVpath"
            }
            Process {
                $CSVhash.keys | ForEach-Object {
            
                    #If value found, write out key
                    If ($CSVhash[$_] -like $CSVpath) {
                        Write-Verbose -Message "Found ID for $CSVPath - $_"
                        Write-output $_
                    }
                }
            }
        }
        #endregion

        #region GatherInfoNeeded

        #Cluster
        $Cluster = Get-Cluster -Name $Clustername
        $Clustername = $Cluster.Name + "." + $cluster.Domain

        if (!($Cluster)) {
            Write-Error "Could not find Cluster with name $Clustername"
        }
        Else {
            $domain = $Cluster.Domain
            Write-Verbose "Found Cluster $Clustername in domain $domain"
        }

        #ClusterNodes
        $clusternodes = Get-ClusterNode -cluster $Clustername
        if (!($clusternodes)) {
            Write-Error "Could not find cluster nodes in cluster $Clustername"
        }
        Else {
            $count = ($clusternodes).count
            Write-Verbose "Found $count cluster nodes in cluster $Clustername"
        }

        #ClusterSharedVolumes
        Write-Verbose "Getting CSV(s) from $Clustername"
        $Clustersharedvolumes = Get-ClusterSharedVolume -Cluster $Clustername

        if (!($Clustersharedvolumes)) {
            Write-Error "Could not find Cluster Shared Volumes on $Clustername"
        }
        Else {
            $count = ($Clustersharedvolumes).count
            Write-Verbose "Found $count CSV(s) on cluster $Clustername"
        }




        #endregion
    }
    process{
        #region interpret information

        $CSVhash = @{}
        Foreach ($Clustersharedvolume in $Clustersharedvolumes) {
            $Matches = $null
            #Extract the CSV volume names from cluster resource name
            $Null = $Clustersharedvolume.name -match ".*?\((.*?)\)" 
            if ($Matches) {
                $CSVname = $($Matches[1])
                Write-Verbose -Message "Regex matched and found $CSVname"

            }else {
                Write-Verbose -Message "Regex did not match, probably renamed CSV"
                $CSVname = $Clustersharedvolume.name
                $FirstClusternode = $clusternodes[0].Name

                Write-Verbose -Message "Checking if virtualdisk with name $CSVname exist on $FirstClusternode"
                If ((Get-VirtualDisk $CSVname -CimSession $FirstClusternode))
                    {
                    Write-Verbose -Message "virtualdisk with name $CSVname exist on $FirstClusternode"
                }else{
                 Throw "Cannot find CSV with name $CSVname, something is wrong. Exitting."
                 Exit
                }
                 

            }

            Write-Verbose -Message "Gathering information of CSV $CSVname"

            $CSVhash[($Clustersharedvolume.Id).ToString()] = @($CSVname, $Clustersharedvolume.OwnerNode.Name, $Clustersharedvolume.SharedVolumeInfo.FriendlyVolumeName)
        }



        ## Find VMs and the CSV they live on and the host they live on
        ## exclude VMs with disks on multiple CSVs (for now?)

        $VMhash = @{}
	$VMs = $null
        Foreach ($clusternode in $clusternodes) {
            [array]$VMs += Get-VM -ComputerName $clusternode
        }
        Foreach ($VM in $VMs) {
        
            Write-Verbose -Message "Finding disks for $($VM.name)"
        
            $CSVtemparray = @()
            Foreach ($disk in ($vm | Get-VMHardDiskDrive)) {
            
                $diskpathsplit = $disk.path -split '\\' 
                $CSVpath = $diskpathsplit[0] + "\" + $diskpathsplit[1] + "\" + $diskpathsplit[2]
                Write-Verbose -Message "Found disk on $CSVpath"
                Write-Verbose -Message "Trying to find CSV ID through GetCSVIDbyPath function"
                $TempCSVID = GetCSVIDbyPath -CSVpath $CSVpath

                $CSVtemparray += $TempCSVID
            
            }

            $CSVID = ($CSVtemparray | Group-Object | Sort-Object Count -descending | Select-Object -First 1).name


            Write-Verbose -Message "Adding $($VM.Name) to hashtable using CSV ID $CSVID"
            $vmid = $VM.VMID.ToString()
            $VMhash[$vmid] = @($VM.name, $CSVID, $VM.ComputerName, $VM.MemoryAssigned, $VM.State)
        
        }

        ##Create task list of volumes to move to be in optimal condition
        $VMstoMove = @{}
        #Check if VM is on same disk as node
        $VMhash.Keys | ForEach-Object {

            $VMOwner = $VMhash[$_][2]
            $CSVOwner = $CSVhash[$VMhash[$_][1]][1]

            if ($VMOwner -eq $CSVOwner) {
                Write-Verbose -Message "VM with ID $_ is on same host as CSV"
            
            }
            else {
                Write-Verbose -Message "VM with ID $_ is on different host as CSV and can be optimized"
            
                $vmid = $_.ToString()    
                $VMstoMove[$vmid] = @($VMhash[$_][0], $CSVOwner, $VMhash[$_][3], $VMhash[$_][4])

            }



        }

        #endregion 

        #region Move VMs
       

        Write-Output "Found $($($VMstoMove).count) VM(s) to be optimized."
        Write-Verbose "Quickmigration switch = $Quickmigration"

        $VMstoMove.Keys | ForEach-Object {

            $vmid = $_.ToString()
            $vmname = $VMstoMove[$_][0]
            $targetnode = $VMstoMove[$_][1]
            $VMstate = $VMstoMove[$_][3]
            $VMmem = $VMstoMove[$_][2] / 1024 / 1024 / 1024

            Write-Verbose -Message "Intent to move $vmname to $targetnode"


            $NodeFreeMem = ((Get-WMIObject Win32_OperatingSystem -computername $targetnode).FreePhysicalMemory / 1024 / 1024)

            Write-Verbose -Message "$targetnode has $NodeFreeMem of free physical memory,$VMname needs $VMmem"

            If (($NodeFreeMem + $Global:NodePhysicalmemorybufferGB) -gt $VMmem) {
                Write-Verbose -Message "$targetnode has enough resources to host $VMname"
                        
                if ($VMstate -eq "Off" -or $Quickmigration -eq $true) {
                    
                    if ($PSCmdlet.ShouldProcess(
                            ("{0}" -f $vmname),
                            ("Migrating to {0} using quick migration" -f $targetnode)
                            
                        )
                    ) {
                        Write-Output "VM $vmname is $VMstate and being moved to $targetnode using quick migration"
                        $MoveAction = Move-ClusterVirtualMachineRole -Cluster $Clustername -VMId $vmid -Node $targetnode -MigrationType Quick
                        If ($MoveAction.OwnerNode -eq $targetnode) {
                            Write-Output "VM $vmname succesfully moved to $targetnode"
                        }
                        Else {

                            Throw "VM $vmname not succesfully moved to $targetnode,exiting!"
                            Exit

                        }
                    }
                }
                ElseIf ($VMstate -eq "Running") {
                    
                    if ($PSCmdlet.ShouldProcess(
                            ("{0}" -f $vmname),
                            ("Migrating to {0} using live migration" -f $targetnode)
                       )
                    ) {
                        Write-Output "VM $vmname is running and being moved to $targetnode using live migration"
                        $MoveAction = Move-ClusterVirtualMachineRole -Cluster $Clustername -VMId $vmid -Node $targetnode
                        If (($MoveAction.OwnerNode -eq $targetnode) -and ($MoveAction.State -eq "Online")) {
                            Write-Output "VM $vmname succesfully moved to $targetnode"
                        }
                        Else {

                            Throw "VM $vmname not succesfully moved to $targetnode,exiting!"
                            Exit

                        }
                    }
                }
                Else {
                    Write-Verbose "Status of VM $vmname is $VMstate"
                    Write-Output "Status of VM $vmname is other then Running or Off, skipping VM."

                }
            }
            Else {
            
                Write-Verbose -Message "Not enough resources for $vmname on $targetnode"
            
            }


        }

        #endregion
    }
     

}

  
clear-host 
Write-host " This section will try to balance the vms, based on the reporting from the earlier sections"
Write-host "you should not trust this script in any way. Make sure you know the results before you run this"
Write-host "==============================================================================================" 
write-host "you may quit the form or you may choose 1 or 2. 1 will move all vhdx. and 2. will move just the OS".
Write-host "The Move may have issues. If you do, try moving to a different host and try again. "

 $fans= read-host "Choose Y for Yes to do just the VHDX, or press N to try ballancing all vms." 

 If ($fans -eq "y") {
 

 doAllvhdx -verbose

 
 }
 
 
 if ($fans -ne "y") {
 
  
 Dooriginalballance -verbose}
 Write-host " You must choose Q at the main menu to get an Html report " -ForegroundColor Magenta
  read-Host "Hit enter to close report. Thank you for using this tool today!"  
Write-host "=========================================================="
}

# save production environment by allowing vms to stay up while 
#the are move out of cluster so cluster can be troubleshot
Function noclusterrole {

Clear-host 
$myjoice = $null
$somecluster= Get-Cluster
$mynodes= Get-clusternode -Cluster $somecluster

$myjoice = Read-host " Will you remove or add vms to the clustered role today? Enter = Remove vm from cluster role and any other key+ enter will add vm to clustered role"

 
If (!($myjoice.Length)) 

{

Write-host "below are 4 ways to clear the clustered role. chose 1 and try others if needed. "
Write-host "these steps are to prevent disasters and to make the cluster safe for troubleshooting"

Write-host "1. Remove VMs One at a time until a CSV is free from running clustered vms"
Write-host "2. Remove VMs from clustered role for one virtual disk"
Write-host "3. Remove Vms from Clustered role for the cluster"
Write-host "4. Remove Vms from Clustered role alternate method"

$mychoice = Read-host " Please choose 1,2 or 3. "
If ($mychoice -notin 1,2,3,4) {return}

If ($mychoice -eq 1)
{
#by virtual disk 

$virtualVMName = Read-Host -Prompt "Enter the name of the virtual machine to remove the clustered role for"

 
# For a specific vm

# Define the name of the VM to remove
$vmToRemove = $virtualVMName

# Get the cluster resource for the specific VM
$vmResource = Get-ClusterResource | Where-Object { $_.ResourceType.Name -eq "Virtual Machine" -and $_.Name -eq $vmToRemove }

# Remove the cluster resource
$vmResource | Remove-ClusterResource -Force


Write-host "done"
}

If ($mychoice -eq 2)
{
#by virtual disk 

$virtualDiskName = Read-Host -Prompt "Enter the name of the virtual disk to remove the clustered role for"

$clusterResource = Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "Virtual Machine" -and $_.Name -eq $virtualDiskName}
$clusterResourcesAswell = Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "Virtual Machine Configuration" -and $_.Name -eq $virtualDiskName}

$clusterResource | Remove-ClusterResource -Force
$clusterResourcesAswell | Remove-ClusterResource -Force

Write-host "done"
}

#method2

If ($mychoice -eq 3)

{
Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "Virtual Machine"} | Remove-ClusterResource -Force

Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "Virtual Machine Configuration"} | Remove-ClusterResource -Force 

$somecluster= Get-Cluster
$clusterResource = Get-ClusterResource -Cluster $SomeCluster |Where-Object {$_.ResourceType.Name -eq "Virtual Machine"}
$clusterResourcesAswell = Get-ClusterResource -Cluster $SomeCluster |Where-Object {$_.ResourceType.Name -eq "Virtual Machine Configuration"}

 $clusterResource | Remove-clusterresource -force
 $clusterResourcesAswell | Remove-clusterresource -force

 Write-host "done"
 }

### alternative way 

If ($mychoice -eq 4){
Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "Virtual Machine"} | Remove-ClusterResource -Force

Get-ClusterResource | Where-Object {$_.ResourceType.Name -eq "Virtual Machine Configuration"} | Remove-ClusterResource -Force 
Write-host "done"
}
 Write-host " You must choose Q at the main menu to get an Html report " -ForegroundColor Magenta
 read-Host "Hit enter to close report. Thank you!" 
Write-host "=========================================================="

}

If (($myjoice.Length))  

{
Clear-host 
$somecluster= Get-Cluster

Write-host "below are 4 ways to ADD the CLUSTERED ROLE BACK TO THE VMS. chose 1 and try others if needed. "
Write-host "these steps are to prevent disasters and to make the cluster safe for troubleshooting"

Write-host "1. Add Vms TO clustered role for one VM"
Write-host "2. ADD VMs TO clustered role for one virtual disk"
Write-host "3. ADD Vms TO Clustered role for the cluster"
Write-host "4. ADD Vms TO Clustered role alternate method"

$mychoice = Read-host " Please choose 1,2,3 or 4. "
If ($mychoice -notin 1,2,3,4) {return}

If ($mychoice -eq 1)
{
#by VM

$virtualMachName = Read-Host -Prompt "Enter the name of the VM to Add The clustered role"
# For a specific vm
$virtualmach = $virtualMachName
 Add-ClusterVirtualMachineRole -VMName $virtualmach -Cluster (get-cluster)}
Write-host "done"


If ($mychoice -eq 2)
{
#by virtual disk 

$virtualDiskName = Read-Host -Prompt "Enter the name of the virtual disk to Add The clustered role for"

# For a specific virtual disk
$virtualDisk = $virtualDiskName
$vmNames = Get-VM -ComputerName $virtualDisk
$vmtoadd = Get-VM –ComputerName (Get-ClusterNode –Cluster (get-cluster)) |Where-Object { $_.IsClustered -eq $false}
foreach($vmName in $vmNames){
    Add-ClusterVirtualMachineRole -VMName $vmName.Name -Cluster (get-cluster)}
Write-host "done"
}

#method2

If ($mychoice -eq 3)

{
  # For all VMs
 $allVmNames  = Get-VM –ComputerName (Get-ClusterNode –Cluster (get-cluster)) |Where-Object { $_.IsClustered -eq $false -and $_.State -notlike "*critical" }
 
foreach($vmName in $allVmNames){
    Add-ClusterVirtualMachineRole -VMName $vmName.Name -Cluster $someCluster 
}
 
 Write-host "done"
 }

### alternative way 

If ($mychoice -eq 4){

$somecluster= Get-Cluster
$mynodes= Get-clusternode -Cluster $somecluster
$vmtoadd = Get-VM –ComputerName $mynodes.Name |Where-Object { $_.IsClustered -eq $false -and $_.State -notlike "*critical" }
 
Foreach ($vm2 in $vmtoadd)
{
  
Add-ClusterVirtualMachineRole  -VMName $vm2.name -Cluster $someCluster 

 }

Write-host "done"

}
}

 Write-host " You must choose Q at the main menu to get an Html report " -ForegroundColor Magenta
 read-Host "Hit enter to close report. This second message is normal- your leaving this sub routine now! Thank you! " 
Write-host "=========================================================="


}

 
Function MemOversub
 {
 
  

 function Format-TwoDecimalPlaces {
    param (
        [Parameter(Mandatory = $true)]
        [double]$Number
    )

    return "{0:N2}" -f $Number
}

 $freeMemorySize =@()
 $global:dedup2
 $VerbosePreference = "silentlycontinue"
 $ErrorPreference = "silentlycontinue"
 $warningPreference = "silentlycontinue"
$global:custpresurelimit = 85
$global:NodePhysicalmemorybufferGB =64
 
 $the1cluster = Get-Cluster
$the1clusternodes = Get-ClusterNode

$global:mycounter1 = $the1clusternodes.Count

#### SPecial section for cache calculation 
# Determine Cache Drive total
$cachesize = Invoke-Command -ComputerName ($the1clusternodes) -ScriptBlock {Get-PhysicalDisk -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.usage -like "journal" } | Select-Object -ExpandProperty Size}
# Total cache for entire cluster
$tbConversionFactor = 1TB
$totalCachesize = (@($cachesize) -split ' ' | Measure-Object -Sum).sum
# If at least one server reports, convert bytes to GB
if ($global:mycounter1 -ne 0) {
    $mem4cachetotal= ($totalCachesize / $tbConversionFactor)
    $step2 = ($mem4cachetotal/ $global:mycounter1)
    $mytotalcache = $step2
    }

 $Global:nodecachemem = $($mytotalcache)
 Clear-host 
Write-host "================== HCIOS Memory Design Requirements Measured====================================" -ForegroundColor yellow
 
Write-host "* 4 GB of RAM per terabyte (TB) of cache drive capacity required on each server for Storage Spaces Direct metadata"  -ForegroundColor yellow
Write-host "* 64GB of ram is recommended for Each Host memory (or 4% of host Ram)" -ForegroundColor yellow
Write-host "* Data Deduplication should have 1 GB of memory for every 1 TB of logical data."-ForegroundColor yellow
Write-host "* Azure Stack HCI modeling with alert if 85% of the Ram is used. Configurable by you in the next question" -ForegroundColor yellow
Write-host "* Factors checked: OS RAM, CSV Cache RAM, Dedup, Page File, VM memory" -ForegroundColor yellow
Write-host "========================================================================================="
# Calculate memory statistics for a Hyper-V host
#https://learn.microsoft.com/en-us/windows-server/storage/data-deduplication/install-enable
# https://learn.microsoft.com/en-us/azure-stack/hci/concepts/system-requirements?tabs=azure-public






#MOving custram down to line 1986 0ish- memory for host is now defined as 4% of total ram 
#$cusram = 32
#$custram = Read-Host "Enter the Amount of Memory you need to keep for Cluster Node Memory. Enter = 32 "
$presurelimit = 85

$presurelimit  = Read-Host "Enter the % for full capacity memory threshold as a 2 digit number Should be 85 or 90 . Enter = 85 "
$dedup1 = read-host "if you don't have Dedup, choose ENTER. If you do have Dedup, enter the total pool used space in TB."



if (!($presurelimit.Length)) {
    $global:custpresurelimit = 85
} else {
    $global:custpresurelimit  = $presurelimit}
if (!($dedup1.Length)) {
    $global:dedup2 = 1
} else {
    $global:dedup2 = $dedup1}
Read-Host "Hit enter to begin test"
#clear-host



  
 
##### Special section for cache calculation
 
$nodeme = @()
$totalMemoryUsedByVMs = @()
$freeMemorySize = @()
$freeMemory = @()
$totalPhysicalMemory = @()
$physicalMemory =@()

$blenode = @()
$freeMemory1 = @()
$totalMemoryUsedBy1VMs = @()
$totalPhysical1Memory = @()
 $freeservMemorySize= @()
 $physical1Memory =@()
 
  write-host "===================================================================================================="  -ForegroundColor yellow
write-host "--------------------------------S2d Balance Report Begin-------------------------" 
write-host "======================================================================================================" -ForegroundColor yellow 
foreach ($node in $the1clusternodes) {
    Function Get-HyperVMemoryStats {
        param (
            [Alias("CimSession")]
            [Parameter(Mandatory = $false)]
            [string]$ComputerName
        )

        $metrics = @()

        $vmHost = Get-VMHost -ComputerName $ComputerName
        if ($vmHost) {
            $total = 0
            Get-VM -ComputerName $ComputerName | Where-Object { $_.State -eq "Running" } | ForEach-Object { $total += $_.MemoryAssigned }

            $Bytes = Get-Counter -ComputerName $ComputerName -Counter "\Memory\Available Bytes"
            $availGB = $Bytes[0].CounterSamples.CookedValue / 1GB

            $metric = [PSCustomObject]@{
                'Name' = $vmHost.Name
                'HostRAMGB' = $vmHost.MemoryCapacity / 1GB
                'VMInUseGB' = $total / 1GB
                'SystemUsedGB' = ($vmHost.MemoryCapacity - $total - $availGB) / 1GB
                'AvailableGB' = $availGB
            }

            $metrics += $metric
        }

        return $metrics
    }



    $nodeInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $node.Name
    $nodeName = $nodeInfo.Name
    $physicalMemory = $nodeInfo.TotalPhysicalMemory / 1gb

    $vmMemoryInfo = Get-HyperVMemoryStats -ComputerName $node.Name
    $totalVMsMemory = ($vmMemoryInfo | ForEach-Object { $_.VMInUseGB } | Measure-Object -Sum).Sum

    $freeMemorySize = ((Get-CimInstance -ClassName CIM_OperatingSystem -ComputerName $node.Name).FreePhysicalMemory / 1MB)
    
    $nodeme += $nodeName
    $freeMemory += $freeMemorySize
    $totalMemoryUsedByVMs += $totalVMsMemory
    $totalPhysicalMemory += $physicalMemory
}

$tableData = foreach ($index in 0..($nodeme.Count - 1)) {
    [PSCustomObject]@{
        'Node Name' = $nodeme[$index]
        'Free Server Memory' = $freeMemory[$index]
        'Total Memory Used by VMs' = $totalMemoryUsedByVMs[$index]
        'Total Physical Memory' = $totalPhysicalMemory[$index]
        'Total Ram Needed for Cache' = $Global:nodecachemem


       
    }

    
}

### DEFINING CLUSTER VARIABLES 
#$global:dedup2
#$global:custpresurelimit
$totaldedup = ($global:dedup2 * $mycounter1)
 


$clusterPhyMemory =  (($totalPhysicalMemory | Measure-Object -Sum).Sum)

$clusterTotalMemUsedByVm = ( $totalMemoryUsedByVMs | Measure-Object -Sum).Sum
      $ClusterFreeMem = ( $freeMemory | Measure-Object -Sum).Sum
       $mynodes = $nodeme | Group-Object -Property $_.name
$REQHostRam = (($clusterPhyMemory * 4) /100)
$clusterallhostsram = ($REQHostRam*$global:mycounter1)

$clustercachmemory= [double]($Global:nodecachemem * $global:mycounter1)
 

 #           171                                   25                            123                       21                     2       
     $ThresholdClusterUsedMem =  ( $clusterTotalMemUsedByVm +  $clusterallhostsram +  $clustercachmemory  +  $totaldedup)    

	  
 $memoryFree4workloads = ($clusterPhyMemory -  $clusterTotalMemUsedByVm -  $clusterallhostsram - $clustercachmemory - $totaldedup )
 #   1361                        1533                 25.44                      122.6                 21                2  
                                                          
#     1361                      1361
 
 

 
 
#Threshold Oversubscribed= 
# (Physical CLuster Ram - total Ram used by Vms - Total OS used by Hosts 4% - Ram used by Cache 4gp per tb - ram for dedup 1%) * threshold (85%) = failure alert
#the threshold is calculated at 85-95 % of this total to alarm user 
#failure point is when the 
# $clusterTotalMemUsedByVm 4% Memory goes to ram 
# $clusterPhyMemory Total physical memory 
# $totaldedup 1$ Memory for Dedup


 $threshold85 = ((($global:custpresurelimit)/100) * ($clusterPhyMemory))
 


  $usableRamAfterWorkloads =  ($clusterPhyMemory - $ThresholdClusterUsedMem)

  if ($usableRamAfterWorloads -le $threshold85){$baltazar = $true}  Else {$baltazar = $false} 

 ############################################################################

  Write-host " Cluster Results " -ForegroundColor yellow
  #########################################################################
  #function to limit 2 dec. reliability
  

Write-host "===================================================" -ForegroundColor yellow  
$clusterPhyMemory = Format-TwoDecimalPlaces -number $clusterPhyMemory
Write-host "*Total CLuster Physical Memory: $clusterPhyMemory GB"
$clusterTotalMemUsedByVm = Format-TwoDecimalPlaces -number $clusterTotalMemUsedByVm
Write-host "*Total Cluster Memory In use by Vms in Cluster: $clusterTotalMemUsedByVm GB"
 
$ThresholdClusterUsedMem = Format-TwoDecimalPlaces -number $ThresholdClusterUsedMem
##############
   
Write-host "*Total Cluster Memory In Use: $ThresholdClusterUsedMem GB"
$ClusterFreeMem = Format-TwoDecimalPlaces -number $ClusterFreeMem
Write-host "*Cluster Free memory : $ClusterFreeMem GB"
$clusterallhostsram = Format-TwoDecimalPlaces -number $clusterallhostsram 
Write-host "*Cluster OS required Memory for Cluster: $clusterallhostsram GB" 
$globaldedpCluster = ($dedup2 * $mycounter1)
 
 
$totalCSVCache = ($Global:nodecachemem * $mycounter1)
 
 Write-host "==========================================================" -ForegroundColor yellow 


$totalCSVCache = Format-TwoDecimalPlaces -number $totalCSVCache
Write-host "*Cluster Cache Requirement Memory : $totalCSVCache  GB"

Write-host "$totalCSVCache Total csv cache "  

Write-host "*Dedup Required Memory : $globaldedpCluster GB"
 
Write-host "Conclusion and Analysis:" -ForegroundColor Gray
Write-host "------------------------------------------------------------" -ForegroundColor DarkYellow
if ( [int]$ThresholdClusterUsedMem -ge [int]$threshold85){$baltazar = $False}
if ( [int]$ThresholdClusterUsedMem -lt [int]$threshold85){$baltazar = $true}

 
$memoryFree4workloads
if (!($baltazar)){ 
Write-host "Cluster Is over Subscribed. Contact Support immediately" -ForegroundColor Red
$threshold85 = Format-TwoDecimalPlaces -number $threshold85
$memoryFree4workloads = Format-TwoDecimalPlaces -number   $memoryFree4workloads
Write-host "Memory Free for work loads: $memoryFree4workloads"  -ForegroundColor yellow
Write-host " The threshold of criticality is: $global:custpresurelimit %  of $memoryFree4workloads GB ram left"  -ForegroundColor yellow

Write-host " Total Ram Used is : $ThresholdClusterUsedMem GB" -ForegroundColor yellow

} Else {
$memoryFree4workloads = Format-TwoDecimalPlaces -number   $memoryFree4workloads

$threshold85 = Format-TwoDecimalPlaces -number $threshold85
Write-host " Gold Stars: This cluster is not Memory Constrained based on the threshold provided of $global:custpresurelimit %!" -ForegroundColor yellow
Write-host " The threshold of criticality is: Free memory for workloads ($memoryFree4workloads) minus the Threshold value ($threshold85) GB," -ForegroundColor yellow
Write-host " The Total Physical Ram: $clusterPhyMemory " -ForegroundColor yellow
Write-host "Memory Free for work loads: $memoryFree4workloads" -ForegroundColor yellow 
 
}

####################################################################################################################################################################
$clusternodes = Get-ClusterNode

$blenode = @()
$freeMemory1 = @()
$totalMemoryUsedBy1VMs = @()
$totalPhysical1Memory = @()
 $freeservMemorySize= @()
 $physical1Memory =@()

 Write-host "===================================================================================================================================" -ForegroundColor yellow 
Write-host "          Individual Node Report "
Write-Host "---------------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor yellow

 
 

# If at least one server reports, convert bytes to GB
#########################################################
if ($global:mycounter1 -ne 0) {
    $mem4cachetotal= ($totalCachesize / $tbConversionFactor)
    $step2 = ($mem4cachetotal/ $global:mycounter1)
    $mytotalcache = $step2
    }
foreach ($bode in $clusternodes) {
    $nodeInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $bode.Name
    $nodeName = $nodeInfo.Name
    $physical1Memory = $nodeInfo.TotalPhysicalMemory / 1GB

    $vmMemoryInfo = Invoke-Command -ComputerName $bode.Name -ScriptBlock { Get-VM | Where-Object { $_.State -eq "Running" } | Measure-Object -Property MemoryAssigned -Sum}
    $totalVMs1Memory = $vmMemoryInfo.Sum / 1GB

     $freeservMemory1Size = ((Get-CimInstance -ClassName CIM_OperatingSystem -ComputerName $bode.Name).FreePhysicalMemory / 1mb)
      $mynodecachram = $Global:nodecachemem


  $blenode += $nodeName
  $freeMemory1 +=  $freeservMemory1Size
   $totalMemoryUsedBy1VMs += $totalVMs1Memory
    $totalPhysical1Memory += $physical1Memory
   $mynodecachram = $Global:nodecachemem
  
 #$threshold85=  (([int]$physical1Memory) *  ($global:custpresurelimit/100))
 #this is the localnode memory statistics calculations 
  $osreqmem = ([int]$physical1Memory * (4/100))
$freeservMemory1Size = Format-TwoDecimalPlaces -number $freeservMemory1Size
$totalVMs1Memory =Format-TwoDecimalPlaces -number  $totalVMs1Memory
$physical1Memory = Format-TwoDecimalPlaces -number $physical1Memory
 $totnodeusedram = ([int]$dedup2 + [int]$Global:nodecachemem + [int]$totalVMs1Memory + [int]$osreqmem)

 $Global:nodecachemem = Format-TwoDecimalPlaces -Number $Global:nodecachemem
  $nodefree4workloads =  ($physical1Memory - $totnodeusedram)
 
# If ($totnodeusedram -ge $threshold85) {$mathesar = $true} else {$mathesar = $false }
# $nodefree4workloads
 Write-host "*Cluster Host: $nodeName"
 Write-host "*Total $nodeName Physical Memory is $physical1Memory GB"
 Write-Host "*Memory In use by $nodeName Vms: $totalVMs1Memory GB" 
 
 Write-host "*Total Memory In Use by $nodename : $totnodeusedram    GB "
 Write-host "*Node Free Memory: $freeservMemory1Size GB  "
 Write-host "*OS required Memory for $nodename :  $osreqmem  GB"
 Write-host "*Cache Requirement Memory: $Global:nodecachemem  GB"
 Write-host "*Dedup required memory for host: $dedup2  GB"
 Write-host "*Net Node Free Memory :  $nodefree4workloads  GB"
 $percenttarget = (($global:custpresurelimit/100) * $physical1Memory)
 $percenttarget = Format-TwoDecimalPlaces -number $percenttarget
 

 Write-host "Conclusion and Analysis:" -ForegroundColor Gray
 Write-host "------------------------------------------------------------" -ForegroundColor DarkYellow
 If ($mathesar -eq $true)
 {
 Write-host "*$nodeName Memory is overdriven. Turn off VMs, increase Ram or move resources to other nodes!" -ForegroundColor Red
 
 Write-host "*$nodename Is over Subscribed. Contact Support immediately" -ForegroundColor Red
 Write-host "*The threshold of criticality is: $global:custpresurelimit %  or total of $percenttarget" -red
 Write-host "*$node free memory is $totnodeusedram"
  $nodefree4workloads = Format-TwoDecimalPlaces -number   $nodefree4workloads
Write-host "*Free Memory for work loads: $nodefree4workloads"  -ForegroundColor yellow
Write-host "*Memory Free for work loads: $nodefree4workloads"  -ForegroundColor yellow
Write-host "*The threshold of criticality is: $global:custpresurelimit %  of $percenttarget GB ram left"  -ForegroundColor yellow
$actualpercenthost = (($percenttarget - $totnodeusedram ) / $totnodeusedram )
$actualpercenthost = Format-TwoDecimalPlaces -number $actualpercenthost
Write-host "*Your total % used resources is : $actualpercenthost %  or $totnodeusedram GB" -ForegroundColor yellow
 Write-host "*$nodename can use  $nodefree4workloads but not $physical1Memory or $freeservMemory1Size GB" -ForegroundColor yellow 
 } else {
 
 Write-host "*Gold Stars: $Nodename is not Memory Constrained, based on the threshold provided: $global:custpresurelimit %" -ForegroundColor yellow
Write-host "*The threshold of criticality is: $global:custpresurelimit %  of $percenttarget GB " -ForegroundColor yellow
Write-host "*Node alarms when $global:custpresurelimit % usage occurs or $physical1Memory GB " -ForegroundColor yellow
 Write-host "*In Gigabytes that threshold is:  $percenttarget GB will be no more then $global:custpresurelimit %  of $physical1Memory GB" -ForegroundColor yellow
 Write-host "*Total Memory in use by $nodename : $totnodeusedram GB" -ForegroundColor yellow


 
# $nodefree4workloads = Format-TwoDecimalPlaces -number   $nodefree4workloads
#Write-host "*Memory Free for work loads: $nodefree4workloads"  -ForegroundColor yellow
#Write-host "*The threshold of criticality is: $global:custpresurelimit %  of $percenttarget GB ram left"  -ForegroundColor yellow
#$actualpercenthost = (($percenttarget - $totnodeusedram ) / $totnodeusedram )
#$actualpercenthost = Format-TwoDecimalPlaces -number $actualpercenthost
#Write-host "*Your total % used resources is : $actualpercenthost %  or $totnodeusedram GB" -ForegroundColor yellow
 }
 Write-Host "-----------------------------------------------------------------------------------------------" -ForegroundColor yellow

 



 
 

}
Write-host "=====================================================================================================" -ForegroundColor yellow
Write-host "---------------Alternate Server Calculations for additional reliability  ----------------------------" -ForegroundColor white
Write-host "-----------------------------------------------------------------------------------------------------" -ForegroundColor white


$babyData = for ($i = 0; $i -lt $blenode.Count; $i++) {
    [PSCustomObject]@{
        'Node Name' = $blenode[$i]
        'Free Server Memory' = [Math]::Round($($freeMemory1[$i]),2)
        'VMS RAM' = [Math]::Round($($totalMemoryUsedBy1VMs[$i]),2)
        'Physical RAM' = [Math]::Round($($totalPhysical1Memory[$i]), 2)
        'CACHE RAM' = [Math]::Round($($mytotalcache) ,2) 




    }
}$babyData | Format-Table -AutoSize


 

Sleep(5)
  write-host "===================================================================================================="  -ForegroundColor yellow
write-host "----------------------------Can the CLuster Sustain a memory Node Failure? -------------------------" 
write-host "======================================================================================================" -ForegroundColor yellow 

 Write-host "========================================================================================" -ForegroundColor yellow 
Write-host "Prediction:One Node Lost:" -ForegroundColor Yellow
Write-host "----------------------------------------------------------------------------------------" -ForegroundColor DarkYellow
Write-host " THis is predictive and an extimate only. This does not mean you cannot sustain a faiure, it just expains how tight the memory may be with one node down. "
Write-host " THis is only a tool and you should look at the documentation and make sure you are deployed correctly and you are following the growth plan built into your deployment"
Write-host " Results: "
Write-host "========================================================================================" -ForegroundColor Green


[double]$fractional = [double]((1 / [double]$global:mycounter1)) 

# 156.66
Write-host "The total amount of Memory used by Vms in the cluster (including overhead is): $ThresholdClusterUsedMem"
####SINGLE NODE USEAGE CALC
[double] $c = ([double]$clusterallhostsram * [double]$fractional)
 [double]$d= ([double]$clustercachmemory * [double]$fractional)
# Write-host "$c and $d c and d"
 [double]$e= ([double]$clusterPhyMemory * $fractional)
 $f= ($globaldedpCluster * $fractional)
 
 $singlenoderemove = ($c+ $d +$f)

# Check if fractional is zero (if applicable)
if ($fractional -eq 0) {
    Write-Host "Error: Fractional value is zero. Division by zero is not allowed."
}
else {
    # Perform the arithmetic operation using double data type
   $result = [double]$clusterallhostsram * [double]$fractional
 Write-Host "Taking one node Offline will remove this much memory: $e GB"
}

#                                   34                                      122-   61                             10.5                                                      
 $memusedwithnodedown =  ( ([double]$clusterTotalMemUsedByVm) +  ([double]$clusterallhostsram -($c)) + ([double]$clustercachmemory - ($d))  + ([double]$globaldedpCluster - ($f))) 



 $thresholdlessonenode = ((([double]$global:custpresurelimit)/100) * ([double]$clusterPhyMemory - ($e)))

 If ($memusedwithnodedown -ge $thresholdlessonenode)
 {
 Write-host "Cluster should not be taken Down. Turn off Vms, Remove the cluster role and/or increase memory!" -ForegroundColor Green
  Write-host "Cluster should not be taken Down. Turn off Vms, Remove the cluster role and/or increase memory!"
  
Write-host " $global:custpresurelimit % of the memory available to the cluster,  with a node down will be $thresholdlessonenode GB"
Write-host " The total memory required for a one node cluster down is:  $memusedwithnodedown GB "
 
 }Else {
 write-host "The Cluster Node can be safely taken down for maintenence!" -ForegroundColor Green
 write-host "The Cluster Node can be safely taken down for maintenence!"
 Write-host " $global:custpresurelimit % of the memory available to the cluster,  with a node down will be $thresholdlessonenode GB"
Write-host " The total memory required for a one node cluster down is:  $memusedwithnodedown GB "
 
 }

 
Write-host "========================================================================================" -ForegroundColor Green 

 
 Read-host "hit a key to exit report. Remember you have to choose Q at the main menu to get a report "
 
 
 
 }


  function startlogging {
    # Define the script block you want to return
    $myScriptBlock = {
 
 # Start capturing the output

 $myloc = "$($env:USERPROFILE)\Desktop\output.txt"
 $myloc1= "$($env:USERPROFILE)\Desktop\"
 $filename= "output.txt"
 set-location -path $myloc

 #Check for files 
$filePath = $myloc1


if (-not (Test-Path $filePath)) {
   # New-Item -ItemType File -Path $filePath -Force
   new-item
    Write-Host "File created: $filePath"
} else { Write-Host "We will use the append action. File already exists: $filePath " }

Start-Transcript -Path $filePath -Append -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue


    }

    # Return the script block
    return $myScriptBlock
}


function Show-Menu {
    param (
        [string]$Title = 'VM Ballancing and Management (VM-BAM) '  
    )
    Clear-Host
    Write-Host "================ $Title ================"
    
    Write-Host "1. Vm Statistics"
    Write-Host "2. Analysis of Pool alignment"
    Write-Host "3. Performance VM to Processor ratio calculations(Diag-v )"
    Write-Host "4. Perform Automated Virtual Disk VM Alignment"
    Write-Host "5. Remove or Add clustered role from VMs by VM, Virtual disk or Pool. "
    Write-Host "6. Test Azure Stack HCI Memory Capacity to take new workloads"
    Write-Host "Q. Quit"
    
    $choice = Read-Host "Please enter your choice" -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
    Process-Choice $choice
}


function Process-Choice {
    param (
        [string]$Choice
    )
     
    switch ($Choice) {
        '1' {
            Write-Host "1. Run Vm Statistics"
             mycol
            # Perform action for Option 1
           }
        '2' {
            Write-Host "2. Analysis of Pool alignment"
              
          alignvmtest
            # Perform action for Option 2
        } 
        '3' {
            Write-Host "3. Performance VM to Processor ratio calculations(Diag-v )"
          
        remote-Vmcalc
            # Perform action for Option 3
        } 
        '4' {
            Write-Host "4. Perform Automated Virtual DIsk VM Alignment"
             
         Calc-VmactulLM
            # Perform action for Option 4
        }
        '5' {
            Write-Host "5. Remove or Add clustered role from VMs when Storage wont stay up and vms wont stay started"
            # Perform action for Option 5 
        noclusterrole
        }
            # Perform action for Option 6
        '6' {
            Write-Host "6. Test Azure Stack HCI Memory Capacity to take new workloads"
            MemOversub
       }

       'Q' {
            Write-Host "Exiting..."
           
            if($global:readit = $true)
			
			
			
{
# Stop capturing the output
 Stop-Transcript

$myloc = "$($env:USERPROFILE)\Desktop\output.txt"
 $myloc1 = "$($env:USERPROFILE)\Desktop\"
# Convert the transcript to HTML
Set-location -path $myloc1
remove-item output.html -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
$transcriptContent = Get-Content -Path $myloc -Raw
$htmlContent += $transcriptContent | ConvertTo-Html -Fragment

# Save the HTML content to a file
$htmlContent | Out-File -FilePath $myloc\output.html -Encoding UTF8
 $global:End_Time = Get-Date
            $global:finsh_time = $global:Start_Time - $global:end_time
           Write-host " total time in program is below: "
            $global:finsh_time 
Read-host " The FIle output.txt is put to the $myloc path.Enter to continue" 
# End the PowerShell session
Exit
}
        }
        default {
            Write-Host "Invalid choice. Please try again."
        }
    }
    
    # Prompt the user for another choice
    Show-Menu
}
# Show the initial menu
$global:readitnow = $null
clear-host 
 $global:readitnow = read-host "Do you want to capture a log for the session? It will contain the report of findings. Enter= yes. Any char+enter = no logging"

 
if (!($global:readitnow.Length)) 
{
    $global:readit = $false
  

   $myloc = "$($env:USERPROFILE)\Desktop\output.txt"
 $myloc1= "$($env:USERPROFILE)\Desktop\"
 $filename= "output.txt"
 set-location -path $myloc

 #Check for files 
$filePath = $myloc


if (-not (Test-Path $filePath)) {
   New-Item -ItemType File -Path $filePath -Force
 
    Write-Host "File created: $filePath"
} else { Write-Host "We will use the append action. File already exists: $filePath " }

Start-Transcript -Path $filePath -Append -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    #not on menu - just begins log session
Read-host "Logging started. Enter to continue to Start Hyper-V VM-BAL Application! "
   
    } else {$global:readit = $true}

 

show-menu





#future fix load ballancing  https://learn.microsoft.com/en-us/azure-stack/hci/manage/vm-load-balancing

#2 https://azurestackhcisolutions.azure.microsoft.com/#/sizer

Function Vcpu2cpu{
  $ErrorActionPreference = 'SilentlyContinue'
   $VerbosePreference = "silentlycontinue"
   $warningactionPreference = "SilentlyContinue"
    
$mybuster = Get-Cluster
$myclusterbones = Get-ClusterNode
$myclount  = (Get-ClusterNode).count

$TotalPhysicalCPUs = (Get-WmiObject -Class Win32_ComputerSystem).NumberOfProcessors
$TotalvCPUs = 0


$mybms1= Invoke-Command -ComputerName ($myclusterbones) -ScriptBlock {
$VMs = Get-VM

foreach ($VM in $VMs) {
    $VMProcessors = $VM | Get-VMProcessor
    $TotalvCPUs += ($VMProcessors | Measure-Object -Property Count).Count
}

$CPUvsvCPU = ($TotalvCPUs / $TotalPhysicalCPUs)



$TotalLogicalProcessors = (Get-WmiObject -Class Win32_ComputerSystem).NumberOfLogicalProcessors
$AssignedLogicalProcessors = (Get-VM | Get-VMProcessor | Measure-Object -Property Count -Sum).Sum

$Ratio = $AssignedLogicalProcessors / $TotalLogicalProcessors

$CPUvsvCPU21 += $CPUvsvCPU
$ratio21 += $Ratio

} -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
clear-host 
Write-host "=============== Report Vcpu etc----------------------------" -ForegroundColor Yellow
Write-Host "CPU to vCPU Ratio: $CPUvsvCPU21"
Write-Host "Assigned Logical Processors Ratio: $Ratio21"

} 


<#

Ideas on completing 

1. calculate storage cache % of use 
2. How much cache gets used by Hyper-v replica

3. Test for nested resiliancey 



#>


