# comandos administrador powershell
#usuarios 
Get-LocalUser
get-localuser -Name usuario|fl

#grupos
Get-LocalGroup
Get-Localgroup -Name administradores
Get-Localgroup -Name administradores|fl

#recursos compartidos
Get-SmbShare
Get-SmbShare -Special:$false
Get-SmbShare -Name print$|fl

#discos
get-disk
get-disk -Number 0|fl
Get-Partition -DiskNumber 0

#red
Get-NetAdapter
Get-NetAdapter -Name "Wi-fi 7"|l

#procesos y servicios 
Get-Process
Get-service|where-object{$_.Status eq "Running"}

#impresoras
Get-printer
Get-printer -Name "name"|fl
Get-printerDriver -Name "name"|fl




