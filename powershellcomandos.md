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

# Verificación rápida de usuario#

Get-ADUser jperez -Properties LockedOut, Enabled, LastLogonDate

# Ver si un usuario está bloqueado#

Search-ADAccount -LockedOut | Select Name

# grupos de un usuario# 

Get-ADPrincipalGroupMembership jperez | Select Name

# Copiar permisos de un usuario a otro#

Get-ADPrincipalGroupMembership jperez |
Where-Object { $_.Name -ne "Domain Users" } |
ForEach-Object {
    Add-ADGroupMember -Identity $_.Name -Members mgonzalez
}


## AUTOMATIZACIONES ##
# Crear usuario AD + contraseña inicial# 

$Password = ConvertTo-SecureString "P@ssw0rd2026!" -AsPlainText -Force

New-ADUser 
 -Name "$Nombre $Apellido" `
    -GivenName $Nombre `
    -Surname $Apellido `
    -SamAccountName $Usuario `
    -UserPrincipalName "$Usuario@$Dominio" `
    -Path $OU `
    -AccountPassword $Password `
    -Enabled $true `
    -ChangePasswordAtLogon $true `


    # Deshabilitar usuario por baja laboral (offboarding)#

    $Usuario = "mparedes"

   Disable-ADAccount -Identity $Usuario

  Set-ADUser $Usuario -Description "Usuario deshabilitado por baja laboral - $(Get-Date -Format dd/MM/yyyy)"


  # Resetear contraseña automáticamente#

    $Usuario = "lperez"
  $NuevaPassword = ConvertTo-SecureString "Temp#2026!" -AsPlainText -Force
  
  Set-ADAccountPassword -Identity $Usuario -NewPassword $NuevaPassword -Reset
  Unlock-ADAccount -Identity $Usuario
  
  Write-Output "Contraseña reseteada y cuenta desbloqueada para $Usuario"

    

  # Obtener información completa de un usuario#

    $Usuario = "jperez"
  
  Get-ADUser $Usuario -Properties * |
  Select-Object Name, SamAccountName, Enabled, Department, Title, LastLogonDate


  # Listar usuarios inactivos (limpieza de AD)#

    Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly |
  Select-Object Name, SamAccountName, LastLogonDate


  # Obtener información de un equipo remoto#

      $PC = "PC-JPEREZ"
  
  Get-ComputerInfo -ComputerName $PC |
  Select-Object CsName, OsName, OsVersion, WindowsProductName


  # Script “todo en uno” para onboarding#

    $Nombre = "Maria"
  $Apellido = "Gonzalez"
  $Usuario = "mgonzalez"
  $Dominio = "empresa.local"
  $OU = "OU=Usuarios,DC=empresa,DC=local"
  $Password = ConvertTo-SecureString "Bienvenido#2026!" -AsPlainText -Force
  
  New-ADUser `
      -Name "$Nombre $Apellido" `
      -GivenName $Nombre `
      -Surname $Apellido `
      -SamAccountName $Usuario `
      -UserPrincipalName "$Usuario@$Dominio" `
      -Path $OU `
      -AccountPassword $Password `
      -Enabled $true `
      -ChangePasswordAtLogon $true
  
  Add-ADGroupMember -Identity "Usuarios-Office" -Members $Usuario
  Add-ADGroupMember -Identity "Ventas" -Members $Usuario
  
  Write-Output "Usuario $Usuario creado correctamente"
    
    




