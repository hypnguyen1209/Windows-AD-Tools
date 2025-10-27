<# ===================== Get-Privilege.ps1 ===================== #>

# Helper: check if a type is already loaded
function Test-TypeLoaded {
  param([Parameter(Mandatory)][string]$TypeName)
  return [bool]($TypeName -as [type])
}

# Add types once, under a unique namespace to avoid collisions
if (-not (Test-TypeLoaded 'PPriv2.Native')) {
  Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PPriv2 {
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID { public UInt32 LowPart; public Int32 HighPart; }

  [StructLayout(LayoutKind.Sequential)]
  public struct LUID_AND_ATTRIBUTES { public LUID Luid; public UInt32 Attributes; }

  public static class Native {
    public const int TokenPrivileges = 3;

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        IntPtr TokenInformation,
        int TokenInformationLength,
        out int ReturnLength);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LookupPrivilegeName(
        string lpSystemName,
        IntPtr lpLuid,
        StringBuilder lpName,
        ref int cchName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
  }

  public enum Privileges {
    SeAssignPrimaryTokenPrivilege=1, SeAuditPrivilege, SeBackupPrivilege, SeChangeNotifyPrivilege,
    SeCreateGlobalPrivilege, SeCreatePagefilePrivilege, SeCreatePermanentPrivilege,
    SeCreateSymbolicLinkPrivilege, SeCreateTokenPrivilege, SeDebugPrivilege,
    SeEnableDelegationPrivilege, SeImpersonatePrivilege, SeIncreaseBasePriorityPrivilege,
    SeIncreaseQuotaPrivilege, SeIncreaseWorkingSetPrivilege, SeLoadDriverPrivilege,
    SeLockMemoryPrivilege, SeMachineAccountPrivilege, SeManageVolumePrivilege,
    SeProfileSingleProcessPrivilege, SeRelabelPrivilege, SeRemoteShutdownPrivilege,
    SeRestorePrivilege, SeSecurityPrivilege, SeShutdownPrivilege, SeSyncAgentPrivilege,
    SeSystemEnvironmentPrivilege, SeSystemProfilePrivilege, SeSystemtimePrivilege,
    SeTakeOwnershipPrivilege, SeTcbPrivilege, SeTimeZonePrivilege,
    SeTrustedCredManAccessPrivilege, SeUndockPrivilege
  }
}
"@
}

function Invoke-PPriv2LocalEnum {
  # Enumerate privileges of the current process token
  $TOKEN_QUERY = 0x0008
  $SE_PRIVILEGE_ENABLED            = 0x00000002
  $SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
  $SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

  $hToken = [IntPtr]::Zero
  if (-not [PPriv2.Native]::OpenProcessToken([PPriv2.Native]::GetCurrentProcess(), $TOKEN_QUERY, [ref]$hToken)) {
    throw "OpenProcessToken failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
  }

  try {
    $outLen = 0
    [void][PPriv2.Native]::GetTokenInformation($hToken, [PPriv2.Native]::TokenPrivileges, [IntPtr]::Zero, 0, [ref]$outLen)
    if ($outLen -le 0) { return @() }

    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLen)
    try {
      if (-not [PPriv2.Native]::GetTokenInformation($hToken, [PPriv2.Native]::TokenPrivileges, $buf, $outLen, [ref]$outLen)) {
        throw "GetTokenInformation failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
      }

      $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf)
      $ptr   = [IntPtr]::Add($buf, 4)
      $laSz  = [System.Runtime.InteropServices.Marshal]::SizeOf([type]'PPriv2.LUID_AND_ATTRIBUTES')

      $items = New-Object System.Collections.Generic.List[object]

      for ($i=0; $i -lt $count; $i++) {
        $la = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type]'PPriv2.LUID_AND_ATTRIBUTES')
        $ptr = [IntPtr]::Add($ptr, $laSz)

        # Marshal LUID for LookupPrivilegeName
        $luidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([type]'PPriv2.LUID'))
        try {
          [System.Runtime.InteropServices.Marshal]::StructureToPtr($la.Luid, $luidPtr, $false)
          $sb  = New-Object System.Text.StringBuilder 256
          $len = $sb.Capacity
          $ok  = [PPriv2.Native]::LookupPrivilegeName($null, $luidPtr, $sb, [ref]$len)
          $name = if ($ok) { $sb.ToString() } else { "<Unknown>" }
        }
        finally {
          [System.Runtime.InteropServices.Marshal]::FreeHGlobal($luidPtr)
        }

        $attr = $la.Attributes
        $items.Add([pscustomobject]@{
          Name             = $name
          Enabled          = ($attr -band $SE_PRIVILEGE_ENABLED) -ne 0
          EnabledByDefault = ($attr -band $SE_PRIVILEGE_ENABLED_BY_DEFAULT) -ne 0
          UsedForAccess    = ($attr -band $SE_PRIVILEGE_USED_FOR_ACCESS) -ne 0
          Attributes       = ('0x{0:X8}' -f $attr)
        })
      }

      return $items
    }
    finally {
      [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
    }
  }
  finally {
    [PPriv2.Native]::CloseHandle($hToken) | Out-Null
  }
}

function Get-Privilege {
<#
.SYNOPSIS
  Enumerates privileges of a process token and optionally filters them.

.PARAMETER Privilege
  One or more privilege names (as [PPriv2.Privileges]) to filter the output. Optional.

.PARAMETER ComputerName
  Target computer (Default set). Defaults to current computer name. Uses WinRM for remote.

.PARAMETER CurrentUser
  Uses the calling session's token on the local machine. Ignores -ComputerName.

.EXAMPLE
  Get-Privilege

.EXAMPLE
  Get-Privilege -Privilege SeBackupPrivilege, SeRestorePrivilege

.EXAMPLE
  Get-Privilege -ComputerName SERVER01

.EXAMPLE
  Get-Privilege -CurrentUser
#>
  [CmdletBinding(DefaultParameterSetName='Default')]
  param(
    [parameter(ParameterSetName='Default')]
    [PPriv2.Privileges[]]$Privilege,

    [parameter(ParameterSetName='Default')]
    [string]$ComputerName = $Env:ComputerName,

    [parameter(ParameterSetName='CurrentUser')]
    [switch]$CurrentUser
  )

  if ($PSCmdlet.ParameterSetName -eq 'CurrentUser') {
    $result = Invoke-PPriv2LocalEnum
  }
  else {
    $isLocal =
      [string]::IsNullOrWhiteSpace($ComputerName) -or
      ($ComputerName -eq '.') -or
      ($ComputerName -eq 'localhost') -or
      ($ComputerName -ieq $env:COMPUTERNAME)

    if ($isLocal) {
      $result = Invoke-PPriv2LocalEnum
    }
    else {
      $remoteBlock = {
        if (-not ([bool]('PPriv2.Native' -as [type]))) {
          Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PPriv2 {
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID { public UInt32 LowPart; public Int32 HighPart; }
  [StructLayout(LayoutKind.Sequential)]
  public struct LUID_AND_ATTRIBUTES { public LUID Luid; public UInt32 Attributes; }
  public static class Native {
    public const int TokenPrivileges = 3;
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
  }
  public enum Privileges {
    SeAssignPrimaryTokenPrivilege=1, SeAuditPrivilege, SeBackupPrivilege, SeChangeNotifyPrivilege,
    SeCreateGlobalPrivilege, SeCreatePagefilePrivilege, SeCreatePermanentPrivilege,
    SeCreateSymbolicLinkPrivilege, SeCreateTokenPrivilege, SeDebugPrivilege,
    SeEnableDelegationPrivilege, SeImpersonatePrivilege, SeIncreaseBasePriorityPrivilege,
    SeIncreaseQuotaPrivilege, SeIncreaseWorkingSetPrivilege, SeLoadDriverPrivilege,
    SeLockMemoryPrivilege, SeMachineAccountPrivilege, SeManageVolumePrivilege,
    SeProfileSingleProcessPrivilege, SeRelabelPrivilege, SeRemoteShutdownPrivilege,
    SeRestorePrivilege, SeSecurityPrivilege, SeShutdownPrivilege, SeSyncAgentPrivilege,
    SeSystemEnvironmentPrivilege, SeSystemProfilePrivilege, SeSystemtimePrivilege,
    SeTakeOwnershipPrivilege, SeTcbPrivilege, SeTimeZonePrivilege,
    SeTrustedCredManAccessPrivilege, SeUndockPrivilege
  }
}
"@
        }

        function Invoke-PPriv2LocalEnum {
          $TOKEN_QUERY = 0x0008
          $SE_PRIVILEGE_ENABLED            = 0x00000002
          $SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
          $SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000

          $hToken = [IntPtr]::Zero
          if (-not [PPriv2.Native]::OpenProcessToken([PPriv2.Native]::GetCurrentProcess(), $TOKEN_QUERY, [ref]$hToken)) {
            throw "OpenProcessToken failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
          }

          try {
            $outLen = 0
            [void][PPriv2.Native]::GetTokenInformation($hToken, [PPriv2.Native]::TokenPrivileges, [IntPtr]::Zero, 0, [ref]$outLen)
            if ($outLen -le 0) { return @() }

            $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($outLen)
            try {
              if (-not [PPriv2.Native]::GetTokenInformation($hToken, [PPriv2.Native]::TokenPrivileges, $buf, $outLen, [ref]$outLen)) {
                throw "GetTokenInformation failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
              }

              $count = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf)
              $ptr   = [IntPtr]::Add($buf, 4)
              $laSz  = [System.Runtime.InteropServices.Marshal]::SizeOf([type]'PPriv2.LUID_AND_ATTRIBUTES')

              $items = New-Object System.Collections.Generic.List[object]

              for ($i=0; $i -lt $count; $i++) {
                $la = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type]'PPriv2.LUID_AND_ATTRIBUTES')
                $ptr = [IntPtr]::Add($ptr, $laSz)

                $luidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([type]'PPriv2.LUID'))
                try {
                  [System.Runtime.InteropServices.Marshal]::StructureToPtr($la.Luid, $luidPtr, $false)
                  $sb  = New-Object System.Text.StringBuilder 256
                  $len = $sb.Capacity
                  $ok  = [PPriv2.Native]::LookupPrivilegeName($null, $luidPtr, $sb, [ref]$len)
                  $name = if ($ok) { $sb.ToString() } else { "<Unknown>" }
                }
                finally {
                  [System.Runtime.InteropServices.Marshal]::FreeHGlobal($luidPtr)
                }

                $attr = $la.Attributes
                $items.Add([pscustomobject]@{
                  Name             = $name
                  Enabled          = ($attr -band 0x00000002) -ne 0
                  EnabledByDefault = ($attr -band 0x00000001) -ne 0
                  UsedForAccess    = ($attr -band 0x80000000) -ne 0
                  Attributes       = ('0x{0:X8}' -f $attr)
                })
              }

              return $items
            }
            finally {
              [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
            }
          }
          finally {
            [PPriv2.Native]::CloseHandle($hToken) | Out-Null
          }
        }

        Invoke-PPriv2LocalEnum
      }

      try {
        $result = Invoke-Command -ComputerName $ComputerName -ScriptBlock $remoteBlock
      }
      catch {
        throw "Remote enumeration failed on '$ComputerName': $($_.Exception.Message)"
      }
    }
  }

  # Filter by -Privilege if provided
  if ($PSBoundParameters.ContainsKey('Privilege') -and $Privilege) {
    $names = $Privilege | ForEach-Object { $_.ToString() }
    $result = $result | Where-Object { $_.Name -in $names }
  }

  $result
}
