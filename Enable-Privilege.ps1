<# ===================== Enable-Privilege.ps1 ===================== #>

Add-Type @"
using System;
using System.Runtime.InteropServices;

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

public struct LUID { public UInt32 LowPart; public Int32 HighPart; }
[StructLayout(LayoutKind.Sequential)]
public struct LUID_AND_ATTRIBUTES { public LUID Luid; public UInt32 Attributes; }
[StructLayout(LayoutKind.Sequential)]
public struct TOKEN_PRIVILEGES { public UInt32 PrivilegeCount; public LUID_AND_ATTRIBUTES Privileges; }

public static class PoshPrivilege {
  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

  [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();

  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool LookupPrivilegeValue(string systemName, string name, out LUID luid);

  [DllImport("advapi32.dll", SetLastError=true)]
  public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
    ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
}
"@

function Enable-Privilege {
<#
.SYNOPSIS
  Enables or disables privileges in the current process.

.PARAMETER Privilege
  One or more privilege names to modify (e.g., SeBackupPrivilege).

.PARAMETER Disable
  Disable instead of enabling the privilege(s).

.EXAMPLE
  Enable-Privilege -Privilege SeBackupPrivilege

.EXAMPLE
  Enable-Privilege -Privilege SeTakeOwnershipPrivilege, SeRestorePrivilege

.EXAMPLE
  Enable-Privilege -Privilege SeDebugPrivilege -Disable
#>
  [CmdletBinding(SupportsShouldProcess=$true)]
  param(
    [Parameter(Mandatory=$true)]
    [Privileges[]]$Privilege,
    [switch]$Disable
  )

  $TOKEN_QUERY = 0x0008
  $TOKEN_ADJUST_PRIVILEGES = 0x0020
  $SE_PRIVILEGE_ENABLED  = 0x00000002
  $SE_PRIVILEGE_DISABLED = 0x00000000

  $hToken = [IntPtr]::Zero
  if (-not [PoshPrivilege]::OpenProcessToken([PoshPrivilege]::GetCurrentProcess(),
      $TOKEN_QUERY -bor $TOKEN_ADJUST_PRIVILEGES, [ref]$hToken)) {
    throw "OpenProcessToken failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
  }

  foreach ($p in $Privilege) {
    if ($PSCmdlet.ShouldProcess("PID $PID", "Set privilege $p")) {
      $luid = New-Object LUID
      if (-not [PoshPrivilege]::LookupPrivilegeValue($null, $p.ToString(), [ref]$luid)) {
        Write-Warning "LookupPrivilegeValue($p) failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
        continue
      }

      $tp = New-Object TOKEN_PRIVILEGES
      $tp.PrivilegeCount = 1
      $la = New-Object LUID_AND_ATTRIBUTES
      $la.Luid = $luid
      $la.Attributes = if ($Disable) { $SE_PRIVILEGE_DISABLED } else { $SE_PRIVILEGE_ENABLED }
      $tp.Privileges = $la

      if (-not [PoshPrivilege]::AdjustTokenPrivileges($hToken, $false, [ref]$tp,
           [Runtime.InteropServices.Marshal]::SizeOf([type]'TOKEN_PRIVILEGES'),
           [IntPtr]::Zero, [IntPtr]::Zero)) {
        Write-Warning "AdjustTokenPrivileges($p) failed: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
      }
    }
  }
}
