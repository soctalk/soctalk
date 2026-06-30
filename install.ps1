<#
.SYNOPSIS
  SocTalk one-click installer for Windows (x64).

  Run from an elevated PowerShell:
    irm https://raw.githubusercontent.com/soctalk/soctalk/main/install.ps1 | iex
    # or:  powershell -ExecutionPolicy Bypass -File install.ps1

  The Windows path runs k3s (lightweight Kubernetes) as a systemd service
  inside WSL2 - no Docker. This script bootstraps WSL2 + systemd, then runs
  the same Linux install.sh the appliance uses. The UI/API are exposed to
  Windows on https://localhost/ via WSL2's localhost forwarding.
  See https://soctalk.github.io/soctalk-docs/windows

  Enabling WSL2 needs one reboot. Log back in afterward and the install
  resumes automatically (a scheduled task that runs at your next logon, in
  your own session - WSL2 cannot run as SYSTEM/session 0). Re-running is
  safe - completed steps are detected and skipped.

  -Real     prompt for real config instead of the demo (random admin pw + demo tenant)
  -Distro   WSL distro to use (default: Ubuntu)
  -Ref      git ref of install.sh to fetch (default: main)
#>
[CmdletBinding()]
param(
  [switch]$Real,
  [switch]$Resume,                 # internal: re-entry after the WSL2-enable reboot
  [string]$ResumeUser,             # internal: user whose session the resume runs in (default: current user)
  [string]$Distro = "Ubuntu",
  [string]$Ref    = "main",
  [string]$InstallShFile,          # optional: use a local install.sh (offline / pre-release) instead of fetching it
  [string]$RootfsUrl = "https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-ubuntu22.04lts.rootfs.tar.gz"
)

$ErrorActionPreference = "Stop"
$StateDir   = Join-Path $env:ProgramData "soctalk"
$SelfPath   = Join-Path $StateDir "install.ps1"
$ResumeTask = "SocTalkInstallResume"
$InstallShUrl = "https://raw.githubusercontent.com/soctalk/soctalk/$Ref/install.sh"
$SelfUrl      = "https://raw.githubusercontent.com/soctalk/soctalk/$Ref/install.ps1"
# The resume runs in this user's interactive session (WSL2 can't run as SYSTEM).
# Defaults to whoever launched the installer; the resume task passes it back explicitly.
$ResumeUserName = if ($ResumeUser) { $ResumeUser } else { [Security.Principal.WindowsIdentity]::GetCurrent().Name }

function Log  { param($m) Write-Host "==> $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "WARN: $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# --------------------------------------------------------------------- #
function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Invoke-Preflight {
  Log "Preflight"
  if (-not [Environment]::Is64BitOperatingSystem) { Die "64-bit Windows required (SocTalk images are amd64)." }
  if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    Die "Windows on ARM isn't supported - SocTalk images are amd64-only. Use a Linux amd64 host or the cloud demo."
  }
  $build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
  if ($build -lt 19041) { Die "Windows 10 2004 (build 19041) or newer is required for WSL2 (found build $build)." }
  $virt = (Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled
  if ($virt -eq $false) {
    Warn "CPU virtualization appears disabled in firmware - WSL2 needs it. If WSL2 fails to start, enable VT-x/AMD-V (and, in a VM, nested virtualization) and re-run."
  }
  Log "  x64, build $build - ok"
}

# Persist this script + register an at-logon task so the install continues
# after the WSL2-enable reboot. It runs in the user's interactive session
# (NOT as SYSTEM): WSL2 fails in session 0 with 'Access is denied', so the
# distro import / k3s install steps must run as a logged-in user.
function Set-Resume {
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  if ($PSCommandPath) { Copy-Item $PSCommandPath $SelfPath -Force }
  else { Invoke-WebRequest $SelfUrl -OutFile $SelfPath -UseBasicParsing }   # irm|iex path: re-fetch
  # Preserve every non-default param across the WSL2-enable reboot. The
  # resume runs from scratch with PowerShell's parameter defaults, so any
  # caller-supplied value the user typed (``-Ref``, ``-Distro``,
  # ``-RootfsUrl``) gets lost unless we round-trip it explicitly. Without
  # this the resume can pull the wrong install.sh ref, target the wrong
  # distro, or download a different rootfs from the one the operator
  # picked.
  $extra = " -ResumeUser `"$ResumeUserName`""
  if ($Real) { $extra += " -Real" }
  if ($Ref       -and $Ref       -ne "main")    { $extra += " -Ref `"$Ref`"" }
  if ($Distro    -and $Distro    -ne "Ubuntu")  { $extra += " -Distro `"$Distro`"" }
  if ($RootfsUrl -and $RootfsUrl -ne "https://cloud-images.ubuntu.com/wsl/jammy/current/ubuntu-jammy-wsl-amd64-ubuntu22.04lts.rootfs.tar.gz") {
    $extra += " -RootfsUrl `"$RootfsUrl`""
  }
  if ($InstallShFile -and (Test-Path $InstallShFile)) {
    $persistSh = Join-Path $StateDir "install.sh"
    Copy-Item $InstallShFile $persistSh -Force
    $extra += " -InstallShFile `"$persistSh`""
  }
  $action    = New-ScheduledTaskAction -Execute "powershell.exe" `
                 -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$SelfPath`" -Resume$extra"
  $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $ResumeUserName
  $principal = New-ScheduledTaskPrincipal -UserId $ResumeUserName -LogonType Interactive -RunLevel Highest
  Register-ScheduledTask -TaskName $ResumeTask -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null
  Log "  resume registered - it continues automatically when you log back in"
}

function Clear-Resume {
  Unregister-ScheduledTask -TaskName $ResumeTask -Confirm:$false -ErrorAction SilentlyContinue
}

function Test-Wsl2Ready {
  $vmp = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
  $wsl = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -ErrorAction SilentlyContinue
  return ($vmp -and $wsl -and $vmp.State -eq "Enabled" -and $wsl.State -eq "Enabled")
}

function Enable-Wsl2Features {
  Log "Enabling WSL2 features (Microsoft-Windows-Subsystem-Linux + VirtualMachinePlatform)"
  & dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart | Out-Null
  & dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null
}

function Invoke-Wsl { param([string[]]$Args) & wsl.exe @Args; return $LASTEXITCODE }

function Install-Stack {
  # wsl.exe is chatty on stderr (progress bars, "WSL is finishing an upgrade...").
  # Under the global $ErrorActionPreference=Stop those notices abort the run, so
  # relax it here and gate the steps that matter on $LASTEXITCODE / explicit checks.
  $ErrorActionPreference = 'Continue'

  Log "Updating the WSL2 kernel + defaulting to version 2"
  & wsl.exe --update 2>&1 | Out-Null
  Start-Sleep -Seconds 5            # let a just-installed WSL finish its upgrade before we drive it
  & wsl.exe --set-default-version 2 2>&1 | Out-Null

  # ``wsl -d <name>`` requires an EXACT distro name match. A substring
  # check (e.g. ``-notmatch 'Ubuntu'``) would falsely match an existing
  # ``Ubuntu-22.04`` install and skip the import — every subsequent
  # ``wsl -d Ubuntu`` command would then fail because no distro is
  # literally named ``Ubuntu``. Split + compare line-by-line instead.
  $installedRaw = (& wsl.exe -l -q 2>$null) -replace "`0",""
  $installedDistros = $installedRaw -split "`r?`n" |
                      ForEach-Object { $_.Trim() } |
                      Where-Object   { $_ -ne "" }
  if ($installedDistros -notcontains $Distro) {
    # Provision the distro by importing a rootfs tarball rather than `wsl --install -d`.
    # The Store/MSIX install path fails under the SYSTEM account (no user profile) with
    # 0x8000ffff - and SYSTEM is exactly the context the post-reboot resume task runs in.
    # Importing a rootfs needs no Store and works headless.
    Log "Importing the $Distro rootfs (headless, SYSTEM-safe)"
    $rootfs = Join-Path $StateDir "$Distro-rootfs.tar.gz"
    $wslDir = Join-Path $StateDir "wsl\$Distro"
    New-Item -ItemType Directory -Force -Path $wslDir | Out-Null
    if (-not (Test-Path $rootfs) -or (Get-Item $rootfs).Length -lt 200MB) {
      Remove-Item $rootfs -Force -ErrorAction SilentlyContinue   # drop any partial download
      Log "  downloading rootfs (~330 MB) ..."
      # Prefer curl.exe (built into Win10 1803+/Server 2022): Invoke-WebRequest in
      # PS 5.1 is 10-50x slower on big files, largely from progress-bar rendering.
      $ProgressPreference = 'SilentlyContinue'
      if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -fsSL $RootfsUrl -o $rootfs
      } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest $RootfsUrl -OutFile $rootfs -UseBasicParsing
      }
      if (-not (Test-Path $rootfs) -or (Get-Item $rootfs).Length -lt 200MB) { Die "rootfs download failed or incomplete." }
    }
    & wsl.exe --import $Distro $wslDir $rootfs --version 2
    if ($LASTEXITCODE -ne 0) { Die "wsl --import of $Distro failed (exit $LASTEXITCODE)." }
  } else { Log "$Distro already installed" }

  Log "Enabling systemd + /dev/kmsg in WSL (k3s needs both)"
  # systemd=true runs real systemd in WSL2 (k3s is a systemd service). The
  # [boot] command recreates /dev/kmsg on every WSL start - k3s's kubelet
  # needs it and WSL2 doesn't provide it by default.
  & wsl.exe -d $Distro -u root -- bash -c "printf '[boot]\nsystemd=true\ncommand = ln -sf /dev/console /dev/kmsg\n' > /etc/wsl.conf"

  # Keep the WSL2 VM from idling out, so k3s stays running and its IP stays
  # stable (the localhost portproxy set up after install targets that IP).
  $wslCfg = Join-Path $env:USERPROFILE ".wslconfig"
  if (-not (Test-Path $wslCfg) -or -not (Select-String -Path $wslCfg -Pattern 'vmIdleTimeout' -Quiet)) {
    Add-Content $wslCfg "[wsl2]`nvmIdleTimeout=-1`n"
  }

  & wsl.exe --shutdown; Start-Sleep -Seconds 4
  & wsl.exe -d $Distro -u root -- bash -c "ln -sf /dev/console /dev/kmsg"   # this session, before k3s starts

  Log "Bootstrapping base packages (curl, ca-certificates)"
  & wsl.exe -d $Distro -u root -- bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get update -y && apt-get install -y curl ca-certificates" 2>&1 | Out-Null

  Log "Running the SocTalk installer (k3s) inside WSL - this pulls images and takes a few minutes"
  # Ingress host = localhost so the UI/API are reachable from Windows at
  # https://localhost/ through WSL2's localhost forwarding (k3s Traefik on :443).
  $demoFlag = if ($Real) { "" } else { "--demo" }
  if ($InstallShFile -and (Test-Path $InstallShFile)) {
    # Local install.sh (offline / pre-release). Map the Windows path to its WSL
    # mount and strip CRs there. We deliberately avoid: piping via PowerShell
    # stdin (adds CRLF -> "$'\r': command not found"), capturing wsl.exe's UTF-16
    # output into a PS var (fragile), and embedded double quotes in the bash
    # command (PowerShell 5.1 mangles those when invoking a native exe).
    $wslPath  = "/tmp/soctalk-install.sh"
    $full     = (Resolve-Path $InstallShFile).Path        # absolute, e.g. C:\soctalk\install.sh
    $drive    = $full.Substring(0,1).ToLower()
    $wslMount = "/mnt/$drive" + ($full.Substring(2) -replace '\\','/')
    # ``$wslMount`` can include spaces (Windows user profile / OneDrive
    # paths are common) — wrap it in single quotes inside the bash -c
    # body so bash treats the path as one token. Without this the
    # tr/redirection silently splits on whitespace and aborts before the
    # local installer ever runs.
    & wsl.exe -d $Distro -u root -- bash -c "tr -d '\r' < '$wslMount' > '$wslPath' && SOCTALK_HOSTNAME=localhost bash '$wslPath' $demoFlag --yes"
  } else {
    & wsl.exe -d $Distro -u root -- bash -c "curl -sfL $InstallShUrl | SOCTALK_HOSTNAME=localhost bash -s -- $demoFlag --yes"
  }
  if ($LASTEXITCODE -ne 0) { Die "the SocTalk installer failed inside WSL (exit $LASTEXITCODE)." }

  # Expose the cluster to Windows. k3s Traefik listens on :80/:443 inside the WSL2
  # distro, but WSL2's localhost forwarding doesn't pick up k3s's iptables service
  # LB - so we add a netsh portproxy from the Windows host to the WSL2 IP. That IP
  # changes each boot, so the same logic is registered as an at-logon task that
  # re-boots WSL (k3s autostarts via systemd) and refreshes the forward.
  Log "Exposing the UI/API to Windows (https://localhost/)"
  $exposePs = Join-Path $StateDir "expose.ps1"
  # Template the WSL distro name into the at-logon helper so callers using
  # ``-Distro <name>`` end up driving the SAME distro the install landed
  # in. The previous hard-coded ``Ubuntu`` left the portproxy with no
  # target IP whenever the install ran in any other distro.
  #
  # Bind the proxy to 127.0.0.1: ``listenaddress=0.0.0.0`` would expose
  # the SocTalk UI/API on every Windows network interface, contrary to
  # the installer's localhost-only promise. Loopback only is what's
  # documented and what k3s + WSL2 actually need.
  $exposeTemplate = @'
# Boot WSL (k3s autostarts via systemd) and point a localhost portproxy at it.
$env:WSL_UTF8 = "1"
& wsl.exe -d "__DISTRO__" -u root -- /bin/true 2>$null
Start-Sleep -Seconds 3
$ip = ((& wsl.exe -d "__DISTRO__" -u root -- hostname -I) -split '\s+' |
        Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
if ($ip) {
  foreach ($port in 80,443) {
    & netsh interface portproxy delete v4tov4 listenport=$port listenaddress=127.0.0.1 2>$null | Out-Null
    & netsh interface portproxy add    v4tov4 listenport=$port listenaddress=127.0.0.1 connectport=$port connectaddress=$ip 2>$null | Out-Null
  }
}
'@
  $exposeTemplate.Replace('__DISTRO__', $Distro) | Set-Content -Encoding ASCII $exposePs

  $exAction    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$exposePs`""
  $exTrigger   = New-ScheduledTaskTrigger -AtLogOn -User $ResumeUserName
  $exPrincipal = New-ScheduledTaskPrincipal -UserId $ResumeUserName -LogonType Interactive -RunLevel Highest
  Register-ScheduledTask -TaskName "SocTalkExpose" -Action $exAction -Trigger $exTrigger -Principal $exPrincipal -Force | Out-Null
  & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $exposePs    # apply now

  $code = ""
  if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    $code = (& curl.exe -ks -o NUL -w "%{http_code}" https://localhost/ 2>$null)
  }

  Write-Host ""
  Log "SocTalk is installed."
  Write-Host "    Open https://localhost/ in your browser." -ForegroundColor Cyan
  if ($code -match '^(200|301|302|307|308|401|403|404)$') {
    Write-Host "    Verified reachable from Windows (HTTP $code)." -ForegroundColor Green
  } else {
    Warn "https://localhost/ didn't answer yet (got '$code'). k3s may still be settling; the SocTalkExpose task refreshes the forward at each login."
  }
}

# --------------------------------------------------------------------- #
if (-not (Test-Admin)) {
  Die "must run as Administrator. Open PowerShell with 'Run as administrator' and retry."
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
Start-Transcript -Path (Join-Path $StateDir "install.log") -Append -ErrorAction SilentlyContinue | Out-Null

try {
  if (-not $Resume) { Invoke-Preflight }

  if (-not (Test-Wsl2Ready)) {
    Enable-Wsl2Features
    Set-Resume
    Log "Rebooting to finish enabling WSL2 - log back in and the install resumes automatically."
    Start-Sleep -Seconds 3
    Restart-Computer -Force
    exit 0
  }

  Clear-Resume      # we're past the reboot (or WSL2 was already enabled)
  Install-Stack
} catch {
  Warn "install failed: $($_.Exception.Message)"
  exit 1
}
