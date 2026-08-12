<#
.SYNOPSIS
    Install, inspect or remove Infra Monitor on this machine.

.DESCRIPTION
    Deploying Infra Monitor to a new box is three files and no toolchain:

        InfraMonitor.exe          the app (self-contained; no Python needed)
        inframonitor-config.json  exported from a working install
        Install-InfraMonitor.ps1  this script

    Copy those to the new machine and run:

        powershell -ExecutionPolicy Bypass -File .\Install-InfraMonitor.ps1 -Install -Config .\inframonitor-config.json

    With no switch at all it only REPORTS - what is installed, where it reads
    its config from, whether it is registered to start at logon and whether
    that registration points at this copy. Read-only by default because the
    first thing you want on a machine you are unsure about is to look, not to
    change something.

    THE UNDO PATH IS PART OF THE INSTALL, NOT AN AFTERTHOUGHT.
    -Uninstall needs no network, no re-download and no state file: it stops the
    app and deletes one per-user registry value. It leaves machines.json and
    the exe alone unless you add -RemoveFiles, because losing a curated fleet
    list to a typo'd uninstall is not recoverable.

    Nothing here needs administrator rights. The logon entry is per-user
    (HKCU), which is also why it starts at LOGON and not at boot - a tray icon
    needs an interactive session to live in.

.PARAMETER Install
    Copy the exe into -Path, import -Config if given, register at logon, start it.

.PARAMETER Uninstall
    Stop Infra Monitor and remove the logon registration.

.PARAMETER Path
    Install directory. Defaults to this script's own folder.

.PARAMETER Config
    An inframonitor-config.json written by Settings > Export (or InfraMonitor.exe --export-config).

.PARAMETER Merge
    Merge -Config into an existing fleet instead of replacing it.

.PARAMETER RemoveFiles
    With -Uninstall, also delete the exe and the runtime state. Never deletes
    machines.json - that is your fleet list, and it is exported, not disposable.

.PARAMETER NoStart
    Do everything except launch it.

.EXAMPLE
    .\Install-InfraMonitor.ps1
    Report the current state and change nothing.

.EXAMPLE
    .\Install-InfraMonitor.ps1 -Install -Config .\inframonitor-config.json
    Fresh deployment onto a machine that has never run Infra Monitor.

.EXAMPLE
    .\Install-InfraMonitor.ps1 -Uninstall
    Stop it and stop it starting at logon. Files and config are kept.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Install,
    [switch]$Uninstall,
    [string]$Path,
    [string]$Config,
    [switch]$Merge,
    [switch]$RemoveFiles,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
$RunKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$RunValue = 'InfraMonitor'
$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Path) { $Path = $Here }

function Get-Registered {
    $p = Get-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
    if ($p) { return $p.$RunValue }
    return $null
}

function Stop-InfraMonitor {
    $procs = Get-Process -Name 'InfraMonitor' -ErrorAction SilentlyContinue
    if (-not $procs) { return $false }
    if ($PSCmdlet.ShouldProcess('InfraMonitor.exe', 'Stop')) {
        # A --onefile build is two processes: the bootloader and the child it
        # unpacked. Stopping only one leaves the other holding the exe open,
        # and the next install then fails to overwrite it.
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 900
        return $true
    }
    # -WhatIf: report what IS, not what would have been. Saying "stopped" when
    # nothing was stopped is exactly the lie -WhatIf exists to avoid.
    return $false
}

function Show-Status {
    $exe = Join-Path $Path 'InfraMonitor.exe'
    $cfg = Join-Path $Path 'machines.json'
    Write-Host ''
    Write-Host 'Infra Monitor status' -ForegroundColor Cyan
    Write-Host ('  install dir   : {0}' -f $Path)

    if (Test-Path -LiteralPath $exe) {
        $f = Get-Item -LiteralPath $exe
        Write-Host ('  exe           : present ({0:N1} MB, built {1:yyyy-MM-dd HH:mm})' -f ($f.Length/1MB), $f.LastWriteTime)
    } else {
        Write-Host '  exe           : MISSING' -ForegroundColor Red
    }

    if (Test-Path -LiteralPath $cfg) {
        try {
            $c = Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json
            $n = 0
            if ($c.machines) { $n = @($c.machines).Count }
            $auto = 'on'
            if ($null -ne $c.autostart -and -not $c.autostart) { $auto = 'off' }
            Write-Host ('  config        : {0} machine(s), autostart setting {1}' -f $n, $auto)
            if ($n -eq 0) {
                Write-Host '                  nothing is being monitored' -ForegroundColor Yellow
            }
        } catch {
            Write-Host '  config        : PRESENT BUT UNREADABLE' -ForegroundColor Red
        }
    } else {
        # The failure that actually happens: the exe was run from a folder with
        # no config beside it, so it monitors nothing and says it is healthy.
        Write-Host '  config        : MISSING - nothing would be monitored' -ForegroundColor Red
        Write-Host '                  import one:  InfraMonitor.exe --import-config <file>' -ForegroundColor Yellow
    }

    $reg = Get-Registered
    if ($reg) {
        Write-Host ('  starts at logon: yes -> {0}' -f $reg)
        $want = '"{0}"' -f $exe
        if ($reg -ne $want) {
            Write-Host ('                  NOTE: points somewhere else, not {0}' -f $want) -ForegroundColor Yellow
        }
        $target = $reg.Trim('"')
        if (-not (Test-Path -LiteralPath $target)) {
            Write-Host '                  and that file does not exist - it will fail silently every logon' -ForegroundColor Red
        }
    } else {
        Write-Host '  starts at logon: no'
    }

    $running = Get-Process -Name 'InfraMonitor' -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host ('  running       : yes (pid {0})' -f (($running | ForEach-Object { $_.Id }) -join ', '))
    } else {
        Write-Host '  running       : no'
    }
    Write-Host ''
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
    Write-Host 'Removing Infra Monitor autostart...' -ForegroundColor Cyan
    if (Stop-InfraMonitor) { Write-Host '  stopped the running instance' }

    if (Get-Registered) {
        if ($PSCmdlet.ShouldProcess("$RunKey\$RunValue", 'Remove logon entry')) {
            Remove-ItemProperty -Path $RunKey -Name $RunValue -ErrorAction SilentlyContinue
            Write-Host '  logon entry removed'
        }
    } else {
        Write-Host '  no logon entry to remove'
    }

    # Also clear the app's own setting, or the next manual launch would put the
    # logon entry straight back and the uninstall would look like it failed.
    $cfg = Join-Path $Path 'machines.json'
    if (Test-Path -LiteralPath $cfg) {
        if ($PSCmdlet.ShouldProcess($cfg, 'Set autostart=false')) {
            try {
                $c = Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json
                $c | Add-Member -NotePropertyName autostart -NotePropertyValue $false -Force
                ($c | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $cfg -Encoding utf8
                Write-Host '  autostart setting turned off in machines.json'
            } catch {
                Write-Host "  could not update machines.json: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }

    if ($RemoveFiles) {
        foreach ($n in 'InfraMonitor.exe', 'inframonitor.log', 'sigcache.json',
                       'alert_state.json', 'alert_state_local.json') {
            $p = Join-Path $Path $n
            if (Test-Path -LiteralPath $p) {
                if ($PSCmdlet.ShouldProcess($p, 'Delete')) {
                    Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
                    Write-Host ("  deleted {0}" -f $n)
                }
            }
        }
        Write-Host '  machines.json was KEPT - delete it by hand if you mean to' -ForegroundColor Yellow
    }
    Show-Status
    return
}

# -------------------------------------------------------------------- install
if ($Install) {
    Write-Host 'Installing Infra Monitor...' -ForegroundColor Cyan
    $src = Join-Path $Here 'InfraMonitor.exe'
    $exe = Join-Path $Path 'InfraMonitor.exe'

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($PSCmdlet.ShouldProcess($Path, 'Create directory')) {
            New-Item -ItemType Directory -Force -Path $Path | Out-Null
        }
    }

    if ($src -ne $exe) {
        if (-not (Test-Path -LiteralPath $src)) {
            throw "InfraMonitor.exe is not next to this script ($src). Copy it here first."
        }
        Stop-InfraMonitor | Out-Null
        if ($PSCmdlet.ShouldProcess($exe, 'Copy InfraMonitor.exe')) {
            Copy-Item -LiteralPath $src -Destination $exe -Force
            Write-Host ('  exe installed to {0}' -f $exe)
        }
    } else {
        Write-Host '  exe already in place'
    }

    if ($Config) {
        if (-not (Test-Path -LiteralPath $Config)) { throw "No such config file: $Config" }
        $args = @('--import-config', (Resolve-Path -LiteralPath $Config).Path, '--quiet')
        if ($Merge) { $args += '--merge' }
        if ($PSCmdlet.ShouldProcess($Config, 'Import configuration')) {
            # --quiet: the exe is a GUI-subsystem binary, so without it the
            # import would report through a message box and block this script
            # until somebody clicked OK.
            $p = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru
            if ($p.ExitCode -ne 0) {
                throw "Config import FAILED (exit $($p.ExitCode)). See inframonitor.log in $Path. Nothing was started."
            }
            Write-Host '  configuration imported'
        }
    }

    $cfg = Join-Path $Path 'machines.json'
    if (-not (Test-Path -LiteralPath $cfg)) {
        Write-Host '  WARNING: no machines.json here - Infra Monitor will monitor nothing.' -ForegroundColor Yellow
        Write-Host '           Re-run with -Config <exported file>, or use Settings > Import.' -ForegroundColor Yellow
    }

    if ($PSCmdlet.ShouldProcess($exe, 'Register to start at logon')) {
        # Ask the app to register itself, so the setting inside machines.json
        # and the registry value are written by the same code that reconciles
        # them at every launch. Writing the registry from here instead would
        # leave the app's own setting saying otherwise.
        $p = Start-Process -FilePath $exe -ArgumentList @('--register-autostart', '--quiet') -Wait -PassThru
        if ($p.ExitCode -eq 0) { Write-Host '  registered to start at logon' }
        else { Write-Host '  could not register autostart' -ForegroundColor Yellow }
    }

    if (-not $NoStart) {
        if ($PSCmdlet.ShouldProcess($exe, 'Start')) {
            Start-Process -FilePath $exe
            Start-Sleep -Seconds 2
            Write-Host '  started - look for the icon in the notification area'
        }
    }
    Show-Status
    Write-Host 'To undo all of this:  .\Install-InfraMonitor.ps1 -Uninstall' -ForegroundColor Cyan
    return
}

Show-Status
Write-Host 'Read-only. Use -Install or -Uninstall to change anything.' -ForegroundColor DarkGray
