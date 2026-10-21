$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$executable = Join-Path $projectRoot 'app\AnyOTPManager.exe'
if (-not (Test-Path -LiteralPath $executable)) { throw 'Published application is missing.' }
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class AnyOtpStartupWindow {
    private delegate bool WindowCallback(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback, IntPtr state);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassNameW(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll")] private static extern bool PostMessageW(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
    public static IntPtr Find(int process) {
        IntPtr found=IntPtr.Zero;
        EnumWindows((window,state) => {
            uint owner; GetWindowThreadProcessId(window,out owner);
            if(owner!=(uint)process) return true;
            var title=new StringBuilder(128); GetWindowTextW(window,title,title.Capacity);
            var kind=new StringBuilder(256); GetClassNameW(window,kind,kind.Capacity);
            if(title.ToString()=="AnyOTPManager" && kind.ToString().StartsWith("HwndWrapper")) { found=window; return false; }
            return true;
        },IntPtr.Zero);
        return found;
    }
    public static bool Close(IntPtr window, int process) {
        uint owner; GetWindowThreadProcessId(window,out owner);
        return owner==(uint)process && PostMessageW(window,0x10,IntPtr.Zero,IntPtr.Zero);
    }
}
'@
$started = Start-Process -FilePath $executable -WorkingDirectory (Split-Path $executable) -WindowStyle Hidden -PassThru
try {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $window = [IntPtr]::Zero
    while ($timer.Elapsed.TotalSeconds -lt 15 -and -not $started.HasExited) {
        $window = [AnyOtpStartupWindow]::Find($started.Id)
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    }
    if ($window -eq [IntPtr]::Zero) { throw 'Published WPF window did not start.' }
    if (-not [AnyOtpStartupWindow]::Close($window, $started.Id)) { throw 'Published WPF window could not be closed.' }
    if (-not $started.WaitForExit(10000) -or $started.ExitCode -ne 0) { throw 'Published WPF shutdown failed.' }
    $report = [ordered]@{
        Status = 'VERIFIED_RUNTIME'
        PublishedExecutableStarted = $true
        WpfMainWindowFound = $true
        NormalShutdown = $true
        ExitCode = $started.ExitCode
        RealProfileImport = 'NOT RUN'
        ActiveAnyOtpTransfer = 'NOT RUN'
        LiveAccountAcceptance = 'NOT RUN'
        Sha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash
    }
    $report | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $projectRoot 'artifacts\published-startup.json') -Encoding UTF8
    $report | ConvertTo-Json
} finally {
    if (-not $started.HasExited) {
        $ownedWindow = [AnyOtpStartupWindow]::Find($started.Id)
        if ($ownedWindow -ne [IntPtr]::Zero) { [AnyOtpStartupWindow]::Close($ownedWindow,$started.Id) | Out-Null }
        if (-not $started.WaitForExit(3000)) { $started.Kill(); $started.WaitForExit() }
    }
    $started.Dispose()
}
