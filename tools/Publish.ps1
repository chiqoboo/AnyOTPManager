$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $projectRoot 'src\AnyOTPManager.App\AnyOTPManager.App.csproj'
$destination = Join-Path $projectRoot 'app'
dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -p:DebugSymbols=false -o $destination
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut((Join-Path $projectRoot 'AnyOTPManager.lnk'))
$shortcut.TargetPath = Join-Path $destination 'AnyOTPManager.exe'
$shortcut.WorkingDirectory = $destination
$shortcut.IconLocation = $shortcut.TargetPath
$shortcut.Description = 'AnyOTPManager — çoklu OTP kayıtları'
$shortcut.Save()
Get-Item -LiteralPath (Join-Path $destination 'AnyOTPManager.exe') | Select-Object FullName,Length
