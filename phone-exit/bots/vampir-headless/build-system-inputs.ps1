$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'Required MSVC toolchain is unavailable' }
$compiler = Join-Path $installation 'VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe'
$msbuild = Join-Path $installation 'MSBuild/Current/Bin/amd64/MSBuild.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Pinned MSVC 14.44.35207 is unavailable' }
$output = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../.tools/vampir-runtime-windows'))
[IO.Directory]::CreateDirectory($output) | Out-Null
$project = Join-Path $PSScriptRoot 'windows/system-inputs.vcxproj'
$source = Join-Path $PSScriptRoot 'windows/system-inputs.cpp'
$log = Join-Path $output 'build.log'
& $msbuild $project /t:Rebuild /p:Configuration=Release /p:Platform=x64 "/p:OutDir=$output/" "/p:IntDir=$output/obj/" /m:1 /nologo /verbosity:minimal *> $log
if ($LASTEXITCODE -ne 0) { throw "System input build failed; inspect $log" }
$binary = Join-Path $output 'vampir_system_inputs.dll'
$receipt = [ordered]@{
    schema_version = 1
    architecture = 'x64'
    compiler_version = '14.44.35207'
    windows_sdk = '10.0.22621.0'
    compiler_sha256 = (Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant()
    source_sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    project_sha256 = (Get-FileHash -LiteralPath $project -Algorithm SHA256).Hash.ToLowerInvariant()
    build_script_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
    binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
}
$text = $receipt | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $output 'receipt.json'), $text, [Text.UTF8Encoding]::new($false))
@{built=$true; bytes=(Get-Item -LiteralPath $binary).Length; sha256=$receipt.binary_sha256} | ConvertTo-Json -Compress
