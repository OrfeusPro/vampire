param([ValidateSet('start','status','stop','retry')][string]$Action='start')
$ErrorActionPreference='Stop'
$python=(Get-Command python.exe -ErrorAction Stop).Source
& $python -X utf8 (Join-Path $PSScriptRoot 'knowledge-index.py') update-watch $Action
if($LASTEXITCODE -ne 0){throw 'Не удалось выполнить команду наблюдателя обновлений Vampir.'}
