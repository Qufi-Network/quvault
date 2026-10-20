# Builds + signs the Veyns Quantum Vault APK. Gradle is run via cmd so PowerShell does not
# wrap its stderr. Run: powershell -ExecutionPolicy Bypass -File C:\veynswallet\android\build-apk.ps1
$ErrorActionPreference = "Continue"
$proj = "C:\veynswallet"
$bt   = "C:\as\build-tools\36.1.0"
$log  = "$proj\android\gradle-term.log"
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-17.0.20.101-hotspot"
$env:PATH = "$env:JAVA_HOME\bin;" + $env:PATH
$env:ANDROID_HOME = "C:\as"

Set-Location $proj
Write-Host "[1/3] Gradle assembleRelease (via cmd, logging to gradle-term.log)..." -ForegroundColor Cyan
cmd /c "`"$proj\gradlew.bat`" assembleRelease -p `"$proj`" --stacktrace > `"$log`" 2>&1"
Write-Host ("gradle exit: {0}" -f $LASTEXITCODE)

$unsigned = Get-ChildItem "$proj\app\build\outputs\apk\release\*.apk" -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $unsigned) { Write-Host "No release APK produced. Tail of log:" -ForegroundColor Yellow; Get-Content $log -Tail 15; exit 1 }

Write-Host "[2/3] zipalign..." -ForegroundColor Cyan
$aligned = "$proj\app-release-aligned.apk"
& "$bt\zipalign.exe" -p -f 4 $unsigned.FullName $aligned

Write-Host "[3/3] apksigner sign..." -ForegroundColor Cyan
$signed = "$proj\veyns-quvault-release.apk"
$line = Get-Content "$proj\android\signing.env" | Where-Object { $_ -match '^BUBBLEWRAP_KEYSTORE_PASSWORD=' }
$pw = $line -replace '^BUBBLEWRAP_KEYSTORE_PASSWORD=',''
cmd /c "`"$bt\apksigner.bat`" sign --ks `"$proj\android\veyns-release.keystore`" --ks-key-alias veyns --ks-pass pass:$pw --key-pass pass:$pw --out `"$signed`" `"$aligned`""
Remove-Item $aligned -ErrorAction SilentlyContinue

Write-Host "=== RESULT ===" -ForegroundColor Green
Get-ChildItem $signed -ErrorAction SilentlyContinue | Select-Object Name, @{N='MB';E={[math]::Round($_.Length/1MB,2)}}, FullName
