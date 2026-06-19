# Build frontend and copy to Go embed directory, then build Go binary
Write-Host "=== Building Frontend ===" -ForegroundColor Cyan
Set-Location -LiteralPath "$PSScriptRoot\frontend"
npm run build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Copying to Go embed ===" -ForegroundColor Cyan
Copy-Item -LiteralPath "$PSScriptRoot\frontend\dist" -Destination "$PSScriptRoot\internal\webserver\frontend\dist" -Recurse -Force

Write-Host "`n=== Building Go Binary ===" -ForegroundColor Cyan
Set-Location -LiteralPath $PSScriptRoot
go build -ldflags="-s -w" -o ares.exe ./cmd/ares/
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n=== Build Complete: ares.exe ===" -ForegroundColor Green
