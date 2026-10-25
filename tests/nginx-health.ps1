# Verifies the separately configured Nginx deployment.
# This test does not modify the Ghost authentication path.

$ErrorActionPreference = "Stop"

$container = "ghost-proxy-nginx-health-test"
$image = "ghost-proxy-nginx-health"

function Cleanup {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    docker rm -f $container 2>$null | Out-Null
    docker image rm $image 2>$null | Out-Null

    $ErrorActionPreference = $previousPreference
}

try {
    Write-Host "Checking Docker..."
    docker info | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker daemon is not available."
    }

    Write-Host "Building Nginx image..."
    docker build -t $image .\deployments\nginx
    if ($LASTEXITCODE -ne 0) {
        throw "Nginx Docker image build failed."
    }

    $ErrorActionPreference = "Continue"
    docker rm -f $container 2>$null | Out-Null
    $ErrorActionPreference = "Stop"

    Write-Host "Starting Nginx..."
    docker run -d --name $container -p 18080:8080 $image | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Nginx container failed to start."
    }

    Write-Host "Waiting for Nginx..."
    $health = $null

    for ($i = 0; $i -lt 20; $i++) {
        try {
            $health = Invoke-WebRequest -Uri "http://127.0.0.1:18080/health" -UseBasicParsing -TimeoutSec 2

            if ($health.StatusCode -eq 200) {
                break
            }
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }

    if (-not $health -or $health.StatusCode -ne 200) {
        throw "Nginx health endpoint did not return HTTP 200."
    }

    if ($health.Content.Trim() -ne "ghost-nginx-ok") {
        throw "Unexpected health response: $($health.Content)"
    }

    Write-Host "Checking root page..."
    $root = Invoke-WebRequest -Uri "http://127.0.0.1:18080/" -UseBasicParsing -TimeoutSec 5

    if ($root.StatusCode -ne 200) {
        throw "Nginx root page returned HTTP $($root.StatusCode)."
    }

    if ($root.Content -notmatch "Ghost Proxy") {
        throw "Nginx root page did not contain expected project content."
    }

    $running = docker ps --filter "name=$container" --filter "status=running" --format "{{.Names}}"

    if ($running -ne $container) {
        throw "Nginx container is not running."
    }

    Write-Host ""
    Write-Host "NGINX HEALTH TEST: PASS"
}
catch {
    Write-Error $_
    exit 1
}
finally {
    Cleanup
}
