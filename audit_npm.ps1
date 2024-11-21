# Read the JSON file containing package and vulnerability details
$json = Get-Content -Path "audit.json" -Raw | ConvertFrom-Json

# Initialize the summary of vulnerabilities by severity level
$results = @{
    high = @()
    moderate = @()
    low = @()
    info = @()
}

foreach ($vulnerability in $json.vulnerabilities.PSObject.Properties) {
    $name = $vulnerability.Name
    $details = $vulnerability.Value
    $severity = $details.severity
    $version = $details.range || "N/A"
    $fixname = if ($details.fixAvailable) { $details.fixAvailable.name } else { "N/A" }
    $fixversion = if ($details.fixAvailable) { $details.fixAvailable.version } else { "N/A" }
    $fixmajor = if ($details.fixAvailable) { $details.fixAvailable.isSemVerMajor } else { "N/A" }

    # Categorize by severity
    if ($severity -eq "high") {
        $results.high += [PSCustomObject]@{ Name = $name; Version = $version; Fixname = $fixname; Fixversion = $fixversion; Fixmajor = $fixmajor }
    } elseif ($severity -eq "moderate") {
        $results.moderate += [PSCustomObject]@{ Name = $name; Version = $version; Fixname = $fixname; Fixversion = $fixversion; Fixmajor = $fixmajor }
    } elseif ($severity -eq "low") {
        $results.low += [PSCustomObject]@{ Name = $name; Version = $version; Fixname = $fixname; Fixversion = $fixversion; Fixmajor = $fixmajor }
    } elseif ($severity -eq "info") {
        $results.info += [PSCustomObject]@{ Name = $name; Version = $version; Fixname = $fixname; Fixversion = $fixversion; Fixmajor = $fixmajor }
    }
}

# Build the comment in Markdown
$commentContent = "# NPM Audit Summary 📊`n"

# High Severity Vulnerabilities Section
$commentContent += "## 🔴 High Vulnerabilities (Total: $($results.high.Count))`n"
if ($results.high.Count -gt 0) {
    foreach ($item in $results.high) {
        Write-Output "Package Name: $($item.Name), Version: $($item.Version), FixAvailable: $($item.Fixname) - $($item.Fixversion) (Major: $($item.Fixmajor))"
        $commentContent += "- **Package**: $($item.Name), **Version**: $($item.Version), **FixAvailable**: $($item.Fixname) - $($item.Fixversion) (Major: $($item.Fixmajor))`n"
    }
} else {
    $commentContent += "No high severity vulnerabilities found.`n"
}

# Moderate Severity Vulnerabilities Section
$commentContent += "`n## 🟠 Moderate Vulnerabilities (Total: $($results.moderate.Count))`n"
if ($results.moderate.Count -gt 0) {
    foreach ($item in $results.moderate) {
        Write-Output "Package Name: $($item.Name), Version: $($item.Version), FixAvailable: $($item.Fixname) - $($item.Fixversion) (Major: $($item.Fixmajor))"
        $commentContent += "- **Package**: $($item.Name), **Version**: $($item.Version), **FixAvailable**: $($item.Fixname) - $($item.Fixversion) (Major: $($item.Fixmajor))`n"
    }
} else {
    $commentContent += "No moderate severity vulnerabilities found.`n"
}

# Low Severity Vulnerabilities Section
$commentContent += "`n## 🟢 Low Vulnerabilities (Total: $($results.low.Count))`n"
if ($results.low.Count -gt 0) {
    foreach ($item in $results.low) {
        Write-Output "Package Name: $($item.Name), Version: $($item.Version), FixAvailable: $($item.Fixname) - $($item.Fixversion) (Major: $($item.Fixmajor))"
        $commentContent += "- **Package**: $($item.Name), **Version**: $($item.Version), **FixAvailable**: $($item.Fixname) - $($item.Fixversion) (Major: $($item.Fixmajor))`n"
    }
} else {
    $commentContent += "No low severity vulnerabilities found.`n"
}

# Send the comment via Azure DevOps API
$repositoryId = "$env:BUILD_REPOSITORY_NAME"
$prId = "$env:SYSTEM_PULLREQUEST_PULLREQUESTID"
if (-not $prId) {
    Write-Output "No PR ID available. Exiting without adding a comment."
    exit 0
}

$url = "$($env:SYSTEM_TEAMFOUNDATIONCOLLECTIONURI)$($env:SYSTEM_TEAMPROJECT)/_apis/git/repositories/$repositoryId/pullRequests/$prId/threads?api-version=7.2-preview.1"

$body = @{
    "comments" = @(@{
        "parentCommentId" = 0
        "content" = $commentContent
        "commentType" = "text"
    })
    "status" = "active"
} | ConvertTo-Json

try {
    Invoke-RestMethod -Uri $url -Method Post -Headers @{
        Authorization = "Bearer $env:SYSTEM_ACCESSTOKEN"
        "Content-Type" = "application/json"
    } -Body $body
    Write-Output "Comment successfully added."
} catch {
    Write-Error "Error while adding the comment: $_"
}
