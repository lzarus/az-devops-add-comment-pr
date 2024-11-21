# Read the audit JSON file
$json = Get-Content -Path "audit.json" -Raw | ConvertFrom-Json

# Initialize variables
$commentContent = "# NuGet Audit Summary 📦`n"

# Iterate through projects
foreach ($project in $json.projects) {
    $projectName = Split-Path -Leaf $project.path
    $commentContent += "`n## Project: $projectName`n"
    
    # Group vulnerabilities by severity
    $vulnerabilities = @{
        High = @()
        Moderate = @()
        Low = @()
        Info = @()
    }

    foreach ($framework in $project.frameworks) {
        foreach ($packageType in @('topLevelPackages', 'transitivePackages')) {
            if ($framework.PSObject.Properties[$packageType]) {
                foreach ($package in $framework.$packageType) {
                    foreach ($vulnerability in $package.vulnerabilities) {
                        $severity = $vulnerability.severity
                        $entry = [PSCustomObject]@{
                            Id = $package.id
                            ResolvedVersion = $package.resolvedVersion
                            AdvisoryUrl = $vulnerability.advisoryurl
                        }
                        $vulnerabilities.$severity += $entry
                    }
                }
            }
        }
    }

    # Format vulnerabilities by severity
    foreach ($severity in $vulnerabilities.Keys) {
        $total = $vulnerabilities.$severity.Count
        $emoji = switch ($severity) {
            "High"      { "🔴" }
            "Moderate"  { "🟠" }
            "Low"       { "🟢" }
            "Info"      { "🔵" }
            default     { "" }
        }
        $commentContent += "`n### $emoji $severity Vulnerabilities (Total: $total)`n"
        
        if ($total -gt 0) {
            foreach ($entry in $vulnerabilities.$severity) {
                $commentContent += "- **Package**: $($entry.Id), **Version**: $($entry.ResolvedVersion), [Advisory]($($entry.AdvisoryUrl))`n"
            }
        } else {
            $commentContent += "No $severity vulnerabilities found.`n"
        }
    }
}

# Output the comment for debugging
Write-Output "### Comment Content:"
Write-Output $commentContent

# (Optional) Send to Azure DevOps as a PR comment
# Replace this section with your API logic for sending the comment
