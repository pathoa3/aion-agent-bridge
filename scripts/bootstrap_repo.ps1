param(
  [string]$RepoUrl = "https://github.com/pathoa3/aion-agent-bridge.git",
  [string]$WorkDir = "$env:TEMP\aion-agent-bridge"
)

Write-Host "This script clones or updates the bridge repo and commits the bootstrap files."
Write-Host "Do not paste GitHub tokens into ChatGPT. If prompted by git, use your GitHub username and a fine-grained PAT locally."

if (Test-Path $WorkDir) {
  Push-Location $WorkDir
  git pull
} else {
  git clone $RepoUrl $WorkDir
  Push-Location $WorkDir
}

Write-Host "Copy the files from this ZIP into $WorkDir, then run:"
Write-Host "git add ."
Write-Host "git commit -m 'Initialize agent bridge'"
Write-Host "git push"
Pop-Location
