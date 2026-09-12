function Invoke-Garuda {
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "src\index.ps1"

    & $scriptPath @args
}

Set-Alias -Name garuda -Value Invoke-Garuda