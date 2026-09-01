. "$([System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, '..', 'Modules', 'Discover', 'Discover.ps1')))"

function discoverCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$targets
    )

    discover -targets $targets
}