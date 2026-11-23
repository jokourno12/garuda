. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'Email.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'Phone.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'Url.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'Ip.ps1'))"
. "$([System.IO.Path]::Combine($PSScriptRoot, 'Private', 'Hash.ps1'))"

function tracer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Email')]
        [string]$email,

        [Parameter(Mandatory = $true, ParameterSetName = 'Phone')]
        [string]$phone,

        [Parameter(Mandatory = $true, ParameterSetName = 'Url')]
        [string]$url,

        [Parameter(Mandatory = $true, ParameterSetName = 'Ip')]
        [string]$ip,

        [Parameter(Mandatory = $true, ParameterSetName = 'Hash')]
        [string]$hash
    )

    switch ($PSCmdlet.ParameterSetName) {
        'Email' {
            Write-Host "Tracing Email: $email" @Cha
            email -target $email
        }
        'Phone' {
            Write-Host "Tracing Phone: $phone" @Cha
            phone -target $phone
        }
        'Url' {
            Write-Host "Tracing Url: $url" @Cha
            url -target $url
        }
        'Ip' {
            Write-Host "Tracing IP: $ip" @Cha
            ip -target $ip
        }
        'Hash' {
            Write-Host "Tracing Hash: $hash" @Cha
            hash -target $hash
        }
    }
}