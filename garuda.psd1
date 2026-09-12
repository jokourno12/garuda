#
# Module manifest for module 'garuda'
# Generated on: 15/06/2026
#

@{
    RootModule        = 'garuda.psm1'

    ModuleVersion     = '1.0.0'
    GUID              = 'd29a73fd-5765-41f7-85b5-293592103012'
    Author            = 'Joko Purnomo'
    Copyright         = '(c) 2026 Joko Purnomo. All rights reserved.'
    Description       = 'PowerShell-based, multithreaded platform for probing remote hosts. (Optional: Deno runtime for high-performance mode).'
    PowerShellVersion = '7.0'
    CompatiblePSEditions = @('Core')

    FunctionsToExport = @('Invoke-Garuda')
    AliasesToExport   = @('garuda')
    CmdletsToExport       = @()
    VariablesToExport     = @()

    PrivateData       = @{
        PSData = @{
            Tags       = @('Discovery', 'Scanner', 'Reconnaissance', 'Security')
            LicenseUri = 'https://github.com/jokourno12/garuda/blob/main/LICENSE'
            ProjectUri = 'https://github.com/jokourno12/garuda'
            ReleaseNotes = 'Initial public release of Garuda remote probing platform.'
        }
    }
}