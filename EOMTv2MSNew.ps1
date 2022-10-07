<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 22.10.06.0840

<#
    .SYNOPSIS
        This script contains mitigations to help address the following vulnerabilities.
            CVE-2022-41040
    .DESCRIPTION
       This script has three operations it performs:
            Mitigation of CVE-2022-41040 via a URL Rewrite configuration. Note: this mitigates current known attacks.
    .PARAMETER RollbackMitigation
        If set, will only reverse the mitigations if present.
    .PARAMETER DoNotAutoUpdateEOMTv2
        If set, will not attempt to download and run latest EOMTv2 version from github.
    .EXAMPLE
		PS C:\> EOMTv2.ps1
		This will run the default mode which does the following:
            1. Checks if an updated version of EOMTv2 is available, downloads and runs latest version if so
            2. Downloads and installs the IIS URL rewrite tool.
            3. Applies the URL rewrite mitigation (only if vulnerable).
    .EXAMPLE
		PS C:\> EOMTv2.ps1 -RollbackMitigation
        This will only rollback the URL rewrite mitigation.
	.Link
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://aka.ms/privacy
#>

[Cmdletbinding()]
param (
    [switch]$RollbackMitigation,
    [switch]$DoNotAutoUpdateEOMTv2
)

$ProgressPreference = "SilentlyContinue"
$EOMTv2Dir = Join-Path $env:TEMP "EOMTv2"
$EOMTv2LogFile = Join-Path $EOMTv2Dir "EOMTv2.log"
$SummaryFile = "$env:SystemDrive\EOMTv2Summary.txt"
$EOMTv2DownloadUrl = 'https://github.com/microsoft/CSS-Exchange/releases/latest/download/EOMTv2.ps1'
$versionsUrl = 'https://aka.ms/EOMTv2-VersionsUri'
$MicrosoftSigningRoot2010 = 'CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$MicrosoftSigningRoot2011 = 'CN=Microsoft Root Certificate Authority 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'

#autopopulated by CSS-Exchange build
$BuildVersion = "22.10.06.0840"

# Force TLS1.2 to make sure we can download from HTTPS
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Run-Mitigate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Justification = 'Invalid rule result')]
    param(
        [string]$WebSiteName = "Default Web Site",
        [string]$Stage = "MitigationProcess",
        [switch]$RollbackMitigation

    )

    function Get-MsiProductVersion {
        param (
            [string]$filename
        )

        try {
            $windowsInstaller = New-Object -com WindowsInstaller.Installer

            $database = $windowsInstaller.GetType().InvokeMember(
                "OpenDatabase", "InvokeMethod", $Null,
                $windowsInstaller, @($filename, 0)
            )

            $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"

            $View = $database.GetType().InvokeMember(
                "OpenView", "InvokeMethod", $Null, $database, ($q)
            )

            try {
                $View.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $View, $Null) | Out-Null

                $record = $View.GetType().InvokeMember(
                    "Fetch", "InvokeMethod", $Null, $View, $Null
                )

                $productVersion = $record.GetType().InvokeMember(
                    "StringData", "GetProperty", $Null, $record, 1
                )

                return $productVersion
            } finally {
                if ($View) {
                    $View.GetType().InvokeMember("Close", "InvokeMethod", $Null, $View, $Null) | Out-Null
                }
            }
        } catch {
            throw "Failed to get MSI file version the error was: {0}." -f $_
        }
    }

    function Get-InstalledSoftwareVersion {
        param (
            [ValidateNotNullOrEmpty()]
            [string[]]$Name
        )

        try {
            $UninstallKeys = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )

            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

            $UninstallKeys += Get-ChildItem HKU: | Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } | ForEach-Object {
                "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            }

            foreach ($UninstallKey in $UninstallKeys) {
                $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue
                foreach ($n in $Name) {
                    $SwKeys = $SwKeys | Where-Object { $_.GetValue('DisplayName') -like "$n" }
                }
                if ($SwKeys) {
                    foreach ($SwKey in $SwKeys) {
                        if ($SwKey.GetValueNames().Contains("DisplayVersion")) {
                            return $SwKey.GetValue("DisplayVersion")
                        }
                    }
                }
            }
        } catch {
            Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
    }

    function Test-IIS10 {
        $iisRegPath = "hklm:\SOFTWARE\Microsoft\InetStp"

        if (Test-Path $iisRegPath) {
            $properties = Get-ItemProperty $iisRegPath
            if ($properties.MajorVersion -eq 10) {
                return $true
            }
        }

        return $false
    }

    function Get-URLRewriteLink {
        $DownloadLinks = @{
            "x86" = @{
                "de-DE" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_en-US.msi"
                "es-ES" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/D/8/1/D81E5DD6-1ABB-46B0-9B4B-21894E18B77F/rewrite_x86_zh-TW.msi"
            }
            "x64" = @{
                "de-DE" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_de-DE.msi"
                "en-US" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
                "es-ES" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_es-ES.msi"
                "fr-FR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_fr-FR.msi"
                "it-IT" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_it-IT.msi"
                "ja-JP" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ja-JP.msi"
                "ko-KR" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ko-KR.msi"
                "ru-RU" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_ru-RU.msi"
                "zh-CN" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-CN.msi"
                "zh-TW" = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_zh-TW.msi"
            }
        }

        if ([Environment]::Is64BitOperatingSystem) {
            $Architecture = "x64"
        } else {
            $Architecture = "x86"
        }

        if ((Get-Culture).Name -in @("de-DE", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "ko-KR", "ru-RU", "zn-CN", "zn-TW")) {
            $Language = (Get-Culture).Name
        } else {
            $Language = "en-US"
        }

        return $DownloadLinks[$Architecture][$Language]
    }

    #Configure Rewrite Rule consts
    $HttpRequestInput = '{UrlDecode:{REQUEST_URI}}'
    $root = 'system.webServer/rewrite/rules'
    $inbound = '.*'
    $name = 'PowerShell - inbound'
    $pattern = '.*autodiscover\.json.*Powershell.*'
    $filter = "{0}/rule[@name='{1}']" -f $root, $name
    $site = "IIS:\Sites\$WebSiteName"
    Import-Module WebAdministration

    if ($RollbackMitigation) {
        $Message = "Starting rollback of mitigation on $env:computername"
        $RegMessage = "Starting rollback of mitigation"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $mitigationFound = $false
        if (Get-WebConfiguration -Filter $filter -PSPath $site) {
            $mitigationFound = $true
            Clear-WebConfiguration -Filter $filter -PSPath $site
        }

        if ($mitigationFound) {
            $Rules = Get-WebConfiguration -Filter 'system.webServer/rewrite/rules/rule' -Recurse
            if ($null -eq $Rules) {
                Clear-WebConfiguration -PSPath $site -Filter 'system.webServer/rewrite/rules'
            }

            $Message = "Rollback of mitigation complete on $env:computername"
            $RegMessage = "Rollback of mitigation complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $Message = "Mitigation not present on $env:computername"
            $RegMessage = "Mitigation not present"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        }
    } else {
        $Message = "Starting mitigation process on $env:computername"
        $RegMessage = "Starting mitigation process"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

        if ($RewriteModule) {
            $Message = "IIS URL Rewrite Module is already installed on $env:computername"
            $RegMessage = "IIS URL Rewrite Module already installed"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } else {
            $DownloadLink = Get-URLRewriteLink
            $DownloadPath = Join-Path $EOMTv2Dir "\$($DownloadLink.Split("/")[-1])"
            $RewriteModuleInstallLog = Join-Path $EOMTv2Dir "\RewriteModuleInstall.log"

            $response = Invoke-WebRequest $DownloadLink -UseBasicParsing
            [IO.File]::WriteAllBytes($DownloadPath, $response.Content)

            $MSIProductVersion = Get-MsiProductVersion -filename $DownloadPath

            if ($MSIProductVersion -lt "7.2.1993") {
                $Message = "Incorrect IIS URL Rewrite Module downloaded on $env:computername"
                $RegMessage = "Incorrect IIS URL Rewrite Module downloaded"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }
            #KB2999226 required for IIS Rewrite 2.1 on IIS ver under 10
            if (!(Test-IIS10) -and !(Get-HotFix -Id "KB2999226" -ErrorAction SilentlyContinue)) {
                $Message = "Did not detect the KB2999226 on $env:computername. Please review the pre-reqs for this KB and download from https://support.microsoft.com/en-us/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c"
                $RegMessage = "Did not detect KB299226"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }

            $Message = "Installing the IIS URL Rewrite Module on $env:computername"
            $RegMessage = "Installing IIS URL Rewrite Module"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

            $arguments = "/i `"$DownloadPath`" /quiet /log `"$RewriteModuleInstallLog`""
            $msiexecPath = $env:WINDIR + "\System32\msiexec.exe"

            if (!(Confirm-Signature -filepath $DownloadPath -Stage $stage)) {
                $Message = "File present at $DownloadPath does not seem to be signed as expected, stopping execution."
                $RegMessage = "File downloaded for UrlRewrite MSI does not seem to be signed as expected, stopping execution"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                Write-Summary -NoRemediation:$DoNotRemediate
                throw
            }

            Start-Process -FilePath $msiexecPath -ArgumentList $arguments -Wait
            Start-Sleep -Seconds 15
            $RewriteModule = Get-InstalledSoftwareVersion -Name "*IIS*", "*URL*", "*2*"

            if ($RewriteModule) {
                $Message = "IIS URL Rewrite Module installed on $env:computername"
                $RegMessage = "IIS URL Rewrite Module installed"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
            } else {
                $Message = "Issue installing IIS URL Rewrite Module $env:computername"
                $RegMessage = "Issue installing IIS URL Rewrite Module"
                Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
                throw
            }
        }

        $Message = "Applying URL Rewrite configuration to $env:COMPUTERNAME :: $WebSiteName"
        $RegMessage = "Applying URL Rewrite configuration"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

        try {
            if ((Get-WebConfiguration -Filter $filter -PSPath $site).name -eq $name) {
                Clear-WebConfiguration -Filter $filter -PSPath $site
            }

            Add-WebConfigurationProperty -PSPath $site -filter $root -name '.' -value @{name = $name; patternSyntax = 'Regular Expressions'; stopProcessing = 'True' }
            Set-WebConfigurationProperty -PSPath $site -filter "$filter/match" -name 'url' -value $inbound
            Set-WebConfigurationProperty -PSPath $site -filter "$filter/conditions" -name '.' -value @{input = $HttpRequestInput; matchType = '0'; pattern = $pattern; ignoreCase = 'True'; negate = 'False' }
            Set-WebConfigurationProperty -PSPath $site -filter "$filter/action" -name 'type' -value 'AbortRequest'

            $Message = "Mitigation complete on $env:COMPUTERNAME :: $WebSiteName"
            $RegMessage = "Mitigation complete"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        } catch {
            $Message = "Mitigation failed on $env:COMPUTERNAME :: $WebSiteName"
            $RegMessage = "Mitigation failed"
            Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
            throw
        }
    }
}

function Write-Log {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'Invalid rule result')]
    param
    (
        [string]$Message,
        [string]$Path = $EOMTv2LogFile,
        [string]$Level = "Info"
    )

    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Write log entry to $Path
    "$FormattedDate $($Level): $Message" | Out-File -FilePath $Path -Append
}

function Set-LogActivity {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidAssignmentToAutomaticVariable', '', Justification = 'Invalid rule result')]
    [CmdletBinding(SupportsShouldProcess)]
    param (
        $Stage,
        $RegMessage,
        $Message,
        [switch]$Notice,
        [switch]$Error
    )
    if ($Notice) {
        $Level = "Notice"
    } elseif ($Error) {
        $Level = "Error"
    } else {
        $Level = "Info"
    }
    if ($Level -eq "Info") {
        Write-Verbose -Message $Message -Verbose
    } elseif ($Level -eq "Notice") {
        Write-Host -ForegroundColor Cyan -BackgroundColor black "NOTICE: $Message"
    } else {
        Write-Error -Message $Message
    }

    Write-Log -Message $Message -Level $Level
}

function Confirm-Signature {
    param(
        [string]$Filepath,
        [string]$Stage
    )

    $IsValid = $false
    $failMsg = "Signature of $Filepath not as expected. "
    try {
        if (!(Test-Path $Filepath)) {
            $IsValid = $false
            $failMsg += "Filepath does not exist"
            throw
        }

        $sig = Get-AuthenticodeSignature -FilePath $Filepath

        if ($sig.Status -ne 'Valid') {
            $IsValid = $false
            $failMsg += "Signature is not trusted by machine as Valid, status: $($sig.Status)"
            throw
        }

        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.VerificationFlags = "IgnoreNotTimeValid"

        $chainsCorrectly = $chain.Build($sig.SignerCertificate)

        if (!$chainsCorrectly) {
            $IsValid = $false
            $failMsg += "Signer certificate doesn't chain correctly"
            throw
        }

        if ($chain.ChainElements.Count -le 1) {
            $IsValid = $false
            $failMsg += "Certificate Chain shorter than expected"
            throw
        }

        $rootCert = $chain.ChainElements[$chain.ChainElements.Count - 1]

        if ($rootCert.Certificate.Subject -ne $rootCert.Certificate.Issuer) {
            $IsValid = $false
            $failMsg += "Top-level certifcate in chain is not a root certificate"
            throw
        }

        if ($rootCert.Certificate.Subject -eq $MicrosoftSigningRoot2010 -or $rootCert.Certificate.Subject -eq $MicrosoftSigningRoot2011) {
            $IsValid = $true
            $Message = "$Filepath is signed by Microsoft as expected, trusted by machine as Valid, signed by: $($sig.SignerCertificate.Subject), Issued by: $($sig.SignerCertificate.Issuer), with Root certificate: $($rootCert.Certificate.Subject)"
            $RegMessage = "$Filepath is signed by Microsoft as expected"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
        } else {
            $IsValid = $false
            $failMsg += "Unexpected root cert. Expected $MicrosoftSigningRoot2010 or $MicrosoftSigningRoot2011, but found $($rootCert.Certificate.Subject)"
            throw
        }
    } catch {
        $IsValid = $false
        Set-LogActivity -Stage $Stage -RegMessage $failMsg -Message $failMsg -Error
    }

    return $IsValid
}
function Write-Summary {
    param(
        [switch]$Pass,
        [switch]$NoRemediation
    )

    $RemediationText = ""
    if (!$NoRemediation) {
        $RemediationText = " and clear malicious files"
    }

    $summary = @"
EOMTv2 mitigation summary
Message: Microsoft attempted to mitigate and protect your Exchange server from CVE-2022-41040 $RemediationText.
For more information on these vulnerabilities please visit (https://aka.ms/Exchangevulns2)
Please review locations and files as soon as possible and take the recommended action.
Microsoft saved several files to your system to "$EOMTv2Dir". The only files that should be present in this directory are:
    a - EOMTv2.log
    b - RewriteModuleInstall.log
    c - one of the following IIS URL rewrite MSIs:
        rewrite_amd64_[de-DE,en-US,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_ x86_[de-DE,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_x64_[de-DE,es-ES,fr-FR,it-IT,ja-JP,ko-KR,ru-RU,zh-CN,zh-TW].msi
        rewrite_2.0_rtw_x86.msi
        rewrite_2.0_rtw_x64.msi
1 - Confirm the IIS URL Rewrite Module is installed. This module is required for the mitigation of CVE-2022-41040, the module and the configuration (present or not) will not impact this system negatively.
    a - If installed, Confirm the following entry exists in the "$env:SystemDrive\inetpub\wwwroot\web.config". If this configuration is not present, your server is not mitigated. This may have occurred if the module was not successfully installed with a supported version for your system.
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="PowerShell - inbound">
                    <match url=".*" />
                    <conditions>
                        <add input="{UrlDecode:{REQUEST_URI}}" pattern=".*autodiscover\.json.*Powershell.*" />
                    </conditions>
                    <action type="AbortRequest" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
"@

    if (Test-Path $SummaryFile) {
        Remove-Item $SummaryFile -Force
    }

    $summary = $summary.Replace("`r`n", "`n").Replace("`n", "`r`n")
    $summary | Out-File -FilePath $SummaryFile -Encoding ascii -Force
}

if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Unable to launch EOMTv2.ps1: please re-run as administrator."
    exit
}

if ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Error "Unsupported version of PowerShell on $env:computername - The Exchange On-premises Mitigation Tool supports PowerShell 3 and later"
    exit
}

# Main
try {
    $Stage = "CheckEOMTv2Version"

    if (!(Test-Path $EOMTv2Dir)) {
        New-Item -ItemType Directory $EOMTv2Dir | Out-Null
    }

    try {
        $Message = "Checking if EOMTv2 is up to date with $versionsUrl"
        Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message
        $latestEOMTv2Version = $null
        $versionsData = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest $versionsUrl -UseBasicParsing).Content) | ConvertFrom-Csv
        $latestEOMTv2Version = ($versionsData | Where-Object -Property File -EQ "EOMTv2.ps1").Version
    } catch {
        $Message = "Cannot check version info at $versionsUrl to confirm EOMTv2.ps1 is latest version. Version currently running is $BuildVersion. Please download latest EOMTv2 from $EOMTv2DownloadUrl and re-run EOMTv2, unless you just did so. Exception: $($_.Exception)"
        $RegMessage = "Cannot check version info at $versionsUrl to confirm EOMTv2.ps1 is latest version. Version currently running is $BuildVersion. Continuing with execution"
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
    }

    $DisableAutoupdateIfneeded = "If you are getting this error even with updated EOMTv2, re-run with -DoNotAutoUpdateEOMTv2 parameter";

    $Stage = "AutoupdateEOMTv2"
    if ($latestEOMTv2Version -and ($BuildVersion -ne $latestEOMTv2Version)) {
        if ($DoNotAutoUpdateEOMTv2) {
            $Message = "EOMTv2.ps1 is out of date. Version currently running is $BuildVersion, latest version available is $latestEOMTv2Version. We strongly recommend downloading latest EOMTv2 from $EOMTv2DownloadUrl and re-running EOMTv2. DoNotAutoUpdateEOMTv2 is set, so continuing with execution"
            $RegMessage = "EOMTv2.ps1 is out of date. Version currently running is $BuildVersion, latest version available is $latestEOMTv2Version.  DoNotAutoUpdateEOMTv2 is set, so continuing with execution"
            Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Notice
        } else {
            $Stage = "DownloadLatestEOMTv2"
            $EOMTv2LatestFilepath = Join-Path $EOMTv2Dir "EOMTv2_$latestEOMTv2Version.ps1"
            try {
                $Message = "Downloading latest EOMTv2 from $EOMTv2DownloadUrl"
                Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message
                Invoke-WebRequest $EOMTv2DownloadUrl -OutFile $EOMTv2LatestFilepath -UseBasicParsing
            } catch {
                $Message = "Cannot download latest EOMTv2.  Please download latest EOMTv2 yourself from $EOMTv2DownloadUrl, copy to necessary machine(s), and re-run. $DisableAutoupdateIfNeeded. Exception: $($_.Exception)"
                $RegMessage = "Cannot download latest EOMTv2 from $EOMTv2DownloadUrl. Stopping execution."
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                throw
            }

            $Stage = "RunLatestEOMTv2"
            if (Confirm-Signature -Filepath $EOMTv2LatestFilepath -Stage $Stage) {
                $Message = "Running latest EOMTv2 version $latestEOMTv2Version downloaded to $EOMTv2LatestFilepath"
                Set-LogActivity -Stage $Stage -RegMessage $Message -Message $Message

                try {
                    & $EOMTv2LatestFilepath @PSBoundParameters
                    exit
                } catch {
                    $Message = "Run failed for latest EOMTv2 version $latestEOMTv2Version downloaded to $EOMTv2LatestFilepath, please re-run $EOMTv2LatestFilepath manually. $DisableAutoupdateIfNeeded. Exception: $($_.Exception)"
                    $RegMessage = "Run failed for latest EOMTv2 version $latestEOMTv2Version"
                    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                    throw
                }
            } else {
                $Message = "File downloaded to $EOMTv2LatestFilepath does not seem to be signed as expected, stopping execution."
                $RegMessage = "File downloaded for EOMTv2.ps1 does not seem to be signed as expected, stopping execution"
                Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message -Error
                Write-Summary -NoRemediation:$DoNotRemediate
                throw
            }
        }
    }

    $Stage = "EOMTv2Start"

    $Message = "Starting EOMTv2.ps1 version $BuildVersion on $env:computername"
    $RegMessage = "Starting EOMTv2.ps1 version $BuildVersion"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    $Message = "EOMTv2 precheck complete on $env:computername"
    $RegMessage = "EOMTv2 precheck complete"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message

    if ($RollbackMitigation) {
        Run-Mitigate -RollbackMitigation
    }

    else {
        $Message = "Applying mitigation on $env:computername"
        $RegMessage = ""
        Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
        Run-Mitigate
    }

    $Message = "EOMTv2.ps1 complete on $env:computername, please review EOMTv2 logs at $EOMTv2LogFile and the summary file at $SummaryFile"
    $RegMessage = "EOMTv2.ps1 completed successfully"
    Set-LogActivity -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -Pass -NoRemediation:$DoNotRemediate #Pass
} catch {
    $Message = "EOMTv2.ps1 failed to complete on $env:computername, please review EOMTv2 logs at $EOMTv2LogFile and the summary file at $SummaryFile - $_"
    $RegMessage = "EOMTv2.ps1 failed to complete"
    Set-LogActivity -Error -Stage $Stage -RegMessage $RegMessage -Message $Message
    Write-Summary -NoRemediation:$DoNotRemediate #Fail
}

# SIG # Begin signature block
# MIIntgYJKoZIhvcNAQcCoIInpzCCJ6MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDoH/5oQdIcBLQY
# TKnvGVhunCMNV1sOgXGXfxDnMhw+haCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZizCCGYcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgpkH8Sfu3
# K1hTPYZLbn2PoPqSKeFAubBuwxPsWqokg4wwWgYKKwYBBAGCNwIBDDFMMEqgGoAY
# AEMAUwBTACAARQB4AGMAaABhAG4AZwBloSyAKmh0dHBzOi8vZ2l0aHViLmNvbS9t
# aWNyb3NvZnQvQ1NTLUV4Y2hhbmdlIDANBgkqhkiG9w0BAQEFAASCAQBDFE8/gI+/
# ShLiuMUi4r8LgAZvvSnDULHd/lobGgu9H7wcjobcWYb91PLdCxplDSrD/16kLLTc
# WXkL5bIxx5yXyMtd21DlpNORg+znw0/eAmNJSykUqWumCuzUUbDuiS7A7roG3IfS
# aMN+If2nLvdb91kNZpUJAsBq7lMSHNeYxxQ8LeJIhchDCekR/pQJOrlzyLmGzXXa
# /O3vuuSLlpWAw3Bqs1gCb3l8x64PepeuIDPc4xHUnmU8lgcoZKZzANw65CLw14Zn
# tl5pWlwhS4YTAIVjLT7GJQD4Sl4d8FLAMjRfxoL3aMyzitgI087D5Li5yV06Oq3o
# 14OjWXgHPevcoYIW/TCCFvkGCisGAQQBgjcDAwExghbpMIIW5QYJKoZIhvcNAQcC
# oIIW1jCCFtICAQMxDzANBglghkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIB
# QASCATwwggE4AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIJutYAgR
# BHLDGPaFJycFmlfUjewioxO+XMJ+7vRwR5IeAgZjI3haVgcYEzIwMjIxMDA2MTUx
# OTMwLjc3NFowBIACAfSggdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlv
# bnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIRVDCCBwwwggT0oAMC
# AQICEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjExMjAyMTkwNTE2WhcNMjMwMjI4MTkw
# NTE2WjCByjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMG
# A1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhh
# bGVzIFRTUyBFU046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQC4E/lXXKMsy9rVa2a8bRb0Ar/Pj4+bKiAgMgKayvCMFn3ddGof8eWFgJWp5JdK
# jWjrnmW1r9tHpcP2kFpjXp2Udrj55jt5NYi1MERcoIo+E29XuCwFAMJftGdvsWea
# /OTQPIFsZEWqEteXdRncyVwct5xFzBIC1JWCdmfc7R59RMIyvgWjIz8356mweowk
# OstN1fe53KIJ8flrYILIQWsNRMOT3znAGwIb9kyL54C6jZjFxOSusGYmVQ+Gr/qZ
# QELw1ipx9s5jNP1LSpOpfTEBFu+y9KLNBmMBARkSPpTFkGEyGSwGGgSdOi6BU6FP
# K+6urZ830jrRemK4JkIJ9tQhlGcIhAjhcqZStn+38lRjVvrfbBI5EpI2NwlVIK2i
# bGW7sWeTAz/yNPNISUbQhGAJse/OgGj/1qz/Ha9mqfYZ8BHchNxn08nWkqyrjrKi
# cQyxuD8mCatTrVSbOJYfQyZdHR9a4vgyGeZEXBYQNAlIuB37QCOAgs/VeDU8M4dc
# /IlrTyC0uV1SS4Gk8zV+5X5eRu+XORN8FWqzI6k/9y6cWwOWMK6aUN1XqLcaF/sm
# 9rX84eKW2lhDc3C31WLjp8UOfOHZfPuyy54xfilnhhCPy4QKJ9jggoqqeeEhCEfg
# DYjy+PByV/e5HDB2xHdtlL93wltAkI3aCxo84kVPBCa0OwIDAQABo4IBNjCCATIw
# HQYDVR0OBBYEFI26Vrg+nGWvrvIh0dQPEonENR0QMB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggIBAHGzWh29ibBNro3n
# s8E3EOHGsLB1Gzk90SFYUKBilIu4jDbR7qbvXNd8nnl/z5D9LKgw3T81jqy5tMiW
# p+p4jYBBk3PRx1ySqLUfhF5ZMWolRzW+cQZGXV38iSmdAUG0CpR5x1rMdPIrTczV
# UFsOYGqmkoUQ/dRiVL4iAXJLCNTj4x3YwIQcCPt0ijJVinPIMAYzA8f99Bbeisky
# I0BHGAd0kGUX2I2/puYnlyS8toBnANjh21xgvEuaZ2dvRqvWk/i1XIlO67au/XCe
# MTvXhPOIUmq80U32Tifw3SSiBKTyir7moWH1i7H2q5QAnrBxuyy//ZsDfARDV/At
# mj5jr6ATfRHDdUanQpeoBS+iylNU6RARu8g+TMCu/ZndZmrs9w+8galUIGg+GmlN
# k07fXJ58Oc+qFqgNAsNkMi+dSzKkWGA4/klJFn0XichXL8+t7KOayXKGzQja6Cdt
# CjisnyS8hbv4PKhaeMtf68wJWKKOs0tt2AJfYC5vSbH9ck8BGj2e/yQXEZEu88L5
# /fHK5XUk/IKXx3zaLkxXTSZ43Ea/WKXVBzMasHZ3Pmny0moEekAXx1UhLNNYv4Vu
# m33VirxSB6r/GKQxFSHu7yFfrWQpYyyDH119TmhAedS8T1VabqdtO5ZP2E14TK82
# Vyxy3xEPelOo4dRIlhm7XY6k9B68MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJ
# mQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1
# WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjK
# NVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhg
# fWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJp
# rx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/d
# vI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka9
# 7aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKR
# Hh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9itu
# qBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyO
# ArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItb
# oKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6
# bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6t
# AgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQW
# BBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYz
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnku
# aHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA
# QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2
# VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwu
# bWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEw
# LTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
# MjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/q
# XBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6
# U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVt
# I1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis
# 9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTp
# kbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0
# sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138e
# W0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJ
# sWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7
# Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0
# dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQ
# tB1VM1izoXBm8qGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUzNEYt
# OUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUAku/zYujnqapN6BJ9MJ5jtgDrlOuggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAObo/QQwIhgP
# MjAyMjEwMDYxNTA2NDRaGA8yMDIyMTAwNzE1MDY0NFowdDA6BgorBgEEAYRZCgQB
# MSwwKjAKAgUA5uj9BAIBADAHAgEAAgIRCDAHAgEAAgISdjAKAgUA5upOhAIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAIUiI9ac8zuzt8D9smq60G2EuhFNTIQz
# wDRh/WeULPojVDBSZt6TekuxOTPLumHWNne7yH9S3xcDeg72ipdSncVvJRoDoFs5
# n3UQ/LLtrK2mmIaEWGFT8feoLSxIjdxg9QGet5QfQ5FeXheKV9dwdchbpH9rvwx4
# wC5NYEQpW2LqMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAGZyI+vrbZ9vosAAQAAAZkwDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgXrGZGAie
# h2XudOuQKU0Yz4QBiRLginFMRRNqIBadVPgwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCBmfWn58qKN7WWpBTYOrUO1BSCSnKPLC/G7wCOIc2JsfjCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABmciPr622fb6LAAEA
# AAGZMCIEIIDcaKFee7xjZUhT4xTBEisO4h/rnclITNhfbYJ2KcQEMA0GCSqGSIb3
# DQEBCwUABIICAJX5L3SSxJsyK0zN1clGTSrjJhmez0nYQP+NKnGOd7qQEBABl+rl
# bAL4VU5nQ5R1ru+lF22xDbUfuNUTTvtUtzDoAlIyoM/aHWxNWd+ee2sQCAF5NHMF
# c5Y4AQFeBUW/z4IcOKl4MWxFCUKqi8k6QHNosXiqC/pyqXAavS6xS2yX8BePyihv
# 2QFj+pBnebrYrYmfAzGEQbfh7ko3RzxCShG2Cy0KwaCOHM4eQuCixS6+TgNeKjl8
# K6h4yin6SGJZfbMghwwNxyaT8V/VnWveTlnH5FlbQb9EnfzXPN6h1dhx9NzfYaO2
# pI/2L+LzZTB4xS6ucawMgaC19WJ4elFUPMNe1K9vcUjmBP/hPhkDo+eXSTAEslWg
# aMAi0r1SmkmZfT1t82B/lZev2XD6V30DSTuWAlj+paa7DdlsYjPl5Jjrg1Mhgg6p
# YE6bfJc0/na0T06XiNLhlbzEXQAWmWftvcDtrNat5Zb9F0MqMLilRS8wOCWs9dX9
# DmGKxJ5tqQFIASp1OxWyj/uL539H/Ugo8mDSb2lu8TJCFv9UluvAcwAuKaNXPmdY
# +kdRdDRCsj9XLdLGqXBOb1BRRYq5K0MuV2aNESMEFANJ0RouR655iGCBrVrto0xe
# 32cVQ4CdDt/jVPqiUDj+7b8XdEZgBoxsLnko5dfy4IJKPKWGU2nf4IfW
# SIG # End signature block
