function Invoke-WinVulmap {
    <#
.SYNOPSIS
Local vulnerability scanner
.DESCRIPTION
Gets installed software information from the local host and asks to vulmon.com if vulnerabilities and exploits exists. 
.PARAMETER DefaultMode
Conducts a vulnerability scanning. Default mode.
.PARAMETER OnlyExploitableVulns
Conducts a vulnerability scanning and only shows vulnerabilities that have exploits.
.PARAMETER DownloadExploit
Downloads given exploit.
.PARAMETER DownloadAllExploits
Scans the computer and downloads all available exploits.
.EXAMPLE
PS> Invoke-WinVulmap
Default mode. Conducts a vulnerability scanning.
.EXAMPLE
PS> Invoke-WinVulmap -OnlyExploitableVulns
Conducts a vulnerability scanning and only shows vulnerabilities that have exploits
.EXAMPLE
PS> Invoke-WinVulmap -DownloadExploit EDB9386
Downloads given exploit
.EXAMPLE
PS> Invoke-WinVulmap -DownloadAllExploits
Scans the computer and downloads all available exploits
.LINK
https://github.com/krishpranav/winvulnmap
https://github.com/yavuzatlas/vulmap-windows

#>

    Param (
        [switch] $DefaultMode,
        [switch] $OnlyExploitableVulns,
        [string] $DownloadExploit = "",
        [switch] $DownloadAllExploits,
        [switch] $Help
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

    function Send-Request($ProductList) {
        $product_list = '"product_list": ' + $ProductList

        $json_request_data = '{'
        $json_request_data = $json_request_data + '"os": "' + (Get-CimInstance Win32_OperatingSystem).Caption + '",'
        $json_request_data = $json_request_data + $product_list
        $json_request_data = $json_request_data + '}'
        

    }

}