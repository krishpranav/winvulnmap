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
        
        $postParams = @{querydata = $json_request_data}
        return (Invoke-WebRequest -Uri https://vulmon.com/scannerapi_vv211 -Method POST -Body $postParams).Content
    }

    function Get-ProductList() {
        $registry_paths = ("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") 

        $objectArray = @();

        foreach ($registry_paths in $registry_paths) {
            $subkeys = Get-ChildItem -Path $registry_path

            ForEach ($key in $subkeys) {
                $DisplayName = $key.getValue('DisplayName');

                if (![string]::IsNullOrEmpty($DisplayName)) {
                    $DisplayVersion = $key.GetValue('DisplayVersion');

                    $Object = [pscustomobject]@{
                        DisplayName = $DisplayName.Trim();
                        DisplayVersion = $DisplayVersion;
                        NameVersionPair = $DisplayName.Trim() + $DisplayVersion;
                    }

                    $Object.pstypenames.insert(0, 'System.Software.Inventory')

                    $objectArray += $Object
                }
            }
        }

        $objectArray | sort-object NameVersionPair -unique;
    }

    function Get-Exploit($ExploitID) {  
        $request1 = Invoke-WebRequest -Uri ('http://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0";
        Invoke-WebRequest -Uri ('http://vulmon.com/downloadexploit?qid=' + $ExploitID) -UserAgent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0" -OutFile ( ($request1.Headers."Content-Disposition" -split "=")[1]);
    }

}