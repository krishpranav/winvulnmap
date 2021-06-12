# winvulnmap
A simple powershell script that performs Host-based local vulnerability scan

# Installation
```
git clone https://github.com/krishpranav/winvulnmap
```

# Examples:

- Default mode does a vulnerability scanning:
```
PS> Invoke-WinVulmap
```

- Conducts a vulnerability scanning and only shows vulnerabilities that have exploits:
```
PS> Invoke-WinVulmap -OnlyExploitableVulns
```

- Download given exploit:
```
PS> Invoke-WinVulmap -DownloadExploit EDB9386
```

- Scans the whole computer and download all available exploits:
```
PS> Invoke-WinVulmap -DownloadAllExploits
```
