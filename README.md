# winvulnmap
A simple powershell script that performs Host-based local vulnerability scan

# Installation
```
git clone https://github.com/krishpranav/winvulnmap
```

# Examples:

- Default mode does a vulnerability scanning:
```
PS> Invoke-Vulmap
```

- Conducts a vulnerability scanning and only shows vulnerabilities that have exploits:
```
PS> Invoke-Vulmap -OnlyExploitableVulns
```

- Download given exploit:
```
PS> Invoke-Vulmap -DownloadExploit EDB9386
```

- Scans the whole computer and download all available exploits:
```
PS> Invoke-Vulmap -DownloadAllExploits
```
