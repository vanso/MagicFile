# MagicFile

MagicFile is is a PowerShell module.

Identify the type of a file by analyzing its content using the libmagic library with PowerShell.

## Requirements

- Windows PowerShell 5.1
- PowerShell 7.x

## Supported platforms

- Windows (x86, AMD64, ARM64)
- Linux (x86_64, armv7l, aarch64)
- macOS (x86_64, arm64)

## Installation

```powershell
PS> Install-Module -Name MagicFile
```

## Usage
```powershell
Get-FileType C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

## License

This module is released under the terms of the GNU General Public License (GPL), Version 2.
