# MagicFile

MagicFile is a PowerShell module.

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

Get-FileType -LiteralPath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -FormatType Mime

Get-FileType -LiteralPath C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -MagicFilePath C:\Users\Shared\magic.mgc

Get-MagicFileVersion

Get-MagicFilePath
```

## Available Functions in the Module

| Function name            | Description                                                                          |
|:-------------------------|:-------------------------------------------------------------------------------------|
| ConvertTo-MagicFile | Converts a file containing a pre-parsed version of the magic file or directory into a compiled .mgc file.|
| Debug-MagicFile | Performs detailed debugging of the file type detection process, printing internal diagnostic information about the magic file and its checks. |
| Get-MagicFileContent | Shows a list of patterns and their strength sorted descending by magic(4) strength which is used for the matching.|
| Get-MagicFilePath | Returns the full paths to the specified magic files, checking system directories or user-defined paths for the magic.mgc. |
| Get-MagicFileType | Determines the specific type of a file by analyzing its magic number. |
| Get-MagicFileVersion | Retrieves the version of the libmagic library. |
| Test-MagicFile | Validates whether a file can be recognized as a valid magic file, based on the predefined magic patterns or user-customized magic files.|

## Available Aliases in the Module

| Alias name | Function name  |                                                                
|:-------------------------|:-------------------------------------------------------------------------------------|
|  Get-FileType          | Get-MagicFileType     |
|  Get-ItemType       | Get-MagicFileType  |

## License

This module is released under the terms of the GNU General Public License (GPL), Version 2.
