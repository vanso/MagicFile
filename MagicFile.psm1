<#

MagicFile

Copyright (C) 2025 Vincent Anso

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

This program was inspired by the file(1) command.

Copyright (c) Ian F. Darwin 1986-1995.
Software written by Ian F. Darwin and others;
maintained 1995-present by Christos Zoulas and others.

https://www.darwinsys.com/file/

#>

using namespace System.Net.Mime
using namespace System.Collections
using namespace System.Runtime.InteropServices

# Magic flag definitions
 enum Flags 
 {
    None                = 0x0000000    # No flags
    Debug               = 0x0000001    # Turn on debugging
    Symlink             = 0x0000002    # Follow symlinks
    Compress            = 0x0000004    # Check inside compressed files
    Devices             = 0x0000008    # Look at the contents of devices
    MimeType            = 0x0000010    # Return the MIME type
    Continue            = 0x0000020    # Return all matches
    Check               = 0x0000040    # Print warnings to stderr
    PreserveAtime       = 0x0000080    # Restore access time on exit
    Raw                 = 0x0000100    # Don't convert unprintable chars
    Error               = 0x0000200    # Handle ENOENT etc as real errors
    MimeEncoding        = 0x0000400    # Return the MIME encoding
    Mime                = 0x0000410    # Combined MIME type and encoding flags
    Apple               = 0x0000800    # Return the Apple creator/type
    Extension           = 0x1000000    # Return a /-separated list of extensions
    CompressTransp      = 0x2000000    # Check inside compressed files but not report compression
    NoCompressFork      = 0x4000000    # Don't allow decompression that needs to fork
    NoDesc              = 0x1000410    # Combined Extension, MIME, and Apple flags
}

# Magic flags for disabling specific checks
enum FlagsNoCheck 
{
    Compress           = 0x0001000    # Don't check for compressed files
    Tar                = 0x0002000    # Don't check for tar files
    Soft               = 0x0004000    # Don't check magic entries
    AppType            = 0x0008000    # Don't check application type
    ELF                = 0x0010000    # Don't check for ELF details
    Text               = 0x0020000    # Don't check for text files
    CDF                = 0x0040000    # Don't check for cdf files
    CSV                = 0x0080000    # Don't check for CSV files
    Tokens             = 0x0100000    # Don't check tokens
    Encoding           = 0x0200000    # Don't check text encodings
    JSON               = 0x0400000    # Don't check for JSON files
    SIMH               = 0x0800000    # Don't check for SIMH tape files
    Builtin            = 0x0F7F000    # Combined flags for common disabled checks
    ASCII              = 0x0020000    # Alias for NoCheck.Text
    Fortran            = 0x0000000    # Don't check ASCII/Fortran (no-op)
    Troff              = 0x0000000    # Don't check ASCII/Troff (no-op)
}

# Flags for disabling specific checks
enum NoCheck 
 {
    ASCII                  = [FlagsNoCheck]::Text # Alias for text checks
    Fortran                = 0x000000             # Disable Fortran checks
    Troff                  = 0x000000             # Disable Troff checks
 }

# Parameters for magic checks
 enum Params 
 {
    IndirMax      # "Max recursion for indirect magic"
    NameMax       # "Max length for name checks"
    ELFPhNumMax   # "Max ELF program headers"
    ELFShNumMax   # "Max ELF section headers"
    ELFNotesMax   # "Max ELF notes size"
    RegexMax      # "Max regex patterns"
    BytesMax      # "Max bytes to check"
    EncodingMax   # "Max encoding checks"
    ELFShSizeMax  # "Max ELF section size"
    MagWarnMax    # "Max warnings for magic parsing"
}

enum MagicResult 
{
    Error   = -1
    Success = 0
}

# Supported platforms

# Darwin-arm64
# Darwin-x86_64

# Linux-aarch64
# Linux-armv7l
# Linux-x86_64

# Windows-AMD64
# Windows-ARM64
# Windows-x86

enum OperatingSystem
{
    Darwin
    Linux
    Windows
}

enum Architecture 
{
    arm64
    x86_64
    aarch64
    armv7l
    amd64
    x86
}

# When $IsWindows doesn't exist on PowerShell 5.x
if ($null -eq $PSVersionTable.Platform) 
{
    $IsWindows = $true
}

$platform = [Environment]::OSVersion.Platform

if ($platform -eq [PlatformID]::Win32NT)
{
    $currentOperatingSystem = [OperatingSystem]::Windows

    $currentArchitecture    = $env:PROCESSOR_ARCHITECTURE
}
elseif ($platform -eq [PlatformID]::Unix)
{
    $currentOperatingSystem = $(uname -s)

    $currentArchitecture    = $(uname -m)

    if ( ($currentArchitecture -eq [Architecture]::aarch64) -and (-Not [Environment]::Is64BitOperatingSystem) )
    {
        $currentArchitecture = [Architecture]::armv7l
    }
} 
else
{
    Write-Warning "Unsupported platform ($platform)."

    exit 0
}

if ( ([OperatingSystem].GetEnumNames() -notcontains $currentOperatingSystem) -or ([Architecture].GetEnumNames() -notcontains $currentArchitecture) ) 
{
    Write-Warning "Unsupported operating system or hardware architecture ($currentOperatingSystem/$currentArchitecture)."
   
    exit 0
}

$libraries = @{
    [OperatingSystem]::Darwin  = "libmagic.1.dylib"
    [OperatingSystem]::Linux   = "libmagic.so.1.0.0"
    [OperatingSystem]::Windows = "libmagic-1.dll" 
}

$libmagic = $libraries[[OperatingSystem]$currentOperatingSystem]

$libraryPath = Join-Path -Path $PSScriptRoot -ChildPath "Platforms/$currentOperatingSystem-$currentArchitecture/$libmagic"

Write-Debug "libmagic path : $libraryPath"

Write-Verbose "Platform : $platform ($currentOperatingSystem/$currentArchitecture)"

$sourceCode = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class LibMagic
{
    [StructLayout(LayoutKind.Sequential)]
    public struct magic_t
    {
        public IntPtr Value;
    }

    public static List<string> magicFilePath = new List<string>();

    public const string LIBRARY_NAME = @"$libraryPath";

    // P/Invoke declarations with EntryPoint and simplified method names
    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_open")]
    public static extern magic_t Open(int flags);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_close")]
    public static extern void Close(magic_t cookie);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_error")]
    public static extern IntPtr Error(magic_t cookie);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_errno")]
    public static extern int Errno(magic_t cookie);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_descriptor")]
    public static extern IntPtr Descriptor(magic_t cookie, int fd);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_file")]
    public static extern IntPtr File(magic_t cookie, string filename);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_buffer")]
    public static extern IntPtr Buffer(magic_t cookie, IntPtr buffer, IntPtr length);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_getflags")]
    public static extern int GetFlags(magic_t cookie);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_setflags")]
    public static extern int SetFlags(magic_t cookie, int flags);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_check")]
    public static extern int Check(magic_t cookie, string filename);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_compile")]
    public static extern int Compile(magic_t cookie, string filename);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_list")]
    public static extern int List(magic_t cookie, string filename);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_load")]
    public static extern int Load(magic_t cookie, string filename);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_load_buffers")]
    public static extern int LoadBuffers(magic_t cookie, IntPtr[] buffers, IntPtr[] sizes, IntPtr nbuffers);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_getparam")]
    public static extern int GetParam(magic_t cookie, int param, IntPtr value);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_setparam")]
    public static extern int SetParam(magic_t cookie, int param, IntPtr value);

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_version")]
    public static extern int Version();

    [DllImport(LIBRARY_NAME, CallingConvention = CallingConvention.Cdecl, EntryPoint = "magic_getpath")]
    public static extern IntPtr GetPath(string magicfile, int action);

    // Utility functions to convert returned IntPtr to string
    public static string PtrToString(IntPtr ptr)
    {
        return ptr == IntPtr.Zero ? null : Marshal.PtrToStringAnsi(ptr);
    }

    public static string GetError(magic_t cookie)
    {
        return PtrToString(Error(cookie));
    }

    public static int GetErrorNumber(magic_t cookie)
    {
        return Errno(cookie);
    }
}
"@

class FInfo
{
    [string]$Type
    [string]$Creator

    FInfo([string]$LibMagicApple)
    {
        $this.Type    = $LibMagicApple.Substring(4,4)
        $this.Creator = $LibMagicApple.Substring(0,4)
    }

    [string] ToString()
    {
        return "$($this.Creator)$($this.Type)"
    }
}

$ExecutionContext.InvokeCommand.ExpandString($sourceCode) | Out-Null

Add-Type -TypeDefinition $sourceCode -Language CSharp

$contentTypePattern = '^[a-zA-Z0-9!#$%&''*+._-]+/[a-zA-Z0-9!#$%&''*+._-]+$'

$magicFile = (Join-Path -Path ".magic"-ChildPath "magic.mgc")

function Get-MagicFileVersion
{
    <#

    .SYNOPSIS
    Retrieves the version of the libmagic library.
   
    #>
    
    $version = [LibMagic]::Version()
    
    $major = [math]::Floor($version / 100)
    $minor = $version % 100
    
    [Version]::new($major, $minor)
}

Write-Verbose "libmagic version : $(Get-MagicFileVersion)"

function Initialize-LibMagic
{
    $magic = [LibMagic]::Open([Flags]::None)

    if ($magic -eq [IntPtr]::Zero) 
    {
        Write-Error $( [InvalidOperationException]::new("Failed to initialize libmagic.") )
        
        exit 0
    }

    return $magic
}

function Get-MagicFileContent
{
    <#

    .SYNOPSIS
    Shows a list of patterns and their strength sorted descending by magic(4) strength which is used for the matching.
    
    #>
    
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath
    )

    $magic = Initialize-LibMagic

    if ( [LibMagic]::List($magic, $FilePath) -eq [MagicResult]::Error )
    {
        Write-Error $( [InvalidOperationException]::new() )

        exit 0
    }

    [LibMagic]::Close($magic)
}

function Debug-MagicFile 
{
    <#

    .SYNOPSIS
    Performs detailed debugging of the file type detection process, printing internal diagnostic information about the magic file and its checks.
    
    #>
    
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath
    )

    $magic = Initialize-LibMagic

    $result = $false

    $flags = [LibMagic]::GetFlags($magic)

    [LibMagic]::SetFlags($magic, $flags -bor [Flags]::Check -bor [Flags]::Debug )

    if ( [LibMagic]::Check($magic, $FilePath) -eq [MagicResult]::Success )
    {
        $result = $true
    }

    [LibMagic]::Close($magic)

    return $result
}

function Test-MagicFilePath 
{
    <#

    .SYNOPSIS
    Validates whether a file can be recognized as a valid magic file, based on the predefined magic patterns or user-customized magic files.
    
    #>
    
    param (
        [string[]]$Path
    )

    foreach ($filePath in $Path) 
    {
        if (Test-Path -LiteralPath $filePath)
        {
            Write-Verbose $($filePath + "... yes")
            
            [LibMagic]::magicFilePath.Add($filePath)
        }
        else 
        {
            Write-Verbose $($filePath + "... no")
        }
    }
}

function Get-MagicFilePathUnix
{
    if ($IsLinux -or $IsMacOS)
    {              
        $magicFilePath = @( $(Join-Path -Path $Env:HOME -ChildPath ".magic.mgc")
                            $(Join-Path -Path $Env:HOME -ChildPath $magicFile) 
                            $(Join-Path -Path "/usr/local/share/misc/" -ChildPath "magic.mgc")
                            $(Join-Path -Path "/usr/local/share/misc/" -ChildPath "magic") 
                            )

        Test-MagicFilePath $magicFilePath
    }
}

function Get-MagicFilePathWindows
{
    if ($IsWindows)
    {
        $magicFilePath = @( $(Join-Path -Path $Env:USERPROFILE -ChildPath "magic.mgc")
                            $(Join-Path -Path $Env:USERPROFILE -ChildPath $magicFile)
                            $(Join-Path -Path $Env:LOCALAPPDATA -ChildPath $magicFile)
                            $(Join-Path -Path $Env:COMMONPROGRAMFILES -ChildPath $magicFile)
                            )
        
        Test-MagicFilePath $magicFilePath
    }
}

function Get-MagicFilePath
{    
    <#

    .SYNOPSIS
    Returns the full paths to the specified magic files, checking system directories or user-defined paths for the magic.mgc.
    
    #>

    [LibMagic]::magicFilePath.Clear()

    if ($Env:MAGIC)
    {
        Test-MagicFilePath $Env:MAGIC
    }
    else
    {
        Write-Verbose "`Env:MAGIC... no"  
    }

    if ( $platform -eq [PlatformID]::Unix )
    {
        Get-MagicFilePathUnix
    }
    elseif ( $platform -eq [PlatformID]::Win32NT )
    {
        Get-MagicFilePathWindows
    }

    Test-MagicFilePath $(Join-Path -Path $PSScriptRoot -ChildPath "magic.mgc")

    return $([LibMagic]::magicFilePath)
}

function ConvertTo-MagicFile
{
    <#

    .SYNOPSIS
    Converts a file containing a pre-parsed version of the magic file or directory into a compiled .mgc file.
    
    #>
    
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath
    )
    
    $magic = Initialize-LibMagic

    $result = $false

    if ( [LibMagic]::Compile($magic, $FilePath) -eq [MagicResult]::Success )
    {
        $result = $true
    }

    [LibMagic]::Close($magic)

    return $result
}

function Test-MagicFile
{
    <#

    .SYNOPSIS
    Validates whether a file can be recognized as a valid magic file.
    
    #>
    
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string]$FilePath
    )

    $magic = Initialize-LibMagic

    $result = $false

    if ( [LibMagic]::Check($magic, $FilePath) -eq [MagicResult]::Success )
    {
        $result = $true
    }

    [LibMagic]::Close($magic)

    return $result
}


function Get-MagicFileType
{   
    <#

    .SYNOPSIS
    Determines the specific type of a file by analyzing its magic number.

    .INPUTS
    You can pipe a string that contains a path, but not a literal path, to this function.

    .PARAMETER Path
    Specifies a path to a file to be tested. Wildcard characters are permitted.

    .PARAMETER LiteralPath
    Specifies a path to be tested. Unlike Path, the value of the LiteralPath parameter is used exactly as it's typed. 

    .PARAMETER IgnoreType
    Excludes certain tests from determining file type.

    .PARAMETER FollowSymlink
    Follow symlinks.

    .PARAMETER ExpandArchive
    Check inside compressed files.

    .PARAMETER InspectArchive
    Check inside compressed files but not report compression.

    .PARAMETER PreserveDate
    Attempt to preserve the access time of files analyzed.

    .PARAMETER All
    Finds all matches instead of stopping at the first.

    #>

    [CmdletBinding(DefaultParameterSetName = "Path")]

    param(
        [Parameter(ParameterSetName = 'Path')]
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string[]]$Path,

        [Parameter(ParameterSetName = 'LiteralPath')]
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string[]]$LiteralPath,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [ValidateSet("Text", "Mime", "Extension", "Apple", IgnoreCase=$false)]
        [string[]]$FormatType = @("Text", "Mime", "Extension", "Apple"),
    
        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [ValidateSet("AppType", "ASCII", "Tokens", "Encoding", "CDF", "Compress", "CSV", "ELF", "JSON", "Soft", "SIMH", "Tar", "Text", IgnoreCase=$false)]
        [string[]]$IgnoreType,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [switch]$FollowSymlink,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [switch]$InspectArchive,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [switch]$ExpandArchive,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [switch]$PreserveDate,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [switch]$All,

        [Parameter(ParameterSetName = 'Path')]
        [Parameter(ParameterSetName = 'LiteralPath')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ })]
        [string[]]$MagicFilePath
    )

    BEGIN 
    {        
        $items = [ArrayList]::new()
        
        if ($Path)
        {
            foreach ($item in $Path) 
            {
                $paths = Get-Item -Path $item
                
                $items.AddRange([Object[]]$paths)
            }
        }
        
        if ($LiteralPath)
        {
            $items = Get-Item -LiteralPath $LiteralPath
        }
        
        if ( [string]::IsNullOrEmpty($MagicFilePath) )
        {
            $MagicFilePath = Get-MagicFilePath 
        }

        $MagicFilePathFromParts = $($MagicFilePath -join ":")

        Write-Verbose "magic file from : $MagicFilePathFromParts"
        
        $types = @{ Text         = [Flags]::None
                    Mime         = [Flags]::Mime
                    Extension    = [Flags]::Extension    
                    Apple        = [Flags]::Apple       
                    }

        $magic = Initialize-LibMagic

        $values = [ArrayList]::new()
    }

    PROCESS 
    {        
        foreach ($item in $items) 
        {   
            $entry = New-Object -TypeName PSObject
           
            Add-Member -InputObject $entry -MemberType NoteProperty -Name File -Value $item

            foreach ($type in $FormatType)
            {
                $flags = $types[$type]
            
                if ( $PSBoundParameters.ContainsKey("FollowSymlink") )
                {
                    $flags = $flags -bor [Flags]::Symlink
                }

                if ( $PSBoundParameters.ContainsKey("InspectArchive") )
                {
                    $flags = $flags -bor [Flags]::Compress -bor [Flags]::CompressTransp
                }

                if ( $PSBoundParameters.ContainsKey("ExpandArchive") )
                {
                    $flags = $flags -bor [Flags]::Compress
                }

                if ( $PSBoundParameters.ContainsKey("PreserveDate") )
                {
                    $flags = $flags -bor [Flags]::PreserveAtime
                }

                if ( $PSBoundParameters.ContainsKey("All") )
                {
                    $flags = $flags -bor [Flags]::Continue
                }

                if ($IgnoreType)
                {
                    foreach($ignoredType in $IgnoreType)
                    {
                        $flags = $flags -bor [FlagsNoCheck]::$ignoredType
                    }
                }

                if ( [LibMagic]::SetFlags($magic, $flags) -eq [MagicResult]::Success )
                {                    
                    if ( [LibMagic]::Load($magic, $MagicFilePathFromParts) -eq [MagicResult]::Error )
                    {
                        $message = [LibMagic]::GetError($magic)
                
                        Write-Error $( [InvalidOperationException]::new($message) )

                        [LibMagic]::Close($magic)
                        
                        exit 0
                    }
                }
                else 
                {
                    Write-Error $( [InvalidOperationException]::new("Unable to set flags : $flags") )

                    [LibMagic]::Close($magic)

                    exit 0
                }

                $fileType = [LibMagic]::File($magic, $($item).ToString() )

                $managedString = [LibMagic]::PtrToString($fileType)

                if ($managedString)
                {
                    Write-Debug $managedString
                    
                    $strings = $($managedString -split "\\012-") | ForEach-Object { $_.Trim() }
                }
                
                $values = [ArrayList]::new()

                $value = $null

                switch ($type)
                {
                    "Text"
                    {
                        if ($strings)
                        {
                            $values = @($strings)
                        }
                    }

                    "Apple"
                    {                        
                        if ($strings)
                        {
                            $typeCreators = $($strings -split "\\012-")

                            foreach ($typeCreator in $typeCreators)
                            {
                                $values.Add( [FInfo]::new($typeCreator) ) | Out-Null
                            }
                        }
                    }

                    "Mime"
                    {
                        if ($managedString)
                        {
                            $mimes = $managedString -split ";"

                            $mediaTypes = $(($mimes[0]) -split "\\012-")

                            $charSet = $mimes[1]

                            foreach($mediaItem in $mediaTypes)
                            {
                                $mediaItem = $mediaItem.Trim()

                                if ($mediaItem -match $contentTypePattern)
                                {
                                    try 
                                    {
                                        $values.Add( [ContentType]::new($mediaItem + ";" + $charSet) ) | Out-Null
                                    }
                                    catch 
                                    {
                                        $values.Add( [ContentType]::new($mediaItem) ) | Out-Null
                                    }
                                }
                            }
                        }
                    }

                    "Extension"
                    {
                        if ($strings)
                        {
                            foreach($extension in $strings)
                            {
                                $values.Add( $($extension -split "/") ) | Out-Null
                            }
                        }
                    }
                }

                if ( $PSBoundParameters.ContainsKey('All') ) 
                {
                    $value = $values
                }
                else
                {
                    $value = $values[0]
                }

                Add-Member -InputObject $entry -MemberType NoteProperty -Name $type -Value $value

                $values = $null
            }

            Write-Output $entry
        }
    }

    END 
    { 
        [LibMagic]::Close($magic)
    }
}


Set-Alias -Name Get-FileType -Value Get-MagicFileType
Set-Alias -Name Get-ItemType -Value Get-MagicFileType

Export-ModuleMember -Alias @(
    'Get-FileType',
    'Get-ItemType'
    )

Export-ModuleMember -Function @(
    'Get-MagicFileType',
    'Get-MagicFileVersion',
    'Get-MagicFileContent',
    'Debug-MagicFile',
    'Get-MagicFilePath',
    'ConvertTo-MagicFile',
    'Test-MagicFile'
    )
