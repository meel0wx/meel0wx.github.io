#### Listing Processes 
```
windows.pslist.PsList
    Lists the processes present in a particular windows memory image.
	
windows.psscan.PsScan
    Scans for processes present in a particular windows memory image.
	
windows.pstree.PsTree
    Plugin for listing processes in a tree based on their parent process ID.

i.e:
python vol.py -f memdump.raw windows.pslist # Get process list (EPROCESS)
python vol.py -f memdump.raw windows.psscan # Get hidden process list(malware)
python vol.py -f memdump.raw windows.pstree # Get processes tree (not hidden)
python vol.py -f memdump.raw windows.pslist --pid <pid> --dump # Get only the .exe and no handles/dlls

```

#### Checking CMD commands
```
windows.cmdline.CmdLine 
		Lists process command line arguments.
i.e:
python vol.py -f memdump.raw windows.cmdline
```

>Commands entered into cmd.exe are processed by **conhost.exe** (csrss.exe prior to Windows 7). So even if an attacker managed to **kill the cmd.exe** **prior** to us obtaining a memory **dump**, there is still a good chance of **recovering history** of the command line session from **conhost.exe’s memory**. If you find **something weird** (using the console's modules), try to **dump** the **memory** of the **conhost.exe associated** process and **search** for **strings** inside it to extract the command lines.

\- [Hacktricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet)


#### Network Information
```
windows.netscan.NetScan
    Scans for network objects present in a particular windows memory image.

windows.netstat.NetStat
    Traverses network tracking structures present in a particular windows memory image.

i.e:
python vol.py -f memdump.raw windows.netscan
python vol.py -f memdump.raw windows.netstat
```

#### Checking DLL Used
```
windows.dlllist.DllList
    Lists the loaded modules in a particular windows memory image.

i.e 
python vol.py -f memdump.raw windows.dlllist [--pid <pid>]
```

#### Getting Hashes/Passwords
```
windows.cachedump.Cachedump
    Dumps lsa secrets from memory

windows.hashdump.Hashdump
    Dumps user hashes from memory

windows.lsadump.Lsadump
    Dumps lsa secrets from memory

i.e
python vol.py -f memdump.raw windows.cachedump 
python vol.py -f memdump.raw windows.hashdump
python vol.py -f memdump.raw windows.lsadump
```

#### Getting SIDs
```
windows.getservicesids.GetServiceSIDs
    Lists process token sids.
	
windows.getsids.GetSIDs
    Print the SIDs owning each process
```

#### Registry
```	
windows.registry.hivelist.HiveList
    Lists the registry hives present in a particular memory image.
	
windows.registry.hivescan.HiveScan
    Scans for registry hives present in a particular windows memory image.
	
windows.registry.printkey.PrintKey
    Lists the registry keys under a hive or specific key value.
	

i.e
python vol.py -f file.dmp windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows NT\CurrentVersion" #Hacktricks

```

#### Certificates in Registry
```
windows.registry.certificates.Certificates
    Lists the certificates in the registry's Certificate Store.
```

#### User Assist
> Enter Explanation Here
```
windows.registry.userassist.UserAssist
    Print userassist registry keys and information.

```

#### Malware Hunting
```
windows.driverirp.DriverIrp
    List IRPs for drivers in a particular windows memory image.
    #Checks for hooks done by malware

windows.malfind.Malfind
	Lists process memory ranges that potentially contain injected code.
	#Usually shows process injection/DLL injection.

windows.ldrmodules.LdrModules
	Displays loaded modules/DLL in the memory.
	#Can be used to detect DLL injection, especially when all 3 are false.

windows.drivermodule.DriverModule
    Determines if any loaded drivers were hidden by a rootkit

windows.ssdt.SSDT   
	Lists the system call table.


```

#### Environmental Variables
```
windows.envars.Envars
    Display process environment variables
```

#### File Related Commands
```
windows.dumpfiles.DumpFiles
    Dumps cached file contents from Windows memory samples.

windows.filescan.FileScan
    Scans for file objects present in a particular windows memory image.

i.e
python vol.py -f memdump.raw windows.dumpfiles #Dumps everything
python vol.py -f memdump.raw windows.dumpfiles --pid <PID> #Dumps .exe and its handles
python vol.py -f memdump.raw windows.dumpfiles --physaddr <offset>
python vol.py -f memdump.raw windows.dumpfiles --virtaddr <offset>
python vol.py -f memdump.raw windows.filescan
```

#### MFT & MBR Records
>Enter About MFT & MBR here
```
windows.mftscan.MFTScan
    Scans for MFT FILE objects present in a particular windows memory image.
						
windows.mbrscan.MBRScan
    Scans for and parses potential Master Boot Records (MBRs)
```

#### Device and Drivers
```
windows.devicetree.DeviceTree
    Listing tree based on drivers and attached devices in a particular windows memory image.

windows.driverscan.DriverScan
    Scans for drivers present in a particular windows memory image.

```

#### Handles
> Explanation about brief Handles
```
windows.handles.Handles
    Lists process open handles.

i.e
python vol.py -f memdump.raw windows.handles [--pid <pid>]
```

#### Computer Information
```
windows.crashinfo.Crashinfo

windows.info.Info
	Show OS & kernel details of the memory sample being analyzed.
```

#### Token Privileges
>Explanation about privileges
```
windows.privileges.Privs
    Lists process token privileges
```

#### Mutex Scans
>Explanation about Mutexes
```
windows.mutantscan.MutantScan
    Scans for mutexes present in a particular windows memory image.
```

#### Sessions
> Sesssions explnaation
```
windows.sessions.Sessions
    lists Processes with Session information extracted from Environmental Variables
```

#### Services
```
windows.svcscan.SvcScan
    Scans for windows services.
```

#### Symlinks
```
windows.symlinkscan.SymlinkScan
    Scans for links present in a particular windows memory image.
```





#### Yara-Related
```
windows.vadyarascan.VadYaraScan
    Scans all the Virtual Address Descriptor memory maps using yara.
	
yarascan.YaraScan   
	Scans kernel memory using yara rules (string or file).

i.e
python vol.py -f memdump.py windows.vadyarascan --yara-rules "http://" --pid <pid>
python vol.py -f memdump.py yarascan --yara-rules "ftp://"
```

#### Vad Related
```
windows.vadinfo.VadInfo
    Lists process memory ranges.
	
windows.vadwalk.VadWalk
    Walk the VAD tree.
```

#### Niche Use case
```
windows.skeleton_key_check.Skeleton_Key_Check
    Looks for signs of Skeleton Key malware
```

#### Still Unsure
```
windows.bigpools.BigPools
	List big page pools
	
windows.poolscanner.PoolScanner
    A generic pool scanner plugin.

windows.statistics.Statistics

windows.joblinks.JobLinks
    Print process job link information

windows.callbacks.Callbacks
    Lists kernel callbacks and notification routines.

windows.memmap.Memmap
    Prints the memory map
						
windows.modscan.ModScan
    Scans for modules present in a particular windows memory image.
						
windows.modules.Modules
    Lists the loaded kernel modules.

windows.strings.Strings
    Reads output from the strings command and indicates which process(es) each string belongs to.
	
windows.verinfo.VerInfo
    Lists version information from PE files.
	
windows.virtmap.VirtMap
    Lists virtual mapped sections.
```

[EVTExtract](https://github.com/williballenthin/EVTXtract)
```
C:/Python27/Scripts/evtxtract.exe   Z:/evidence/1/image.dd   >   Z:/work/1/evtx.xml
```