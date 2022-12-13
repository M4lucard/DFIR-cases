## Follina vector

1. threat actor (TA) abused the CVE-2022-30190 (Follina) vulnerability
    => How to find Follina-vulnerable devices
    => How to detect exploitation of Follina
        monitor for this process (`msdt.exe`)  being spawned by a Microsoft Office application such as `WINWORD.EXE`

2. expoit code in malicious word document to gain initial access
    => (how to detect such behaviour)
        If the payload contains base64-encoded Powershell code, the decoded payload will be logged in EventID 4104 (script block logging) upon execution by the PowerShell engine.

    likely arrived by the means of thread-hijacked emails from distribution channels used by TA570.
    Weaponized Word document got executed

3. HTML file was retrieved from a remote server containing a PowerShell payload
    => (how to detect the used technique)
    Payload contained base64-encoded content => to download Qbot DDLs inside the user's Temp directory

----------------------

## Qbot vector

1. What is Qbot

2. Qbot DLL executed via regsvr32.exe
    => explain what regsvr32.exe
        Regsvr32.exe is a command-line utility in Microsoft Windows that registers .dll files as command components in the Windows Registry. It is used to register and unregister object linking and embedding (OLE) controls, such as DLLs and ActiveX controls in the Windows operating system.
        In the context of malware analysis, Regsvr32.exe is often used to launch malicious code or execute malicious scripts. Malware authors use this utility to bypass application whitelisting and UAC (User Account Control) controls. Malware analysts can analyze the behavior of the malicious code using Regsvr32.exe to assess the impact of the malicious code on the system.
    => How to detect qbot dll's on disk
        Qbot DLLs can be detected by scanning the disk for malicious DLL files. This is accomplished by searching for known malicious DLL filenames, hashes, and/or signatures, or by scanning the disk for DLLs that have suspicious properties, such as a high entropy value or a suspicious compilation timestamp. Additionally, scanning for DLLs that are loaded into memory by processes can reveal Qbot DLLs that are actively running and can be blocked or removed.

    => how to detect behaviour of qbot
        1. Monitor Processes: Qbot is a malicious program that is designed to run in the background of your system. Monitor processes to detect any suspicious or unknown processes that are running in the background.
        2. Check Network Connections: Qbot often communicates with malicious servers to receive instructions or to download additional malicious components. Monitor network connections to detect any suspicious connections that may be related to Qbot.
        3. Scan for Malware: Use a reliable anti-malware program to scan your system for any malicious files or programs that may be related to Qbot.
        4. Check Registry: Qbot often adds malicious entries to the Windows registry. Check the registry for any suspicious entries that may be related to Qbot.
        5. Monitor for Unusual Activity: Qbot can be used for activities such as data exfiltration, credential theft and more. Monitor for any unusual activity on your system that may be related to Qbot.

    was then injected into legitimate processes (explorer.exe) on the host
    Injected process spawned Windows utilities such as whoami, net.exe and nslookup for discovery and to establish connection to the Qbot C2 servers
    => how did it establish connections?
        => Detect connections in the future (pcap)

    Approx. an hour later: leverage of the Windows built-in utility esentutl.exe to extract browser data
    => What is exentutl.exe ?
        - Esentutl is a command-line utility used to manage Extensible Storage Engine (ESE) databases. ESE databases are used by Windows to store data such as registry information, user profiles, and browser data. Esentutl can be used to perform a variety of tasks such as defragmenting, repairing, and backing up ESE databases. It can also be used to extract data from ESE databases, such as browser data, which can then be analyzed or used for forensic investigations.
        - https://forensicitguy.github.io/how-qbot-uses-esentutl/

        ```cmd
        esentutl.exe /r V01 /l"C:\Users\[REDACTED]\AppData\Local\Microsoft\Windows\WebCache" /s"C:\Users\[REDACTED]\AppData\Local\Microsoft\Windows\WebCache" /d"C:\Users\[REDACTED]\AppData\Local\Microsoft\Windows\WebCache"
        ```

    => How should we monitor this (Fp behaviour) ?
        - Set up an audit policy that logs esentutil.exe-related events. You can do this by running the auditpol.exe command line tool with the appropriate parameters, or by using the Local Security Policy editor.
        -  Set up an event log subscription to monitor the ESE database. This can be done using Windows Event Viewer.
        -  Monitor the system for any suspicious activity involving esentutil.exe and the ESE database. This can be done using a combination of system and application logs, as well as system monitoring tools such as Sysmon.

3. Qbot used scheduled task creation as a persistence mechanism
    => (how to detect such behaviour)
        The Windows Event Log records all registry key creation events and provides detailed information about the registry key, such as when it was created and by whom. To view the Windows Event Log, open Event Viewer from the Control Panel, then in the left pane select Windows Logs > Application. Look for Event ID 4657, which indicates the creation of a registry key.
        In addition to Windows event log monitoring, Autoruns can be used to detect the creation of registry keys as a persistence mechanism. Autoruns is a tool from Sysinternals that scans the Windows registry and file system for startup programs and services. It identifies entries configured to run automatically when the system starts and shows the details of each entry, including the registry key and value name. Autoruns can be used to detect and analyze any suspicious programs or services that have been configured for automatic startup.

    contained PowerShell command referencing multiple C2 IP addresses stored as base64-encoded blob in randomly named keys under the HKCU registry hive.
    TA proceeded with remote creation of Qbot DLLs over SMB to other hosts throughout the environment
    TA added folders to the Microsoft Defender exlusions list on each of the infected machines to evade defenses
    => **How to detect mde exclusions operations** ?

    Remote services were then used in a similar fashion to execute the DLLs
    Cobalt Strike server connection was witnessed within the first hour, but wasn't ustilised untill the lateral movement phase

4. nltest.exe and AdFind were executed by the injected Cobalt Strike process (explorer.exe)
    => explain what nltest and adfind are
        Nltest is a command-line tool used to troubleshoot and diagnose issues with the Windows NT LAN Manager (NTLM) authentication protocol. It can be used to test various aspects of the NTLM protocol, such as verifying trust relationships, testing secure channel status, and checking user and computer accounts.
        Adfind is a command-line tool used to query Active Directory (AD). It can be used to search for and retrieve information about objects in AD, such as user accounts, computers, contacts, groups, and organizational units. Adfind can also be used to modify attributes, create, delete, and move objects, and perform other management tasks.
    => how to detect this
        - Process Execution & Command Line Logging - Windows Security Event Id 4688, Sysmon, or any CIM compliant EDR technology.
        - PowerShell Script Block Logging - Microsoft-Windows-PowerShell/Operational Event Id 4104.
        - Any other Active Directory Discovery detection techniques
    also used to access the LSASS system process

    TA installed remote management tool called Netsupport Manager
    TA moved laterally to the domain controller via Remote Desktop session
    On the DC
    A tool called Atera Remote Management was deployed (popular tool to control victim  machines)
    Next day: TA downloaded a tool named Network Scanner by SoftPerfect on the DC
    Execution ran a port scan across the network
    TA connected to one of the file share servers via RDP and accessed sensitive documents
    No further activity was observed before the TA got evicted from the domain.
