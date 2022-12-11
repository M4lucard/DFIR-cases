## Follina vector
1. threat actor (TA) abused the CVE-2022-30190 (Follina) vulnerability
    => How to find Follina-vulnerable devices
    => How to detect exploitation of Follina

2. expoit code in malicious word document to gain initial access
    => (how to detect such behaviour)
    likely arrived by the means of thread-hijacked emails from distribution channels used by TA570.
    Weaponized Word document got executed

3. HTML file was retrieved from a remote server containing a PowerShell payload
    => (how to detect the used technique)
    Payload contained base64-encoded content => to download Qbot DDLs inside the user's Temp directory
----------------------------------------------------------------------------------------------------------------
## Qbot vector
4. What is Qbot

5. Qbot DLL executed via regsvr32.exe
    => explain what regsvr32.exe
    => How to detect qbot dll's on disk
    => how to detect behaviour of qbot
    was then injected into legitimate processes (explorer.exe) on the host
    Injected process spawned Windows utilities such as whoami, net.exe and nslookup for discovery and to establish connection to the Qbot C2 servers
    => how did it establish connections?
        => Detect connections in the future (pcap)

    Approx. an hour later: leverage of the Windows built-in utility esentutl.exe to extract browser data
    => What is exentutl.exe ?
    => How should we monitor this (Fp behaviour) ?

6. Qbot used scheduled task creation as a persistence mechanism
    => (how to detect such behaviour)

    contained PowerShell command referencing multiple C2 IP addresses stored as base64-encoded blob in randomly named keys under the HKCU registry hive.
    TA proceeded with remote creation of Qbot DLLs over SMB to other hosts throughout the environment
    TA added folders to the Microsoft Defender exlusions list on each of the infected machines to evade defenses
    => How to detect mde exclusions operations ?

    Remote services were then used in a similar fashion to execute the DLLs
    Cobalt Strike server connection was witnessed within the first hour, but wasn't ustilised untill the lateral movement phase

7. nltest.exe and AdFind were executed by the injected Cobalt Strike process (explorer.exe)
    => explain what nltest and adfind are
    => how to detect this 

    also used to access the LSASS system process

    TA installed remote management tool called Netsupport Manager
    TA moved laterally to the domain controller via Remote Desktop session
    On the DC
    A tool called Atera Remote Management was deployed (popular tool to control victim  machines)
    Next day: TA downloaded a tool named Network Scanner by SoftPerfect on the DC
    Execution ran a port scan across the network
    TA connected to one of the file share servers via RDP and accessed sensitive documents
    No further activity was observed before the TA got evicted from the domain.
