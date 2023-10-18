# - Hidrogen

![](/images/writeup/internship/hidrogen/challenge.PNG)
## Information Gathering

- Boot2Root Challenge `IP = 192.168.8.118`

![](/images/writeup/internship/hidrogen/web.PNG)

```bash
## Internship NBS
192.168.8.118   hidrogen.netbytesec.com
```

## Enumeration

```bash
┌──(root㉿kali)-[/home/kali/Desktop/internship/hidrogen]
└─# nmap -sCV -A 192.168.8.118 -o nmap/scan.txt
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-18 01:29 EDT
Nmap scan report for hydrogen.co (192.168.8.118)
Host is up (0.00092s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 6.0p1 Debian 4+deb7u7 (protocol 2.0)
| ssh-hostkey: 
|   1024 24:04:bf:3c:02:c8:ac:cd:5e:41:e8:5e:c8:47:96:76 (DSA)
|   2048 28:fd:24:7b:a5:9a:b6:62:ad:d6:3f:b0:4e:7e:ea:e9 (RSA)
|_  256 eb:b8:37:33:af:eb:a2:a7:4a:84:27:6e:35:65:d4:a6 (ECDSA)
80/tcp open  http    nginx 1.2.1
|_http-title: Hydrogen Co
|_http-server-header: nginx/1.2.1
| http-robots.txt: 1 disallowed entry 
|_/phpmyadmin
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|general purpose
Running: Actiontec embedded, Linux 2.4.X
OS CPE: cpe:/h:actiontec:mi424wr-gen3i cpe:/o:linux:linux_kernel cpe:/o:linux:linux_kernel:2.4.37
OS details: Actiontec MI424WR-GEN3I WAP, DD-WRT v24-sp2 (Linux 2.4.37)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.09 ms 192.168.37.2
2   0.11 ms hydrogen.co (192.168.8.118)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 271.18 seconds
```

We can see here there is `/robots.txt` on the port 80 and the directory to `/phpmyadmin` login page that maybe some database service is running on the web server. On the other hand, one more interesting port that is open which is FTP port 21. How about we try to login into it by using default login `anonymous:anonymous`. 

```bash
┌──(root㉿kali)-[/home/kali/Desktop/internship/hidrogen]
└─# ftp hidrogen.netbytesec.com
Connected to hidrogen.netbytesec.com.
220 ProFTPD 1.2.6 Server (Hydrogen Corporation File Transfer Service) [hydrogrencorp]
Name (hidrogen.netbytesec.com:kali): anonymous
331 Anonymous login ok, send your complete email address as your password.
Password: 
230 Anonymous access granted, restrictions apply.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
227 Entering Passive Mode (192,168,8,118,161,169).
150 Opening ASCII mode data connection for file list
drwxr-xr-x   2 ftp      ftp          4096 Feb 19  2019 .
drwxr-xr-x   2 ftp      ftp          4096 Feb 19  2019 ..
-rw-r--r--   1 ftp      ftp           472 Jan 19  2019 email.txt
-r--------   1 ftp      ftp            39 Jan 18  2019 flag1.txt
226 Transfer complete.

```

![](/images/writeup/internship/hidrogen/hidrogen.PNG)

We got nothing in here, so we will try to fuzz the directory in hopes we get something interesting to look on. 
```bash
┌──(root㉿kali)-[/home/kali/Desktop/internship/hidrogen]
└─# dirb http://hidrogen.netbytesec.com

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct 18 02:42:46 2023
URL_BASE: http://hidrogen.netbytesec.com/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://hidrogen.netbytesec.com/ ----
==> DIRECTORY: http://hidrogen.netbytesec.com/css/                                
==> DIRECTORY: http://hidrogen.netbytesec.com/img/                                
+ http://hidrogen.netbytesec.com/index.html (CODE:200|SIZE:5033)                  
+ http://hidrogen.netbytesec.com/info.php (CODE:200|SIZE:49739)                   
==> DIRECTORY: http://hidrogen.netbytesec.com/phpmyadmin/                         
+ http://hidrogen.netbytesec.com/robots.txt (CODE:200|SIZE:36)                    
==> DIRECTORY: http://hidrogen.netbytesec.com/vendor/                             
==> DIRECTORY: http://hidrogen.netbytesec.com/wordpress/
```


```bash
## Internship NBS
192.168.8.118   hidrogen.netbytesec.com hydrogen.co
```


