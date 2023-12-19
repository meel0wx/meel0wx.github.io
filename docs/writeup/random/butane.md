---
date:
  created: 2023-12-19
  updated: 2023-12-19
description: Butane Writeup
tags:
  - udp
  - snmpwalk
  - linpeas
  - lse
  - pnwkit
comments: true
---

# Butane

Here is a challenge on Butane, Boot2Root machine.

## Reconnaissance

`IP = 192.168.8.131`

First and foremost, doing nmap scan to gather information of the machine. We get this

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/butane]
└─# nmap -p- --min-rate 10000 192.168.8.131 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-27 03:36 EDT
Nmap scan report for butane.netbytesec.com (192.168.8.131)
Host is up (0.0011s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds
```

There is only one service running. I thought that the machine is not running correctly haha. So just relax... 

After a while, there is a hint said that "Why not trying the UDP". So bump into nmap UDP scan. It took some time, so we give `-vv` to make it more aggressive. 

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/butane]
└─# nmap -sU -T4 -vv 192.168.8.131
```

Output

```js
Scanned at 2023-10-27 00:17:08 EDT for 1579s
Not shown: 999 open|filtered udp ports (no-response)
PORT    STATE SERVICE REASON
161/udp open  snmp    udp-response ttl 128

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1578.88 seconds
           Raw packets sent: 2279 (106.097KB) | Rcvd: 2 (181B)
```

## Enumeration

It is snmp service running on this machine. So we go thru the SNMP hacktricks [https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/butane]
└─# snmpwalk -v 2c -c public 192.168.8.131 .1 > output.txt
```

We will be using this command to enumerate and get the machine information. We get this and there is credentials of `mike:P@55w0Rd` to log in into the SSH and the first flag.

![](/images/writeup/internship/butane/cred.PNG)

## Exploitation

We go into the SSH. Directly we got the second flag

```js
┌──(root㉿kali)-[/home/kali/Desktop/internship/butane]
└─# ssh mike@192.168.8.131                
mike@192.168.8.131's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

279 packages can be updated.
197 updates are security updates.

New release '18.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Fri Oct 27 12:46:19 2023 from 192.168.22.12
mike@butane:~$ ls
flag2.txt
mike@butane:~$ cat flag2.txt
flag{37503d2ac009c25f88f86a4961be83d0944afcd6}
```


### Privesc

To get the root I try to look on the `linpeas` and directly install into the machine because there is `wget`

```js
mike@butane:/tmp$ wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

After a few testing of privesc OS and Linux kernel. It was mission failed because there is no `gcc` install

```js
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 4.4.0-62-generic (buildd@lcy01-30) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.4) ) #83-Ubuntu SMP Wed Jan 18 14:10:15 UTC 2017
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.2 LTS
Release:	16.04
Codename:	xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version
Sudo version 1.8.16
```

After trying some exploit on the public, we cannot get thru anything

