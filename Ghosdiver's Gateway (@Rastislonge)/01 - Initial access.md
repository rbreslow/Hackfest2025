We spent a lot of time on this challenge. 

We got given a website with a user-login. Looking around inside yields nothing.

Doing a nmap scan on the URL shows another service on port 8080.

```console
┌──(alex㉿FF-DEV-36864)-[/mnt/c/dev]
└─$ nmap -sV -Pn d81e53c704edd6f7b344885db72bca3.rastislonge.challenges.hfctf.ca
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-17 02:13 CEST
Nmap scan report for d81e53c704edd6f7b344885db72bca3.rastislonge.challenges.hfctf.ca (54.90.228.246)
Host is up (0.028s latency).
rDNS record for 54.90.228.246: ec2-54-90-228-246.compute-1.amazonaws.com
Not shown: 573 filtered tcp ports (no-response), 425 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3000/tcp open  http    Node.js Express framework
8080/tcp open  http    OpenWrt uHTTPd
Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.56 seconds
```

Doing a dirbuster on the 8080 service yields a error 403 on `/dev`, `/app`, `/public`. 

We were stuck here for a long time. Later in the CTF we got a hint:
> There is a txt file somewhere on another common port...

We dirbusted again searching for `.txt` files. We finally found `/public/dev/CHANGELOG.txt`. That file contained the admin-password `YLJ0gI6SDQKePO`.

Logging in as admin then gave the flag.