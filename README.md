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

# 3.3.5.1 (page 59)
Using /etc/passwd, extract the user and home directory fields for all users on your Kali machine for which the shell is set to /bin/false. Make sure you use a Bash one-liner to print the output to the screen. The output should look similar to Listing 53 below:
```
The user mysql home directory is /nonexistent
The user Debian-snmp home directory is /var/lib/snmp
The user speech-dispatcher home directory is /var/run/speech-dispatcher The user Debian-gdm home directory is /var/lib/gdm3
```

Solution
```cat /etc/passwd | grep /bin/false | awk -F ":" '{ printf("The user %s home directory is %s\n", $1, $6)}'```

Output:
```
The user mysql home directory is /nonexistent
The user tss home directory is /var/lib/tpm
The user Debian-snmp home directory is /var/lib/snmp
The user lightdm home directory is /var/lib/lightdm
```

