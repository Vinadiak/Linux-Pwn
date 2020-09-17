from pwn import *
p = process('./pwn1',env={"LD_PRELOAD":"./libc-2.23.so"})
p.interactive()
