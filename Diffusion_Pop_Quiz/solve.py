from pwn import *
from string import printable
import re

def remove_ansi_escape_codes(text):
    # Regular expression to match ANSI escape codes
    ansi_escape = re.compile(r'(?:\x1B[@-_][0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

io = remote('diffusion-pop-quiz.ctf.csaw.io' ,5000)



io.recvuntil('Can you decrypt this? ')
ct = io.recvuntil('\n').decode().strip()
ct = remove_ansi_escape_codes(ct)

print(ct)

pt = 'Diffusion matters a lo'
for k in ct:
    if k == ' ':
        pt += ' '
        continue
    for c in printable:
        io.recvuntil('encrypt?')
        io.sendline(pt + c)
        io.recvuntil('Here is your encrypted text: ')
        res = io.recvuntil('\n').decode().strip()
        res = remove_ansi_escape_codes(res)
        if res == ct[:len(res)]:
            pt += c
            break
        io.recvuntil('Would you like to continue? (yes/no)')
        io.sendline('yes')
        print(c,pt)

    
print(pt)
