from pwn import * 
from string import printable





flag = ''

with open('flag.txt', 'r') as file:
	flag = file.read()
	



guessed = 'csawctf{'

for i in range(8,len(flag)):
	for c in printable:
		payload = guessed + c
		process_instance = process('./chall')
		process_instance.sendline(payload.encode())
		process_instance.recvall()
		
		with open('output.txt','r') as file:
			data = file.read()
			print(data)
			if data == flag[:len(data)]:
				guessed = payload
				print(guessed)
				break
		
