#!/usr/bin/env python3

import asyncio
import sys
import json
import random
from datetime import datetime
from cryptography.hazmat.primitives import hashes

async def handle_signing(reader, writer):
    request = None
    for _ in range(2):
        request = (await reader.read(255)).decode("utf8")
        print(request)
        writer.write(json.dumps({
                "message_type": "GenerateKey",
                "data": {
                    "commitment": [["MESSAGE #" + str(random.randint(1, 100))]]
                }
            }).encode('utf-8'))
    request = (await reader.read(255)).decode("utf8")
    print(request)
    writer.write(json.dumps({
            "message_type": "GenerateKey",
            "data": {
                "commitment": [["MESSAGE #" + str(random.randint(1, 100))] for _ in range(3)]
            }
        }).encode('utf-8'))
    
        
    for _ in range(2):
        request = (await reader.read(255)).decode("utf8")
        print(request)
        writer.write(json.dumps({
                "message_type": "GenerateKey",
                "data": {
                    "commitment": [["MESSAGE #" + str(random.randint(1, 100))]]
                }
            }).encode('utf-8'))
        
    request = (await reader.read(255)).decode("utf8")
    print(request)
    writer.write(json.dumps({
            "message_type": "GenerateKey",
            "data": {
                "commitment": [["MESSAGE PBKEY YAAY #" + str(random.randint(1, 100))]]
            }
        }).encode('utf-8'))
    
_, port = sys.argv

loop = asyncio.get_event_loop()
server = loop.run_until_complete(asyncio.start_server(handle_signing, "localhost", int(port)))
servers = [server]
try:
    print("Running... Press ^C to shutdown")
    loop.run_forever()
except KeyboardInterrupt:
    pass

for i, server in enumerate(servers):
    print("Closing server {0}".format(i+1))
    server.close()
    loop.run_until_complete(server.wait_closed())
loop.close()

