#!/usr/bin/env python3

import asyncio
import sys
import json
import random
from datetime import datetime
from cryptography.hazmat.primitives import hashes

async def init_keygen(reader, writer):
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

async def init_sign(reader, writer):
    request = (await reader.read(255)).decode("utf8")
    print(request)
    writer.write(json.dumps({
                "message_type": "InitSign",
                "data": {
                    "commitment": [["BOY I AM HERE: " + sys.argv[1]]]
                }
            }).encode('utf-8'))
    for i in range(8):
        request = (await reader.read(255)).decode("utf8")
        print(request)
        writer.write(json.dumps({
                "message_type": "Sign",
                "data": {
                    "commitment": [["MESSAGE #" + str(random.randint(1, 100))] for _ in range(3)],
                    "sign_num": i
                }
            }).encode('utf-8'))
    
    request = (await reader.read(255)).decode("utf-8")
    print(request)
    writer.write(json.dumps({
            "message_type": "Sign",
            "data": {
                "commitment": [["MESSAGE #" + str(random.randint(1, 100))] for _ in range(3)],
                "sign_num": i,
                "signature": "boy we are here"
            }
        }).encode('utf-8'))
    

async def handle_signing(reader, writer):
    await init_keygen(reader, writer)
    print("KEYGEN INIT SUCCESSFUL")
    await init_sign(reader, writer)
    print("SIGNING SUCCESSFUL")
    
    
    
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

