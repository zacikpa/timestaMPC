#!/usr/bin/env python3

import asyncio
from email import message
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes

SIGNERS = [("localhost", 30000 + x) for x in range(3)]
SIGNER_INSTANCES = [None for _ in range(len(SIGNERS))]


async def sign_data(data):
    # TODO figure out precision

    timestamp = str(datetime.now())
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(data + timestamp, "utf-8"))
    hash_hex = digest.finalize().hex()

    # TODO distribute to clients (hash, timestamp)

    await asyncio.sleep(5)

    return json.dumps(
        {
            "type": "result",
            "data": "success",
            "signature": hash_hex,
            "timestamp": timestamp,
        }
    )


async def handle_command(data) -> str:
    match data["command"]:
        case "sign":
            return await sign_data(data["data"])
        # TODO figure out more commands

async def handle_client(reader, writer):
    request = None
    request = (await reader.read(255)).decode("utf8")
    data = json.loads(request)

    result = await handle_command(data)

    # TODO I think the channel back (with the real timestamp) would have to be encrypted,
    # because someone can mangle with the timestamp
    # TODO figure out how secure channels work
    writer.write(result.encode("utf-8"))
    await writer.drain()
    writer.close()
 
async def _distribute_copies(writer, messages):

    writer.write(json.dumps({
        "message_type": "GenerateKey",
        "data": {
            "commitments": messages
        }
    }).encode('utf-8'))
    await writer.drain()
        
async def _distribute_p3(recv_messages):
    messages = [[recv_messages[j][i] for j in range(len(recv_messages))] for i in range(len(recv_messages[0]))]
    cleaned = []
    for i in range(len(messages)):
        cleaned.append([])
        for j in range(len(messages[i])):
            if messages[i][j] is None:
                continue
            cleaned[-1].append(messages[i][j])
            
    for index, (_, w) in enumerate(SIGNER_INSTANCES):
        w.write(json.dumps({
            "message_type": "GenerateKey",
            "data": {
                "commitments": cleaned[index]
            }
        }).encode('utf-8'))
        await w.drain()
        
async def _init_signing():
    for index, (_, w) in enumerate(SIGNER_INSTANCES):
        w.write(json.dumps({
            "message_type": "InitGenerateKey",
            "data": {
                "number_of_signers": len(SIGNER_INSTANCES),
                "threshold": 2,
                "signer_index": index
            }
        }).encode('utf-8'))
        await w.drain()
        
async def _recv_to_array(array, expected_phase, multiple = False):
    for index, (r, _) in enumerate(SIGNER_INSTANCES):
        recv = (await r.read(255)).decode("utf8")
        recv_dct = json.loads(recv)
        if recv_type := recv_dct.get("message_type") != expected_phase:
            raise RuntimeError("Wrong message type: " + recv_type + " != " + expected_phase)
        
        print(recv_dct)
        if not multiple:
            array[index] = recv_dct['data']['commitment'][0]
            continue
        
        array[index] = recv_dct['data']['commitment']
        array[index].insert(index, None)
        

def _build_distributed_data(recv_array):
    built_array = []
    for signer in range(len(SIGNER_INSTANCES)):
        built_array.append([])
        for message in range(len(recv_array)):
            if message == signer:
                continue
            
            built_array[-1].append(recv_array[message])
            
    return built_array
        
        
 
async def init_signers():
    
    for index, (url, port) in enumerate(SIGNERS):
        SIGNER_INSTANCES[index] = (await asyncio.open_connection(url, port))
    
    await _init_signing()
    for _ in range(2):
        key_gen_messages = [None for _ in range(len(SIGNERS))]
        await _recv_to_array(key_gen_messages, "GenerateKey")
    
        copies_of_data = _build_distributed_data(key_gen_messages)
        print("AAAAAAAAA", copies_of_data)
    
        for index, (_, w) in enumerate(SIGNER_INSTANCES):
            await _distribute_copies(w, copies_of_data[index])
    
    key_gen_messages = [None for _ in range(len(SIGNERS))]
    await _recv_to_array(key_gen_messages, "GenerateKey", True)
    await _distribute_p3(key_gen_messages)
    
    for _ in range(2):
        key_gen_messages = [None for _ in range(len(SIGNERS))]
        await _recv_to_array(key_gen_messages, "GenerateKey")
    
        copies_of_data = _build_distributed_data(key_gen_messages)
        print(copies_of_data)
    
        for index, (_, w) in enumerate(SIGNER_INSTANCES):
            await _distribute_copies(w, copies_of_data[index])

    key_gen_sign_contexts = [None for _ in range(len(SIGNERS))]
    await _recv_to_array(key_gen_sign_contexts, "GenerateKey")

loop = asyncio.get_event_loop()
server = loop.run_until_complete(asyncio.start_server(handle_client, "localhost", 15555))
signer_server = loop.run_until_complete(init_signers())
servers = [server, signer_server]
try:
    print("Running... Press ^C to shutdown")
    loop.run_forever()
except KeyboardInterrupt:
    for _, w in SIGNER_INSTANCES:
        w.close()

loop.close()

