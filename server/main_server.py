#!/usr/bin/env python3

import asyncio
from email import message
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes

N_SIGNERS = 3
K_SIGNERS = 2

SIGNERS = [("localhost", 30000 + x) for x in range(N_SIGNERS)]
SIGNER_INSTANCES = [None for _ in range(len(SIGNERS))]
ACTIVE_SIGNERS = []

TASK_QUEUE = asyncio.Queue()
SIGNATURE_QUEUE = asyncio.Queue()

def build_payload(request_type, data):
    return {
        "request_type": request_type,
        "data": data
    }

async def sign_data(data):
    # TODO figure out precision

    timestamp = str(int(datetime.now().timestamp()))
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(data + timestamp, "utf-8"))
    hash_hex = digest.finalize().hex()
    print("GOT HEX:", hash_hex)
    # TODO distribute to clients (hash, timestamp)
    await TASK_QUEUE.put((hash_hex, timestamp))
    print("put into queue")
    signature = await SIGNATURE_QUEUE.get()    

    return json.dumps(
        {
            "type": "result",
            "data": "success",
            "signature": signature,
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
    request = (await reader.read(4096)).decode("utf8")
    data = json.loads(request)

    result = await handle_command(data)

    # TODO I think the channel back (with the real timestamp) would have to be encrypted,
    # because someone can mangle with the timestamp
    # TODO figure out how secure channels work
    writer.write(result.encode("utf-8"))
    await writer.drain()
    writer.close()
 
async def _distribute_copies(writer, messages):
    writer.write(json.dumps(
        build_payload("GenerateKey", messages)
        ).encode('utf-8'))
    await writer.drain()
        
async def _distribute_p3(recv_messages, instances):
    messages = [[recv_messages[j][i] for j in range(len(recv_messages))] for i in range(len(recv_messages[0]))]
    cleaned = []
    for i in range(len(messages)):
        cleaned.append([])
        for j in range(len(messages[i])):
            if messages[i][j] is None:
                continue
            cleaned[-1].append(messages[i][j])
            
    for index, (_, w) in enumerate(instances):
        w.write(json.dumps(
            build_payload("GenerateKey", cleaned[index])).encode('utf-8'))
        await w.drain()
        
async def _init_keygen():
    for _, (_, w) in enumerate(SIGNER_INSTANCES):
        w.write(json.dumps(
            build_payload("GenerateKey", {})
        ).encode('utf-8'))
        await w.drain()
        
async def _recv_to_array(array, expected_phase, instances, multiple = False):
    for index, (r, _) in enumerate(instances):
        recv = (await r.read(4096)).decode("utf-8")
        print(recv)
        recv_dct = json.loads(recv)
        if recv_type := recv_dct.get("message_type") != expected_phase:
            raise RuntimeError("Wrong message type: " + recv_type + " != " + expected_phase)
        
        if not multiple:
            array[index] = recv_dct['data']['commitment'][0]
            continue
        
        array[index] = recv_dct['data']['commitment']
        array[index].insert(index, None)
        
        
async def _recv_results(array, expected_phase, instances):
    for index, (r, _) in enumerate(instances):
        recv = (await r.read(4096)).decode("utf-8")
        recv_dct = json.loads(recv)
        if recv_type := recv_dct.get("message_type") != expected_phase:
            raise RuntimeError("Wrong message type: " + recv_type + " != " + expected_phase)
        
        print(recv_dct)
        array[index] = recv_dct['data']
        

def _build_distributed_data(recv_array, instances):
    built_array = []
    for signer in range(len(instances)):
        built_array.append([])
        for message in range(len(recv_array)):
            if message == signer:
                continue
            
            built_array[-1].append(recv_array[message])
            
    return built_array
        
async def _get_signer(index):
    reader, _ = SIGNER_INSTANCES[index]
    response = (await reader.read(4096)).decode("utf8") 
    return index, response
        
async def _get_active_signers():
    current_missing = K_SIGNERS
    for (_, w) in SIGNER_INSTANCES:
        w.write(json.dumps(
            build_payload("InitSign", [])
            ).encode('utf-8'))
        await w.drain()
        
    for f in asyncio.as_completed([_get_signer(i) for i in range(N_SIGNERS)]):
        index, response = await f
        current_missing -= 1
        print(response)
        ACTIVE_SIGNERS.append(index)
        if current_missing == 0:
            break
        
def to_byte_array(data):
    return [x for x in bytes(data, 'utf-8')]

async def mp_sign_init(hash, timestamp: str):
    for index in ACTIVE_SIGNERS:
        _, w = SIGNER_INSTANCES[index]
        payload = build_payload("Sign", 
                          [sorted(ACTIVE_SIGNERS), to_byte_array(hash), to_byte_array(timestamp)]
                          )
        dump = json.dumps(
            payload
            ).encode('utf-8')
        print(dump)
        w.write(dump)
        await w.drain()
    
async def mp_sign():
    active_signer_instances = [SIGNER_INSTANCES[i] for i in ACTIVE_SIGNERS]
    sign_messages = [None for _ in range(K_SIGNERS)]
    await _recv_to_array(sign_messages, "Sign", active_signer_instances)
    
    copies_of_data = _build_distributed_data(sign_messages, active_signer_instances)
    
    for index, (_, w) in enumerate(active_signer_instances):
        await _distribute_copies(w, copies_of_data[index])
        
    p3_messages = [None for _ in range(K_SIGNERS)]
    await _recv_to_array(p3_messages, "Sign", active_signer_instances, True)
    await _distribute_p3(p3_messages, active_signer_instances)
    
    for _ in range(6):
        sign_messages = [None for _ in range(K_SIGNERS)]
        await _recv_to_array(sign_messages, "Sign", active_signer_instances)
        
        copies_of_data = _build_distributed_data(sign_messages, active_signer_instances)
        
        for index, (_, w) in enumerate(active_signer_instances):
            await _distribute_copies(w, copies_of_data[index])
            
    signatures = [None for _ in range(K_SIGNERS)]
    await _recv_results(signatures, "Sign", active_signer_instances)
    print("signatures got")
    return signatures
    
    
async def signer_manager():
    contexts = await key_generation()
    print(contexts)
    print("signers inited")
    while True:
        task, timestamp = await TASK_QUEUE.get()
        print(task, timestamp)
        ACTIVE_SIGNERS.clear()
        await _get_active_signers()
        await mp_sign_init(task, timestamp)
        signatures = await mp_sign()
        print("Signing complete, signatures:", signatures)
        await SIGNATURE_QUEUE.put(signatures[0]["signature"])
        
    
async def key_generation():
    for index, (url, port) in enumerate(SIGNERS):
        SIGNER_INSTANCES[index] = (await asyncio.open_connection(url, port))
    
    await _init_keygen()
    
    for _ in range(2):
        key_gen_messages = [None for _ in range(len(SIGNERS))]
        await _recv_to_array(key_gen_messages, "GenerateKey", SIGNER_INSTANCES)
    
        copies_of_data = _build_distributed_data(key_gen_messages, SIGNER_INSTANCES)
        print("AAAAAAAAA", copies_of_data)
    
        for index, (_, w) in enumerate(SIGNER_INSTANCES):
            await _distribute_copies(w, copies_of_data[index])
    
    key_gen_messages = [None for _ in range(len(SIGNERS))]
    await _recv_to_array(key_gen_messages, "GenerateKey", SIGNER_INSTANCES, True)
    await _distribute_p3(key_gen_messages, SIGNER_INSTANCES)
    
    for _ in range(2):
        key_gen_messages = [None for _ in range(len(SIGNERS))]
        await _recv_to_array(key_gen_messages, "GenerateKey", SIGNER_INSTANCES)
    
        copies_of_data = _build_distributed_data(key_gen_messages, SIGNER_INSTANCES)
        print(copies_of_data)
    
        for index, (_, w) in enumerate(SIGNER_INSTANCES):
            await _distribute_copies(w, copies_of_data[index])

    key_gen_sign_contexts = [None for _ in range(len(SIGNERS))]
    await _recv_to_array(key_gen_sign_contexts, "GenerateKey", SIGNER_INSTANCES)
    return key_gen_sign_contexts

loop = asyncio.get_event_loop()
server = loop.run_until_complete(asyncio.start_server(handle_client, "localhost", 15555))
signer_server = loop.run_until_complete(signer_manager())
servers = [server, signer_server]
try:
    print("Running... Press ^C to shutdown")
    loop.run_forever()
except KeyboardInterrupt:
    for _, w in SIGNER_INSTANCES:
        w.close()

loop.close()

