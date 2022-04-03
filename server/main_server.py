#!/usr/bin/env python3

import asyncio
import json
import sys
from datetime import datetime

from typing import Dict, List, Tuple

BUFFER_SIZE = 100000
TASK_QUEUE = asyncio.Queue()
SIGNATURE_QUEUE = asyncio.Queue()


class SignerManager:
    def __init__(self, config, signer_instances) -> None:
        self.num_parties: int = config.get("num_parties")
        self.threshold: int = config.get("threshold")
        self.signers: List[Dict] = config.get("signers")
        self.signer_instances = signer_instances
        self.awake_signers = []
        self.active_signers = []
        
    @staticmethod
    async def _distribute_data(messages, request_type, instances):
        for index, (_, w) in enumerate(instances):
            w.write(json.dumps(
                build_payload(request_type, messages[index])
                ).encode('utf-8'))
        await w.drain()
 
        
    async def connect_to_signers(self):
        for signer in self.signers:
            self.signer_instances[signer.get("index")] = await asyncio.open_connection(signer.get("host"), signer.get("port"))
            
    async def _init_keygen(self):
        for _, (_, w) in enumerate(self.signer_instances):
            w.write(json.dumps(
                build_payload("GenerateKey", [])
            ).encode('utf-8'))
            await w.drain()
            
    
    @staticmethod
    async def _recv_to_array(array: List, expected_phase: str, instances: List,  multiple: bool = False) -> None:
        for index, (r, _) in enumerate(instances):
            recv = (await r.read(BUFFER_SIZE)).decode("utf-8")
            print(recv)
            recv_dct = json.loads(recv)
            if (recv_type := recv_dct.get("response_type")) != expected_phase:
                print(recv_type)
                raise RuntimeError("Wrong response type: " + recv_type + " != " + expected_phase)

            if not multiple:
                array[index] = recv_dct['data'][0]
                continue

            array[index] = recv_dct['data']
            array[index].insert(index, None)
            
    def _build_distributed_data(self, recv_array: List, instances: List) -> List:
        built_array = []
        for signer in range(len(instances)):
            built_array.append([])
            for message in range(len(recv_array)):
                if message == signer:
                    continue
                built_array[-1].append(recv_array[message])
        return built_array

    @staticmethod
    def _build_distributed_data_p3(recv_array) -> List:
        messages = [[recv_array[j][i] for j in range(len(recv_array))] for i in range(len(recv_array[0]))]
        cleaned = []
        for i in range(len(messages)):
            cleaned.append([])
            for j in range(len(messages[i])):
                if messages[i][j] is None:
                    continue
                cleaned[-1].append(messages[i][j])
        return cleaned
            
    async def key_generation(self) -> List:
        await self._init_keygen()

        for phase in range(5):
            recv_messages = [None for _ in self.signers]
            if phase == 2:
                await SignerManager._recv_to_array(recv_messages, "GenerateKey", self.signer_instances,  True)
                send_messages = SignerManager._build_distributed_data_p3(recv_messages)
            else:
                await SignerManager._recv_to_array(recv_messages, "GenerateKey", self.signer_instances)
                send_messages = self._build_distributed_data(recv_messages, self.signer_instances)
            await SignerManager._distribute_data(send_messages, "GenerateKey", self.signer_instances)

        key_gen_sign_contexts = [None for _ in self.signers]
        await SignerManager._recv_to_array(key_gen_sign_contexts, "GenerateKey", self.signer_instances)
        return key_gen_sign_contexts
    
    async def _get_signer(self, index):
        reader, _ = self.signer_instances[index]
        response = (await reader.read(BUFFER_SIZE)).decode("utf8")
        print(f'for index {index} response {response}')
        return index, response
    
    async def get_active_signers(self) -> None:
        current_missing = self.threshold
        for (_, w) in self.signer_instances:
            w.write(json.dumps(
                build_payload("InitSign", [])
                ).encode('utf-8'))
            await w.drain()

        active_signers = []
        awake_signers = []

        for f in asyncio.as_completed([self._get_signer(i) for i in range(self.num_parties)]):
            index, response = await f
            print(response)
            if current_missing > 0:
                current_missing -= 1
                active_signers.append(index)
            awake_signers.append(index)

        print("awake:", awake_signers)
        self.active_signers = active_signers
        self.awake_signers = awake_signers
    
    async def mp_sign_init(self, hash, timestamp):
        print("Active signers", self.active_signers)
        for index in self.active_signers:
            _, w = self.signer_instances[index]
            payload = build_payload("Sign", [bytes(self.active_signers).hex(), hash, timestamp.hex()])
            dump = json.dumps(payload).encode('utf-8')
            print(dump)
            w.write(dump)
            await w.drain()

        for index, (r, w) in enumerate(self.signer_instances):
            if not (index in self.awake_signers and index not in self.active_signers):
                continue
            payload = build_payload("Abort", [])
            dump = json.dumps(payload).encode('utf-8')
            print(dump)
            w.write(dump)
            await w.drain()
            await r.read(BUFFER_SIZE)


    async def mp_sign(self):
        active_signer_instances = [self.signer_instances[i] for i in self.active_signers]

        for phase in range(9):
            recv_messages = [None for _ in range(self.threshold)]
            if phase == 1:
                await SignerManager._recv_to_array(recv_messages, "Sign",active_signer_instances,  True)
                send_messages = SignerManager._build_distributed_data_p3(recv_messages)
            else:
                await SignerManager._recv_to_array(recv_messages, "Sign", active_signer_instances)
                send_messages = self._build_distributed_data(recv_messages, active_signer_instances)
            await SignerManager._distribute_data(send_messages, "Sign", active_signer_instances)

        signatures = [None for _ in range(self.threshold)]
        await SignerManager._recv_to_array(signatures, "Sign", active_signer_instances)
        print("Signing done")
        return signatures

def build_payload(request_type: str, data: List):
    return {
        "request_type": request_type,
        "data": data
    }


async def sign_data(data: str):
    timestamp = str(int(datetime.now().timestamp()))
    print("GOT DATA:", data)
    await TASK_QUEUE.put((data, timestamp.encode("utf-8")))
    print("put into queue")
    signature = await SIGNATURE_QUEUE.get()
    return json.dumps(
        {
            "status": "success",
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
    request_data = (await reader.read(BUFFER_SIZE)).decode("utf-8")
    request = json.loads(request_data)
    response_data = await handle_command(request)

    # TODO I think the channel back (with the real timestamp) would have to be encrypted,
    # because someone can mangle with the timestamp
    # TODO figure out how secure channels work
    writer.write(response_data.encode("utf-8"))
    await writer.drain()
    writer.close()



def to_byte_array(data):
    return [x for x in bytes(data, 'utf-8')]


async def signer_manager(config, signer_instances):
    manager = SignerManager(config, signer_instances)
    await manager.connect_to_signers()
    contexts = await manager.key_generation()
    print(contexts)
    print("signers inited")
    while True:
        hash, timestamp = await TASK_QUEUE.get()
        print(hash, timestamp)
        await manager.get_active_signers()
        await manager.mp_sign_init(hash, timestamp)
        signatures = await manager.mp_sign()
        print("Signing complete, signatures:", signatures)
        await SIGNATURE_QUEUE.put(signatures[0])


def main():
    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "CONFIG_FILE")
    config_filename = sys.argv[1]
    with open(config_filename, "r") as config_file:
        config = json.load(config_file)

    signer_instances = [None for _ in config.get("signers")]

    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.start_server(handle_client, config.get("host"), config.get("port")))
    loop.run_until_complete(signer_manager(config, signer_instances))

    try:
        print("Running... Press ^C to shutdown")
        loop.run_forever()
    except KeyboardInterrupt:
        for _, w in signer_instances:
            w.close()

    loop.close()


if __name__ == "__main__":
    main()
