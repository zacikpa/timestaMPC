#!/usr/bin/env python3

import asyncio
import json
import sys
from datetime import datetime

from typing import Dict, List, Tuple

from signer_instance import SignerInstance

BUFFER_SIZE = 100000
TASK_QUEUE = asyncio.Queue()
SIGNATURE_QUEUE = asyncio.Queue()


class SignerManager:
    def __init__(self, config) -> None:
        self.num_parties: int = config.get("num_parties")
        self.threshold: int = config.get("threshold")
        self.signers: List[Dict] = config.get("signers")
        self.signer_instances: List[SignerInstance] = []
        self.awake_signers = []
        self.active_signers = []
            
    async def spawn_instances(self):
        for signer in self.signers:
            self.signer_instances.append(SignerInstance(signer.get("index"), signer.get("host"), signer.get("port")))
        for instance in self.signer_instances:
            await instance.connect()
        
        
    @staticmethod
    async def _distribute_data(messages, request_type, instances: List[SignerInstance]):
        for index, signer in enumerate(instances):
            await signer.send(build_payload(request_type, messages[index]))
            
    async def _init_keygen(self):
        for signer in self.signer_instances:
            await signer.send(build_payload("GenerateKey", []))
            
    
    @staticmethod
    async def _recv_to_array(array: List, expected_phase: str, instances: List[SignerInstance],  multiple: bool = False) -> None:
        for index, signer in enumerate(instances):
            recv = await signer.recv()
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
        print(self.signer_instances, self.active_signers, self.awake_signers)
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
        signer = self.signer_instances[index]
        response = await signer.recv()
        print(f'for index {index} response {response}')
        return index, response
    
    async def get_active_signers(self) -> None:
        current_missing = self.threshold
        for signer in self.signer_instances:
            await signer.send(build_payload("InitSign", []))

        active_signers = []
        awake_signers = []

        for f in asyncio.as_completed([self._get_signer(i) for i in range(self.num_parties)]):
            index, response = await f
            print("response: ", response, len(response), type(response), index)
            if current_missing > 0 and len(response) != 0:
                current_missing -= 1
                active_signers.append(index)
                print(active_signers, current_missing)
            awake_signers.append(index)

        print("awake:", awake_signers)
        self.active_signers = active_signers
        self.awake_signers = awake_signers
    
    async def mp_sign_init(self, hash, timestamp):
        print("Active signers", self.active_signers)
        for index in self.active_signers:
            signer = self.signer_instances[index]
            payload = build_payload("Sign", [bytes(self.active_signers).hex(), hash, timestamp.hex()])
            dump = json.dumps(payload).encode('utf-8')
            print(dump)
            await signer.send(payload)

        for index, signer in enumerate(self.signer_instances):
            if not (index in self.awake_signers and index not in self.active_signers):
                continue
            payload = build_payload("Abort", [])
            dump = json.dumps(payload).encode('utf-8')
            print(dump)
            try:
                await signer.send(payload)
                await signer.recv()
            except ConnectionResetError:
                print(f'Server {index} is already dead.')


    async def mp_sign(self):
        active_signer_instances = [self.signer_instances[i] for i in self.active_signers]

        for phase in range(9):
            recv_messages = [None for _ in range(self.threshold)]
            if phase == 1:
                await SignerManager._recv_to_array(recv_messages, "Sign", active_signer_instances,  True)
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


async def signer_manager(manager: SignerManager):
    await manager.spawn_instances()
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
    manager = SignerManager(config)
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.start_server(handle_client, config.get("host"), config.get("port")))
    loop.run_until_complete(signer_manager(manager))

    try:
        print("Running... Press ^C to shutdown")
        loop.run_forever()
    except KeyboardInterrupt:
        for signer in manager.signer_instances:
            signer.writer.close()

    loop.close()


if __name__ == "__main__":
    main()
