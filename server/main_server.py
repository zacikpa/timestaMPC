#!/usr/bin/env python3

import asyncio
import json
import secrets
import sys
import ca
import glob
from base64 import b64encode, b64decode
from datetime import datetime
from typing import Dict, List
from signer_instance import SignerInstance

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

REQUEST_QUEUE = asyncio.Queue()
RESPONSE_QUEUE = asyncio.Queue()
CLIENT_BUFFER_SIZE = 2000
BUFFER_SIZE_PER_PARTY = 20000


class SignerManager:
    def __init__(self, config) -> None:
        self.num_parties: int = config.get("num_parties")
        self.threshold: int = config.get("threshold")
        self.refresh: bool = config.get("refresh")
        self.manager_key_path: str = config.get("manager_key")
        if self.refresh and (self.num_parties != 2):
            raise RuntimeError("For refresh to work there must be exactly 2 parties (2-of-2).")

        self.do_2p = (self.num_parties == 2 and self.refresh)
        self.signers: List[Dict] = config.get("signers")
        self.signer_instances: List[SignerInstance] = []
        self.active_signers = []
        self.buffer_size = self.num_parties * BUFFER_SIZE_PER_PARTY
        self.signer_public_keys = []
        self.manager_key = None

    async def spawn_instances(self) -> bool:
        for signer in self.signers:
            self.signer_instances.append(SignerInstance(signer.get("index"), signer.get("host"), signer.get("port")))
        for instance in self.signer_instances:
            if not (await instance.connect()):
                return False
        return True


    def load_keyfiles(self):
        for signer in self.signers:
            with open(signer["key"], "rb") as key_file:
                self.signer_public_keys.append(
                    serialization.load_pem_public_key(key_file.read())
                    )
        with open(self.manager_key_path, 'rb') as f:
            self.manager_key = serialization.load_pem_private_key(f.read(), None)


    """
    1) Manager pošle signerům zašifrovaná náhodná data (asi to může být vygenerované stejným způsobem jako symetrický klíč)
    Signeři dešifrují, vygenerují symetrický klíč a pošlou zašifrovaný symetrický klíč || přijatá náhodná data
    2) Manager dešifruje, porovná náhodná data a uloží si symetrický klíč. Pošle prázdnou zprávu zašifrovanou tím klíčem. (od teď už jsou zašifrované všechny zprávy)
    Signeři pošlou zpátky asymetricky zašifrovaná nová náhodná data pro signery s vyšším indexem.
    3) Manager přepošle data
    Signeři dešifrují náhodná data a pošlou odpovídajícím signerům zašifrovaný symetrický klíč || data
    4) Manager přepošle
    Signeři přijmou, dešifrují, zkontrolují náhodná data, uloží si klíče, pošlou prázdnou odpověď.
    """
    async def distribute_symmetric_key(self):
        recv_messages = [None for _ in self.signers]
        random_challenges = [secrets.token_bytes(32) for _ in self.signer_instances]
        for index, signer in enumerate(self.signer_instances):
            public_key = self.signer_public_keys[index]
            encrypted_data = public_key.encrypt(
                random_challenges[index],
                padding.PKCS1v15()
            )
            payload = build_payload("SymmetricKeySend", [b64encode(encrypted_data).decode()])
            await signer.send(payload, skip_encrypt=True)
            recv_messages[index] = json.loads(await signer.recv(BUFFER_SIZE_PER_PARTY, skip_decrypt=True))

        for index, response in enumerate(recv_messages):
            response = b64decode(response["data"][0])
            response = self.manager_key.decrypt(response, padding.PKCS1v15())
            sym_key, resp = response[:32], response[32:]
            if resp != random_challenges[index]:
                # TODO abort or sth
                print("BAD BAD BAD CHALLENGE")
                return
            self.signer_instances[index].symmetric_key = sym_key

        for signer in self.signer_instances:
            await signer.send(build_payload("SymmetricKeySend", []), True)

        for _ in range(2):
            await self._recv_to_array(recv_messages, "SymmetricKeySend", self.signer_instances, multiple=True)

            send_messages = SignerManager._build_distributed_data_p3(recv_messages)
            await SignerManager._distribute_data(send_messages, "SymmetricKeySend", self.signer_instances)

        # empty messages
        for signer in self.signer_instances:
            await signer.recv(BUFFER_SIZE_PER_PARTY)



    @staticmethod
    async def _distribute_data(messages, request_type, instances: List[SignerInstance]):
        for index, signer in enumerate(instances):
            await signer.send(build_payload(request_type, messages[index]))

    async def _init_keygen(self, message):
        for signer in self.signer_instances:
            await signer.send(build_payload(message, []))

    async def _recv_to_array(self, array: List, expected_phase: str, instances: List[SignerInstance],  multiple: bool = False, skip_decrypt: bool = False) -> None:
        for index, signer in enumerate(instances):
            recv = await signer.recv(self.buffer_size, skip_decrypt=skip_decrypt)
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

        phase_enum = "GenerateKey2p" if self.do_2p else "GenerateKey"

        await self._init_keygen(phase_enum)
        print(self.signer_instances, self.active_signers)

        for phase in range(5 if not self.do_2p else 3):
            recv_messages = [None for _ in self.signers]
            if phase == 2 and not self.do_2p:
                await self._recv_to_array(recv_messages, phase_enum, self.signer_instances,  True)
                send_messages = SignerManager._build_distributed_data_p3(recv_messages)
            else:
                await self._recv_to_array(recv_messages, phase_enum, self.signer_instances)
                send_messages = self._build_distributed_data(recv_messages, self.signer_instances)
            await SignerManager._distribute_data(send_messages, phase_enum, self.signer_instances)

        key_gen_sign_contexts = [None for _ in self.signers]
        await self._recv_to_array(key_gen_sign_contexts, phase_enum, self.signer_instances)

        return key_gen_sign_contexts

    async def _get_signer(self, index):
        signer = self.signer_instances[index]
        response = await signer.recv(self.buffer_size)
        print(f'for index {index} response {response}')
        return index, response

    async def get_active_signers(self) -> None:
        current_missing = self.threshold
        for signer in self.signer_instances:
            if not signer.is_connected():
                print("Trying to reconnect to {}".format(signer.index))
                await signer.connect()
            await signer.send(build_payload("InitSign", []))

        active_signers = []

        for f in asyncio.as_completed([self._get_signer(i) for i in range(self.num_parties)]):
            index, response = await f
            if current_missing > 0 and len(response) != 0:
                current_missing -= 1
                active_signers.append(index)
                print(active_signers, current_missing)

        self.active_signers = active_signers

    async def refresh_2p(self):
        phase_enum = "Refresh2p"

        await self._init_keygen(phase_enum)
        print(self.signer_instances, self.active_signers)

        for _ in range(3):
            recv_messages = [None for _ in self.signers]

            await self._recv_to_array(recv_messages, phase_enum, self.signer_instances)
            send_messages = self._build_distributed_data(recv_messages, self.signer_instances)
            await SignerManager._distribute_data(send_messages, phase_enum, self.signer_instances)

        # now they _probably_ wont send new key TODO
        key_gen_sign_contexts = [None for _ in self.signers]
        await self._recv_to_array(key_gen_sign_contexts, phase_enum, self.signer_instances)

        return key_gen_sign_contexts

    async def mp_sign_init(self, hash, timestamp):
        print("Active signers", self.active_signers)
        for index in self.active_signers:
            signer = self.signer_instances[index]

            if self.do_2p:
                payload = build_payload("Sign2p", [hash, b64encode(timestamp).decode()])
            else:
                payload = build_payload("Sign", [b64encode(bytes(self.active_signers)).decode(), hash, b64encode(timestamp).decode()])

            print(payload)
            dump = json.dumps(payload).encode('utf-8')
            print(dump)
            await signer.send(payload)

        if self.do_2p:
            return
        # all signers have to be online if 2p (both of them)

        for index, signer in enumerate(self.signer_instances):
            if index in self.active_signers:
                continue
            payload = build_payload("Abort", [])
            dump = json.dumps(payload).encode('utf-8')
            print(dump)
            await signer.send(payload)
            await signer.recv(self.buffer_size)

    async def mp_sign(self):
        active_signer_instances = [self.signer_instances[i] for i in sorted(self.active_signers)]

        for phase in range(9 if not self.do_2p else 3):
            recv_messages = [None for _ in range(self.threshold)]
            if phase == 1 and not self.do_2p:
                await self._recv_to_array(recv_messages, "Sign", active_signer_instances,  True)
                send_messages = SignerManager._build_distributed_data_p3(recv_messages)
            else:
                await self._recv_to_array(recv_messages, "Sign" if not self.do_2p else "Sign2p", active_signer_instances)
                send_messages = self._build_distributed_data(recv_messages, active_signer_instances)
            await SignerManager._distribute_data(send_messages, "Sign" if not self.do_2p else "Sign2p", active_signer_instances)

        signatures = [None for _ in range(self.threshold)]
        await self._recv_to_array(signatures, "Sign" if not self.do_2p else "Sign2p", active_signer_instances)
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
    await REQUEST_QUEUE.put((data, timestamp.encode("utf-8")))
    print("put into queue")
    response = await RESPONSE_QUEUE.get()
    if response["status"] == "success":
        response["timestamp"] = timestamp
    return json.dumps(response)


async def handle_command(data) -> str:
    match data["command"]:
        case "sign":
            return await sign_data(data["data"])
        # TODO figure out more commands


async def handle_client(reader, writer):
    request_data = (await reader.read(CLIENT_BUFFER_SIZE)).decode("utf-8")
    try:
        request = json.loads(request_data)
        response_data = await handle_command(request)
    except json.JSONDecodeError:
        response = {
            "status": "failure",
            "reason": "invalid request"
        }
        response_data = json.dumps(response)
    writer.write(response_data.encode("utf-8"))
    await writer.drain()
    writer.close()


def to_byte_array(data):
    return [x for x in bytes(data, 'utf-8')]


async def signer_manager(manager: SignerManager):
    manager.load_keyfiles()
    if not (await manager.spawn_instances()):
        exit("Error: could not connect to all signers")

    await manager.distribute_symmetric_key()

    try:
        contexts = await manager.key_generation()
    except (RuntimeError, json.JSONDecodeError) as err:
        print(str(err))
        exit("Error: communication with signers failed during key generation")
    print("Key point", b64decode(contexts[0].encode()).hex())
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b64decode(contexts[0].encode()))
    manager.certificate = ca.issue_cert("TimestaMPC", public_key)
    print(contexts)
    print("signers inited")
    while True:
        hash, timestamp = await REQUEST_QUEUE.get()
        print(hash, timestamp)
        await manager.get_active_signers()
        if len(manager.active_signers) < manager.threshold:
            response = {
                "status": "failure",
                "reason": "unable to connect to enough signing servers"
            }
            await RESPONSE_QUEUE.put(response)
            for signer in manager.signer_instances:
                if signer.index in manager.active_signers:
                    await signer.send(build_payload("Abort", []))
                    await signer.recv(manager.buffer_size)
            continue
        try:
            await manager.mp_sign_init(hash, timestamp)
            signatures = await manager.mp_sign()
        except (RuntimeError, json.JSONDecodeError) as err:
            print(str(err))
            response = {
                "status": "failure",
                "reason": "communication with signers failed"
            }
            await RESPONSE_QUEUE.put(response)
            continue
        print("Signing complete, signatures:", signatures)
        response = {
            "status": "success",
            "signature": signatures[0],
            "certificate": manager.certificate.public_bytes(serialization.Encoding.PEM).decode()
        }
        await RESPONSE_QUEUE.put(response)

        if manager.do_2p:
            await manager.refresh_2p()


def main():
    if len(sys.argv) != 2:
        print("Usage:", sys.argv[0], "CONFIG_FILE")
        return

    config_filename = sys.argv[1]
    with open(config_filename, "r") as config_file:
        config = json.load(config_file)
    manager = SignerManager(config)

    loop = asyncio.new_event_loop()
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
