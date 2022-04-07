import asyncio
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BUFFER_SIZE = 100000


class SignerInstance:
    def __init__(self, index, host, port, symmetric_key, iv) -> None:
        self.host = host
        self.port = port
        self.reader, self.writer = None, None
        self.index = index
        self.connected = False
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()


    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            self.connected = True
        except ConnectionRefusedError:
            return False
        return True

    async def send(self, payload, skip_encrypt=False):
        payload = json.dumps(
                payload
            ).encode('utf-8')
        
        if not skip_encrypt:
            payload = self.encryptor.update(payload) + self.encryptor.finalize()
            
        try:
            self.writer.write(payload)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self.connected = False

    async def recv(self, size, skip_decrypt=False):
        try:
            data = (await self.reader.read(size)).decode("utf8")
        except (ConnectionResetError, BrokenPipeError):
            data = ""
        if len(data) == 0:
            self.connected = False

        if not skip_decrypt:
            data = self.decryptor.update(data) + self.decryptor.finalize()
        return data

    def is_connected(self):
        return self.connected

    def __repr__(self) -> str:
        return f'Server @ {self.port} with index {self.index}'

    def __str__(self) -> str:
        return self.__repr__()
