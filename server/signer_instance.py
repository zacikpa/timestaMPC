import asyncio
import json

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


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
            padder = padding.PKCS7(256).padder()
            padded_data = padder.update(payload)
            padded_data += padder.finalize()
            payload = self.encryptor.update(padded_data) + self.encryptor.finalize()
            
        try:
            self.writer.write(payload)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self.connected = False

    async def recv(self, size, skip_decrypt=False):
        try:
            data = (await self.reader.read(size))
        except (ConnectionResetError, BrokenPipeError):
            data = ""
        if len(data) == 0:
            self.connected = False

        if not skip_decrypt:
            data = self.decryptor.update(data) + self.decryptor.finalize()
            unpadder = padding.PKCS7(256).unpadder()
            data = unpadder.update(data)
            data += unpadder.finalize()
        return data.decode()

    def is_connected(self):
        return self.connected

    def __repr__(self) -> str:
        return f'Server @ {self.port} with index {self.index}'

    def __str__(self) -> str:
        return self.__repr__()
