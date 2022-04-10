import asyncio
import json
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class SignerInstance:
    def __init__(self, index, host, port) -> None:
        self.host = host
        self.port = port
        self.reader, self.writer = None, None
        self.index = index
        self.connected = False
        self.symmetric_key = secrets.token_bytes(32)

    def encrypt(self, data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return iv + encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, payload):
        iv, data = payload[:16], payload[16:]
        cipher = Cipher(algorithms.AES(self.symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(data) + unpadder.finalize()
        return data

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
            payload = self.encrypt(payload)

        try:
            self.writer.write(payload)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self.connected = False

    async def recv(self, size, skip_decrypt=False):
        try:
            data = (await self.reader.read(size))
        except (ConnectionResetError, BrokenPipeError):
            data = b""
        if len(data) == 0:
            self.connected = False

        if not skip_decrypt:
            try:
                data = self.decrypt(data)
            except ValueError:
                return ""

        try:
            decoded = data.decode()
        except UnicodeDecodeError:
            return ""

        return decoded

    def is_connected(self):
        return self.connected

    def __repr__(self) -> str:
        return f'Server @ {self.port} with index {self.index}'

    def __str__(self) -> str:
        return self.__repr__()
