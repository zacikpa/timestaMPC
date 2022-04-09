import asyncio
import json


class SignerInstance:
    def __init__(self, index, host, port) -> None:
        self.host = host
        self.port = port
        self.reader, self.writer = None, None
        self.index = index
        self.connected = False

    async def connect(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
            self.connected = True
        except ConnectionRefusedError:
            return False
        return True

    async def send(self, payload):
        payload = json.dumps(payload).encode()
        try:
            self.writer.write(payload)
            await self.writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            self.connected = False

    async def recv(self, size):
        try:
            data = (await self.reader.read(size))
        except (ConnectionResetError, BrokenPipeError):
            data = b""
        return data.decode()

    def is_connected(self):
        return self.connected

    def __repr__(self) -> str:
        return f'Server @ {self.port} with index {self.index}'

    def __str__(self) -> str:
        return self.__repr__()
