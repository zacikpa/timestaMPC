import asyncio
import json

BUFFER_SIZE = 100000

class SignerInstance:
    def __init__(self, index, host, port) -> None:
        self.host = host
        self.port = port
        self.reader, self.writer = None, None
        self.index = index
        
    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)    
    
    async def send(self, payload):
        self.writer.write(json.dumps(
                payload
            ).encode('utf-8'))
        await self.writer.drain()
        
    async def recv(self):
        return (await self.reader.read(BUFFER_SIZE)).decode("utf8")
    
    def __repr__(self) -> str:
        return f'Server @ {self.port} with index {self.index}'
    
    def __str__(self) -> str:
        return self.__repr__()