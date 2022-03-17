#!/usr/bin/env python3

import asyncio
import json
import sys
from cryptography.hazmat.primitives import hashes


class TMPCClient:
    def __init__(self, hostname, port) -> None:
        self.hostname = hostname
        self.port = port

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(
            self.hostname, self.port
        )

    def send_data(self, data):
        self.writer.write(bytes(data, encoding="utf-8"))

    async def receive_data(self):
        return (await self.reader.read(255)).decode()

    def close(self):
        self.writer.close()


def hash_document(filename: str) -> str:
    digest = hashes.Hash(hashes.SHA3_256())
    with open(filename, "r") as f:
        for line in f:
            digest.update(line.encode("utf-8"))

    return digest.finalize().hex()


async def sign_document(client: TMPCClient, message):
    await client.connect()
    client.send_data(json.dumps({"command": "sign", "data": message}))




def main():
    client = TMPCClient("localhost", 12345)
    asyncio.run(sign_document(client, "AHOJ AHOJ"))

if __name__ == "__main__":
    main()
