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
        return (await self.reader.read(2000)).decode()

    def close(self):
        self.writer.close()


def hash_document(filename: str) -> str:
    digest = hashes.Hash(hashes.SHA3_256())
    with open(filename, "r") as f:
        for line in f:
            digest.update(line.encode("utf-8"))

    return digest.finalize().hex()


async def sign_document(client: TMPCClient, filename: str):
    await client.connect()
    hash_of_document = hash_document(filename)
    print(hash_of_document)
    client.send_data(json.dumps({"command": "sign", "data": hash_of_document}))
    resp = await client.receive_data()
    print(resp)


def verify_signature(filename: str, timestamp: str, signature: str):
    hash_of_document = hash_document(filename)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(hash_of_document + timestamp, "utf-8"))

    hash_to_verify = digest.finalize().hex()

    if hash_to_verify != signature:
        print("signature invalid")
        return
    print("signature valid")


def main():
    if len(sys.argv) == 3:
        _, _, filename = sys.argv
        client = TMPCClient("localhost", 15555)
        asyncio.run(sign_document(client, filename))
    elif len(sys.argv) == 5:
        _, _, filename, signature, timestamp = sys.argv
        verify_signature(filename, timestamp, signature)
    else:
        print(
            "USAGE: ./client.py sign filename\n      ./client.py verify filename signature timestamp"
        )


if __name__ == "__main__":
    main()
