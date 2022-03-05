#!/usr/bin/env python3

import asyncio
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes


async def sign_data(data):
    # TODO figure out precision

    timestamp = str(datetime.now())
    digest = hashes.Hash(hashes.SHA256())
    digest.update(bytes(data + timestamp, "utf-8"))
    hash_hex = digest.finalize().hex()

    # TODO distribute to clients (hash, timestamp)

    await asyncio.sleep(5)

    return json.dumps(
        {
            "type": "result",
            "data": "success",
            "signature": hash_hex,
            "timestamp": timestamp,
        }
    )


async def handle_command(data) -> str:
    match data["command"]:
        case "sign":
            return await sign_data(data["data"])
        # TODO figure out more commands


async def handle_client(reader, writer):
    request = None
    request = (await reader.read(255)).decode("utf8")
    data = json.loads(request)

    result = await handle_command(data)

    # TODO I think the channel back (with the real timestamp) would have to be encrypted,
    # because someone can mangle with the timestamp
    # TODO figure out how secure channels work
    writer.write(result.encode("utf-8"))
    await writer.drain()
    writer.close()


async def run_server():
    server = await asyncio.start_server(handle_client, "localhost", 15555)
    async with server:
        await server.serve_forever()


asyncio.run(run_server())
