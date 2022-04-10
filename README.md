# TimestaMPC
A multi-party timestamping server created as a semestral project for the
[Security Technologies](https://is.muni.cz/predmet/fi/jaro2022/PV204) course
at [FI MUNI](https://www.fi.muni.cz/).

## Overview
The project consists of three parts:
- The signer server (written in Rust)
- The manager server (written in Python)
- The client application (written in Python)

To get a document timestamped, the _client_ connects to the _manager server_
which then directs the signing process by communicating with _signers_.

## Build
Install necessary Python packages:
```bash
pip install -r requirements.txt
```
Compile the signer server source code:
```bash
cd server-signer
cargo build --release
```
## Intended usage
First, one needs to set up configuration files for the signers.
If we are going to do _2 out of 3_ threshold signing, the configuration
file `signer0.cfg` for one of the signers may look as follows:
```json
{
"index": 0,
"context_path": "signer0",
"private_rsa": "signer-key-0",
"manager_public_key_path": "manager-key.pub",
"pub_keys_paths": ["signer-key-0.pub", "signer-key-1.pub", "signer-key-2.pub"],
"symm_keys_folder": "symm_keys",
"host": "127.0.0.1",
"port": 30000,
"num_parties": 3,
"threshold": 2,
"acceptable_seconds": 60
}
```
The signer can then be run:
```bash
cd server-signer
./target/release/server-signer signer0.cfg
```
Once the signers are running, we must set up the manager. It also needs
a configuration file, e.g., `server.cfg`:
```json
{
  "num_parties": 3,
  "threshold": 2,
  "host": "127.0.0.1",
  "port": 15555,
  "signers":
  [
    {"index": 0, "host": "127.0.0.1", "port": 30000},
    {"index": 1, "host": "127.0.0.1", "port": 30001},
    {"index": 2, "host": "127.0.0.1", "port": 30002}
  ]
}
```
After the manager is executed, it immediately establishes a connection with the
signers in order to generate a distributed ECDSA private key.
```bash
cd server
./main_server.py server.cfg
```
At this point, the manager is ready to accept timestamping requests. To have
a document signed, use the client application:
```bash
cd client
./client.py sign document.txt
```
As a response, the client receives a JSON dictionary containing the timestamp,
server certificate, and the signature itself. The result can be immediately
validated by running the `client verify` command:
```bash
./client.py sign document.txt | ./client.py verify document.txt
```

## Authors
The project is developed by Stanislav Boboň, Jiří Gavenda, and Pavol Žáčik.
