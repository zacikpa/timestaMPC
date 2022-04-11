# TimestaMPC
A multi-party timestamping server created as a semestral project for the
[Security Technologies](https://is.muni.cz/predmet/fi/jaro2022/PV204) course
at [FI MUNI](https://www.fi.muni.cz/).

## Overview
The project consists of three parts:
- The signer server (written in Rust)
- The manager server (written in Python)
- The client application (written in Python)

To get a document timestamped, the _client_ connects to the _manager_
who then directs the signing process by communicating with _signers_.

## Prerequisites
In order to build the project, you need to have:
- **Rust**, version **1.59** or higher;
- **Python**, version **3.10** or higher.

## Build
Install necessary Python packages:
```bash
pip install -r requirements.txt
```
Compile the signer server source code:
```bash
cd signer
cargo build --release
```

## Setup
We assume that the signers and the manager are able to exchange their public
keys in advance, via a secure channel. For testing purposes on a single machine,
you can use the `generate_keys.py` script:
```bash
python generate_keys.py 3 setup
```
This will generate asymmetric key pairs for 3-party ECDSA and store them in
the `setup` directory.

The `config` directory of this repository contains example configuration files
for 2-out-of-3 threshold ECDSA timestamping. These configuration files may be
changed depending on the used setup.

For instance, to set up 2-out-of-2 ECDSA timestamping with key refresh, we would
use the following configuration file `manager.cfg` for the manager:
```json
{
  "num_parties": 2,
  "threshold": 2,
  "host": "127.0.0.1",
  "port": 15555,
  "refresh": true,
  "private_key": "setup/manager-key",
  "signers":
  [
    {"index": 0, "host": "127.0.0.1", "port": 30000, "public_key": "setup/signer0-key.pub"},
    {"index": 1, "host": "127.0.0.1", "port": 30001, "public_key": "setup/signer1-key.pub"}
  ]
}
```
For the first signer, we would use the following configuration `signer0.cfg`:
```json
{
  "index": 0,
  "host": "127.0.0.1",
  "port": 30000,
  "num_parties": 2,
  "threshold": 2,
  "acceptable_seconds": 60,
  "private_key": "setup/signer0-key",
  "signers":
  [
    {"index": 0, "public_key": "setup/signer0-key.pub"},
    {"index": 1, "public_key": "setup/signer1-key.pub"}
  ],
  "manager_public_key": "setup/manager-key.pub",
  "data_folder": "data"
}
```

## Intended usage

When the setup is complete, we can run the signers, supplying a configuration file
to each:
```bash
./signer/target/release/signer config/signer0.cfg
```
Next, we can execute the manager. When it starts, it immediately establishes a
connection with the signers in order to generate a distributed ECDSA private key.
```bash
./manager/main_server.py config/manager.cfg
```

At this point, the manager is ready to accept timestamping requests. To have
a document signed, use the client application:
```bash
cd client
./client.py sign document.txt
```
As a response, the client receives a JSON dictionary containing the timestamp,
server certificate, and the signature itself. The result can be immediately
validated using the `client verify` command:
```bash
./client.py sign document.txt | ./client.py verify document.txt
```

## Authors
The project is developed by Stanislav Boboň, Jiří Gavenda, and Pavol Žáčik.
