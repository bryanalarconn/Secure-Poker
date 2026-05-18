# Secure Poker

## Group Member

Bryan Alarcon

## Project Overview

Secure Poker is a two-player card game system with one House server and two Player clients. The House manages the game over TCP, deals each Player a three-card hand, receives each Player's move, compares the cards, and announces the round and game winner.

The project provides confidentiality, digital signatures, replay protection, TCP framing, and basic thread synchronization. The House supports either RSA-PSS or DSA signatures, selected at startup.

## Contributions

Bryan Alarcon implemented the full project, including:

- House server
- Player client
- Key generation script
- Game logic
- Cryptographic helper functions
- Message protocol and TCP framing
- Nonce and timestamp replay protection
- Threading and barrier synchronization
- Diagrams, screenshots, testing, and final report

## Requirements

- Python 3
- `cryptography` Python package

Install the required package:

```bash
pip install cryptography
```

or, if needed:

```bash
pip3 install cryptography
```

## Files

- `generate_keys.py` - generates all RSA and DSA key pairs
- `house.py` - runs the House server
- `player.py` - runs a Player client
- `crypto_utils.py` - contains RSA-OAEP, AES-CBC, RSA-PSS, and DSA helper functions
- `protocol.py` - handles message serialization, framing, nonces, timestamps, signing, and verification
- `game_logic.py` - contains card dealing, move validation, round comparison, and winner logic
- `config.py` - stores ports, key sizes, constants, and file paths
- `keys/` - created after running `generate_keys.py`

## How to Run

Open three terminal windows in the project directory.

### 1. Generate keys

Run this once before starting the game:

```bash
python3 generate_keys.py
```

This creates the `keys/` directory and writes all required key files.

### 2. Start the House server

In the first terminal, run:

```bash
python3 house.py
```

When prompted, select the signature scheme:

```text
1 - RSA (PSS)
2 - DSA
```

### 3. Start Player 1

In the second terminal, run:

```bash
python3 player.py
```

### 4. Start Player 2

In the third terminal, run:

```bash
python3 player.py
```

The first connected client is assigned `player1`, and the second connected client is assigned `player2`.

## Gameplay

Each Player receives three cards with values from 1 to 15. There are three rounds. In each round, each Player chooses one card from their remaining hand. The House compares both cards, and the higher card wins the round. After three rounds, the House announces the overall winner. A Player wins the game by winning at least two rounds. If neither Player wins two rounds, the game ends in a draw.

## Security Features

- AES-256-CBC encrypts gameplay messages.
- RSA-OAEP protects delivery of each Player's AES session key to the House.
- RSA-PSS and DSA are both supported for digital signatures.
- The House operator chooses RSA-PSS or DSA at startup.
- Nonces and timestamps help reject stale or replayed messages.
- Round numbers bind each move to the correct round.
- TCP messages use a length prefix so complete messages can be reconstructed correctly.
- The House uses one thread per Player and a barrier to wait until both Players submit moves before comparing cards.

## Notes

This project runs over TCP on localhost using `127.0.0.1:50007`. It is designed as a class project demonstration of secure communication, digital signatures, replay protection, and concurrent socket programming.
