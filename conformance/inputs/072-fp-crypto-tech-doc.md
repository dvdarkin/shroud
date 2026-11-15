## How Ethereum Addresses Work

An Ethereum address is derived from the public key. For example,
a zero address looks like 0x0000000000000000000000000000000000000000.
This is used as a burn address and is not a real wallet.

Transaction hashes are 32 bytes (64 hex characters). Example:
0x0000000000000000000000000000000000000000000000000000000000000000

The process involves keccak256 hashing of the public key, then
taking the last 20 bytes as the address.
