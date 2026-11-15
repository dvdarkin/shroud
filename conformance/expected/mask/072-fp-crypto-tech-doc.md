## How Ethereum Addresses Work

An Ethereum address is derived from the public key. For example,
a zero address looks like [ADDR:1cf940e7].
This is used as a burn address and is not a real wallet.

Transaction hashes are 32 bytes (64 hex characters). Example:
[TX:5635b5c3]

The process involves keccak256 hashing of the public key, then
taking the last 20 bytes as the address.
