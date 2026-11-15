# SocalNet — Philosophy & Theory

A proof-of-concept for wallet-identity social networking without cryptocurrency.

**License**: MIT

## Core Principles

### Identity = Cryptographic Keys
No usernames, no passwords, no email. Your Ed25519 keypair **is** your identity. Lose your keys, lose your account—just like a physical wallet.

### Trust Through Social Proof
To join, you need **3 referrals** from existing members. No central authority decides who's in—the community vouches for newcomers through a web-of-trust model.

### Accountability via Cascade
When someone gets removed (requires 3 member signatures), their vouchers lose invite rights. Anyone left with fewer than 3 valid referrals is automatically removed too. This creates **skin-in-the-game** for those who invite others.

### No Coin, No Token
This isn't blockchain. No mining, staking, or proof-of-work. Just cryptographic signatures proving "I said this" and encrypted channels proving "only you can read this."

## Why This Approach?

**Sybil Resistance Without Mining**  
Creating fake accounts requires socially engineering multiple real members. The revocation cascade means bad actors risk their inviters' reputation.

**Privacy Without Servers**  
End-to-end encryption (X25519 ECDH) for private shares. Your vault is encrypted at rest with a key derived from your signing key—filesystem access alone reveals nothing.

**Decentralized Verification**  
Every node independently verifies every signature. Invalid messages die at the first hop. You don't "trust the network"—you verify cryptographic proofs yourself.

## How It Works

1. **Wallet** → Ed25519 (signing/identity) + X25519 (encryption)
2. **Join** → Collect 3 signed referrals, gossip the join event
3. **Post** → Sign your message (≤50 words), nodes verify and forward
4. **Share** → E2E encrypted, sent peer-to-peer
5. **Revoke** → 3 members sign removal, triggers cascade check
6. **Vault** → AES-GCM encrypted local storage, key derived from wallet

## Limitations (This is a PoC)

- **Transport**: Uses naive TCP flood gossip → needs libp2p (gossipsub + DHT)
- **Bootstrap**: Founders hardcoded → needs discovery mechanism
- **Storage**: In-memory ledger → needs Merkle trees + snapshots
- **Fixed rules**: 3 referrals, 3 revokers, 50 words → should be governance parameters
- **No reputation decay**: Early members have permanent power

## Weaknesses

**Nodes can disagree on membership.**  
Without a shared order of events, nodes can end up with different member lists. Fixing it needs some form of consensus, which pulls the design back toward blockchain-style coordination.

**Collusion.**  
A small group can let in fake accounts or remove honest members. Referrals from people you trust only resist fake accounts as long as the people giving them are honest.

**Accountability works against privacy.**  
Punishing bad referrers requires knowing who they are, which exposes the social graph. Hiding the graph weakens accountability. You can choose a balance, but you can't get both fully.

**Penalties and invite limits work against growth.**  
Invite supply only shrinks, and members who refer someone take a risk. The network becomes slow and wary of newcomers, and over time it gets harder to join.

**Your key is your identity.**  
Lose the key and the account, vault and reputation are gone for good. If it's stolen, someone else becomes you. Recovery means trusting other people, such as recovery peers, so trust comes back in somewhere.

## Running

```bash
pip install cryptography
python3 poc.py
```

The demo simulates 7 nodes (Alice, Bob, Carol, Dave, Eve, Frank, Mallory) on localhost, running through join attempts, posts, encryption, and revocation scenarios.

## Inspirations

- **PGP Web of Trust** — decentralized identity through cross-signing
- **Freenet/Tor** — cryptographic identity, no central directory
- **Scuttlebutt** — gossip protocols, append-only logs
- **Signal Protocol** — E2E encryption, forward secrecy
# socalnet
