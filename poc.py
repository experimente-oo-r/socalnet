#!/usr/bin/env python3
"""
Minimal PoC — wallet-identity social network, no coin.

  Wallet  -> Ed25519 (signing / identity) + X25519 (encryption) keypair
  Vault   -> per-user AES-GCM encrypted local store, key derived from the wallet
  Join    -> a new node needs signed referrals from 3 distinct existing members
  Posts   -> signed, max 50 words, gossiped; invalid messages die at the first hop
  Shares  -> end-to-end encrypted, sent directly peer to peer
  Revoke  -> 3 members can remove a node; its vouchers lose invite rights;
             anyone left with < 3 valid referrals is removed too (cascade)

Transport: asyncio TCP + flood gossip, isolated in the Node class (_send /
_reader_loop / connect). Swap for libp2p (gossipsub + DHT) in a real build.

Run:  python3 poc.py          (needs only the `cryptography` package)
"""
import asyncio, base64, hashlib, json, os, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

REFERRALS_REQUIRED = 3
MAX_WORDS = 50
MAX_INVITES = 3          # referrals each member may give
VAULT_DIR = "vaults"
NAMES: dict = {}         # demo-only display names for wallet ids

# ---------------------------------------------------------------- helpers
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":")).encode()
short = lambda i: i[:8] if i else "?"
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def hkdf(material: bytes, info: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, info).derive(material)


def verify(pub_b64: str, obj, sig_b64: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64d(pub_b64)).verify(b64d(sig_b64), canon(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- wallet
class Wallet:
    def __init__(self):
        self.sign_sk = Ed25519PrivateKey.generate()
        self.enc_sk = X25519PrivateKey.generate()
        self.id = b64e(self.sign_sk.public_key().public_bytes(**RAW))
        self.enc_pub = b64e(self.enc_sk.public_key().public_bytes(**RAW))

    def sign(self, obj) -> str:
        return b64e(self.sign_sk.sign(canon(obj)))

    def vault_key(self) -> bytes:
        raw = self.sign_sk.private_bytes(serialization.Encoding.Raw,
                                         serialization.PrivateFormat.Raw,
                                         serialization.NoEncryption())
        return hkdf(raw, b"vault")


def seal(recipient_enc_pub: str, plaintext: bytes) -> dict:
    """Encrypt for one recipient: ephemeral X25519 ECDH -> HKDF -> AES-GCM."""
    eph = X25519PrivateKey.generate()
    key = hkdf(eph.exchange(X25519PublicKey.from_public_bytes(b64d(recipient_enc_pub))), b"share")
    nonce = os.urandom(12)
    return {"eph": b64e(eph.public_key().public_bytes(**RAW)), "nonce": b64e(nonce),
            "ct": b64e(AESGCM(key).encrypt(nonce, plaintext, None))}


def unseal(enc_sk: X25519PrivateKey, box: dict) -> bytes:
    key = hkdf(enc_sk.exchange(X25519PublicKey.from_public_bytes(b64d(box["eph"]))), b"share")
    return AESGCM(key).decrypt(b64d(box["nonce"]), b64d(box["ct"]), None)


# ---------------------------------------------------------------- vault
class Vault:
    """Encrypted-at-rest personal data store. Only the wallet owner can open it."""

    def __init__(self, path: str, key: bytes):
        self.path, self.aes = path, AESGCM(key)
        self.data = {"posts": [], "shares": []}
        if os.path.exists(path):
            blob = open(path, "rb").read()
            self.data = json.loads(self.aes.decrypt(blob[:12], blob[12:], None))

    def add(self, kind: str, item):
        self.data[kind].append(item)
        nonce = os.urandom(12)
        with open(self.path, "wb") as f:
            f.write(nonce + self.aes.encrypt(nonce, canon(self.data), None))


# ---------------------------------------------------------------- ledger
class Ledger:
    """Membership state. Every node keeps its own copy, built only from
    signed events it has verified itself (founders = public genesis config)."""

    def __init__(self, founders: dict):
        self.members = {fid: {"enc": enc, "vouchers": [], "invites": 0}
                        for fid, enc in founders.items()}
        self.revoked: set = set()
        self.events: list = []        # accepted events, replayable for sync

    def is_member(self, i):
        return i in self.members

    # -- join
    def check_join(self, ev):
        b = ev["body"]
        new = b["id"]
        if not verify(new, b, ev["sig"]):
            return "bad signature"
        if new in self.members or new in self.revoked:
            return "already member or revoked"
        vouchers = {v["by"] for v in ev["vouches"]}
        if len(vouchers) < REFERRALS_REQUIRED:
            return f"need {REFERRALS_REQUIRED} distinct referrals, got {len(vouchers)}"
        for v in ev["vouches"]:
            if not self.is_member(v["by"]):
                return f"referral from non-member {short(v['by'])}"
            if not verify(v["by"], {"vouch": new}, v["sig"]):
                return f"forged referral from {short(v['by'])}"
            if self.members[v["by"]]["invites"] >= MAX_INVITES:
                return f"{short(v['by'])} has no invites left"
        return None

    def apply_join(self, ev):
        b = ev["body"]
        vouchers = sorted({v["by"] for v in ev["vouches"]})
        for v in vouchers:
            self.members[v]["invites"] += 1
        self.members[b["id"]] = {"enc": b["enc"], "vouchers": vouchers, "invites": 0}
        self.events.append(ev)

    # -- revoke
    def check_revoke(self, ev):
        b = ev["body"]
        if not self.is_member(b["target"]):
            return "target not a member"
        signers = {s["by"] for s in ev["sigs"]
                   if s["by"] != b["target"] and self.is_member(s["by"]) and verify(s["by"], b, s["sig"])}
        if len(signers) < REFERRALS_REQUIRED:
            return f"need {REFERRALS_REQUIRED} member signatures, got {len(signers)}"
        return None

    def apply_revoke(self, ev):
        target = ev["body"]["target"]
        removed = [target]
        for v in self.members[target]["vouchers"]:      # accountability
            if v in self.members:
                self.members[v]["invites"] = MAX_INVITES
        del self.members[target]
        self.revoked.add(target)
        changed = True                                   # cascade
        while changed:
            changed = False
            for mid, m in list(self.members.items()):
                if m["vouchers"] and sum(v in self.members for v in m["vouchers"]) < REFERRALS_REQUIRED:
                    del self.members[mid]; self.revoked.add(mid); removed.append(mid); changed = True
        self.events.append(ev)
        return removed


# ---------------------------------------------------------------- node
class Node:
    def __init__(self, name, port, wallet, founders):
        self.name, self.port, self.w = name, port, wallet
        self.ledger = Ledger(founders)
        self.peers = {}               # writer -> peer wallet id
        self.hello_sent = set()
        self.seen = set()             # gossip message ids
        self.pending = {}             # request id -> future
        self.names = NAMES            # id -> display name (demo only, shared)
        os.makedirs(VAULT_DIR, exist_ok=True)
        self.vault = Vault(f"{VAULT_DIR}/{name}.vault", wallet.vault_key())

    def log(self, msg):
        print(f"  [{self.name:>7}] {msg}")

    def nm(self, i):
        return self.names.get(i, short(i))

    # ---- transport (replace with libp2p) ----
    async def start(self):
        self.server = await asyncio.start_server(self._reader_loop, "127.0.0.1", self.port)

    async def connect(self, port):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        asyncio.create_task(self._reader_loop(r, w))
        await self._hello(w)

    async def _hello(self, w):
        self.hello_sent.add(w)
        await self._send(w, {"t": "HELLO", "id": self.w.id, "name": self.name})

    async def _send(self, w, msg):
        w.write((json.dumps(msg) + "\n").encode())
        await w.drain()

    async def _reader_loop(self, r, w):
        self.peers.setdefault(w, None)
        try:
            while line := await r.readline():
                await self._on_msg(json.loads(line), w)
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self.peers.pop(w, None)

    async def request(self, w, msg):
        rid = os.urandom(8).hex()
        fut = asyncio.get_running_loop().create_future()
        self.pending[rid] = fut
        await self._send(w, {**msg, "rid": rid})
        return await asyncio.wait_for(fut, 3)

    def writer_for(self, peer_id):
        return next(w for w, i in self.peers.items() if i == peer_id)

    # ---- message handling ----
    async def _on_msg(self, m, w):
        t = m["t"]
        if t == "HELLO":
            self.peers[w] = m["id"]; self.names[m["id"]] = m["name"]
            if w not in self.hello_sent:
                await self._hello(w)
        elif t == "RESP":
            self.pending.pop(m["rid"]).set_result(m["data"])
        elif t == "VOUCH_REQ":
            ok = self.ledger.is_member(self.w.id)
            data = {"by": self.w.id, "sig": self.w.sign({"vouch": m["id"]})} if ok else None
            await self._send(w, {"t": "RESP", "rid": m["rid"], "data": data})
        elif t == "SYNC_REQ":
            await self._send(w, {"t": "RESP", "rid": m["rid"], "data": self.ledger.events})
        elif t == "GOSSIP":
            await self._on_gossip(m["kind"], m["payload"], src=w)
        elif t == "SHARE":
            self._on_share(m["payload"])

    async def _on_gossip(self, kind, p, src=None, force=False):
        mid = hashlib.sha256(canon([kind, p])).hexdigest()
        if mid in self.seen:
            return
        self.seen.add(mid)
        err = None if force else self._validate_and_apply(kind, p)
        if err:
            self.log(f"REJECTED {kind}: {err}  (not forwarded)")
            return
        for w in list(self.peers):          # flood to everyone except the source
            if w is not src:
                await self._send(w, {"t": "GOSSIP", "kind": kind, "payload": p})

    def _validate_and_apply(self, kind, p):
        if kind == "JOIN":
            err = self.ledger.check_join(p)
            if not err:
                self.ledger.apply_join(p)
                self.log(f"accepted JOIN of {self.nm(p['body']['id'])} "
                         f"(referred by {', '.join(self.nm(v['by']) for v in p['vouches'])})")
            return err
        if kind == "REVOKE":
            err = self.ledger.check_revoke(p)
            if not err:
                gone = self.ledger.apply_revoke(p)
                self.log(f"accepted REVOKE -> removed {[self.nm(g) for g in gone]}")
            return err
        if kind == "POST":
            b = p["body"]
            if not self.ledger.is_member(b["author"]):
                return f"author {self.nm(b['author'])} is not a member"
            if not verify(b["author"], b, p["sig"]):
                return "bad signature"
            if len(b["text"].split()) > MAX_WORDS:
                return f"post is {len(b['text'].split())} words (max {MAX_WORDS})"
            self.vault.add("posts", b)
            self.log(f"feed <- {self.nm(b['author'])}: \"{b['text'][:50]}\"")
            return None
        return "unknown kind"

    def _on_share(self, env):
        b = env["body"]
        if not self.ledger.is_member(b["from"]) or not verify(b["from"], b, env["sig"]):
            self.log("REJECTED share: unknown or forged sender"); return
        text = unseal(self.w.enc_sk, b["box"]).decode()
        self.vault.add("shares", {"from": b["from"], "text": text})
        self.log(f"decrypted private share from {self.nm(b['from'])}: \"{text}\"")

    # ---- user actions ----
    async def ask_referral(self, peer_id):
        return await self.request(self.writer_for(peer_id), {"t": "VOUCH_REQ", "id": self.w.id})

    async def join(self, vouches, force=False):
        body = {"type": "JOIN", "id": self.w.id, "enc": self.w.enc_pub, "ts": time.time()}
        await self._on_gossip("JOIN", {"body": body, "vouches": vouches, "sig": self.w.sign(body)},
                              force=force)

    async def sync(self, peer_id):
        """Rebuild the ledger by re-verifying every event from genesis."""
        for ev in await self.request(self.writer_for(peer_id), {"t": "SYNC_REQ"}):
            if "vouches" in ev and not self.ledger.check_join(ev):
                self.ledger.apply_join(ev)
            elif "sigs" in ev and not self.ledger.check_revoke(ev):
                self.ledger.apply_revoke(ev)
        self.log(f"synced ledger: {len(self.ledger.members)} members, all signatures verified")

    async def post(self, text, force=False):
        body = {"type": "POST", "author": self.w.id, "text": text, "ts": time.time()}
        p = {"body": body, "sig": self.w.sign(body)}
        if not force:
            err = self._validate_and_apply("POST", p)
            if err:
                self.log(f"local client refused post: {err}"); return
        await self._on_gossip("POST", p, force=True)

    async def share(self, peer_id, text):
        body = {"from": self.w.id, "to": peer_id, "ts": time.time(),
                "box": seal(self.ledger.members[peer_id]["enc"], text.encode())}
        await self._send(self.writer_for(peer_id), {"t": "SHARE", "payload": {"body": body, "sig": self.w.sign(body)}})


# ---------------------------------------------------------------- demo
def step(title):
    print(f"\n=== {title}")


async def settle():
    await asyncio.sleep(0.3)


async def main():
    for f in os.listdir(VAULT_DIR) if os.path.isdir(VAULT_DIR) else []:
        os.remove(os.path.join(VAULT_DIR, f))

    # Genesis: 4 founders, published as the network's public config.
    fw = {n: Wallet() for n in ["Alice", "Bob", "Carol", "Dave"]}
    founders = {w.id: w.enc_pub for w in fw.values()}
    nodes = {n: Node(n, 9001 + i, w, founders) for i, (n, w) in enumerate(fw.items())}
    for n in ["Eve", "Frank", "Mallory"]:
        nodes[n] = Node(n, 9001 + len(nodes), Wallet(), founders)
    for nd in nodes.values():
        NAMES[nd.w.id] = nd.name
        await nd.start()
    A, B, C, D, E, F, M = (nodes[n] for n in ["Alice", "Bob", "Carol", "Dave", "Eve", "Frank", "Mallory"])

    step("1. Founders form a ring: Alice-Bob-Carol-Dave-Alice")
    await A.connect(B.port); await B.connect(C.port); await C.connect(D.port); await D.connect(A.port)
    await settle()
    print("  4 founder nodes online")

    step("2. Eve gets only 2 referrals (Alice, Bob) and tries to join anyway")
    await E.connect(A.port); await E.connect(B.port); await settle()
    vouches = [await E.ask_referral(A.w.id), await E.ask_referral(B.w.id)]
    await E.join(vouches, force=True); await settle()

    step("3. Frank gets 3 referrals (Alice, Bob, Carol) and joins")
    await F.connect(A.port); await F.connect(B.port); await F.connect(C.port); await settle()
    vouches = [await F.ask_referral(x.w.id) for x in (A, B, C)]
    await F.join(vouches); await settle()
    await F.sync(A.w.id)
    print("  (Dave got the join via gossip; Frank is not connected to Dave)")

    step("4. Frank posts (50-word limit, signed, gossiped)")
    await F.post("Hello network! Glad to be in, thanks for the referrals."); await settle()

    step("5. Mallory (not a member) connects to Carol and posts")
    await M.connect(C.port); await settle()
    await M.sync(C.w.id)
    await M.post("Buy cheap followers now!!!", force=True); await settle()

    step("6. Alice uses a modified client to push a 60-word post")
    await A.post(" ".join(["word"] * 60), force=True); await settle()

    step("7. Bob sends Frank an end-to-end encrypted share (direct P2P)")
    await B.share(F.w.id, "Meet at 6, code word is mango"); await settle()
    box = seal(F.ledger.members[F.w.id]["enc"], b"secret")
    try:
        unseal(C.w.enc_sk, box)
    except InvalidTag:
        print("  [  Carol] cannot decrypt a box sealed for Frank -> InvalidTag")

    step("8. Frank spams; Alice, Bob and Dave sign a revocation")
    body = {"type": "REVOKE", "target": F.w.id, "reason": "spam", "ts": time.time()}
    rev = {"body": body, "sigs": [{"by": x.w.id, "sig": x.w.sign(body)} for x in (A, B, D)]}
    await A._on_gossip("REVOKE", rev); await settle()
    inv = A.ledger.members[A.w.id]["invites"]
    print(f"  Alice/Bob/Carol referred Frank -> invites now {inv}/{MAX_INVITES} (lost referral rights)")
    await F.post("Still here?", force=True); await settle()

    step("9. Vaults are encrypted at rest")
    raw = open(f"{VAULT_DIR}/Frank.vault", "rb").read()
    print(f"  Frank.vault on disk: {len(raw)} bytes, contains 'mango'? {b'mango' in raw}")
    reopened = Vault(f"{VAULT_DIR}/Frank.vault", F.w.vault_key())
    print(f"  reopened with Frank's wallet -> shares: {[s['text'] for s in reopened.data['shares']]}")
    try:
        Vault(f"{VAULT_DIR}/Frank.vault", Wallet().vault_key())
    except InvalidTag:
        print("  opened with any other wallet -> InvalidTag")

    for nd in nodes.values():
        nd.server.close()
    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())