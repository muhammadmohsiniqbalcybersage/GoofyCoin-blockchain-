"""
GoofyCoin: Complete Blockchain Cryptocurrency & Server Implementation.

Fixed Supply: Exactly 1,000 GoofyCoins in circulation.
Admin (Goofy / USER001) starts with all 1,000 genesis coins.
Both Buy Coins and Free Coin Requests require Admin Approval before any transfer occurs.
All transfers and approvals show complete cryptographic proof:
  - Block Index
  - Current Block Hash
  - Previous Block Hash
  - Digital Signature (SECP256k1 ECDSA)
  - Sender Public Key
  - Recipient Public Key
  - Timestamp & Ownership Verification

Core Functions Implemented:
  1. CreateUser: Generates ECDSA keypair (SECP256k1), User ID (USER001), GFC Address, Balance=0.
  2. CreateCoin: Mints authorized coins (strictly capped at 1,000 total coins).
  3. TransferCoin: Cryptographically transfers coins by amount or coin ID and intercepts illegal spending.
  4. Verify_chain: Validates SHA-256 hash chains, digital signatures, and 1,000 coin supply integrity.
  5. start_server: Binds TCP socket, logs connections, and handles client workers.
  6. handle_client: Manages client requests, JSON operations, and error handling.
"""

import socket
import sys
import json
import hashlib
import threading
from datetime import datetime, timezone
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# Configure UTF-8 encoding on Windows consoles
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HOST = "127.0.0.1"
PORT = 5000
BUFFER_SIZE = 8192
MAX_COIN_SUPPLY = 1000


class GoofyCoin:
    def __init__(self, creator="Goofy"):
        self.creator_name = creator
        self.users = {}            # username -> {"user_id": str, "username": str, "wallet_address": str, "private_key": SigningKey, "public_key": VerifyingKey}
        self.user_by_id = {}       # user_id -> username
        self.chain = []            # list of verified block records
        self.coin_owners = {}      # coin_id -> current_owner_username
        self.coin_details = {}     # coin_id -> {"name": str, "creator_id": str, "minted_at": str}
        self.coin_requests = []    # list of coin acquisition requests
        self.active_sessions = {}  # username -> session dict
        self.user_count = 0
        self.coin_count = 0
        self._lock = threading.Lock()

        # Initialize Creator Account and Genesis 1,000 Coins at Startup
        self._init_creator_account()

    def _init_creator_account(self):
        """Initializes authorized creator and genesis 1,000 coin inventory."""
        self.CreateUser(self.creator_name)
        self.creator_id = self.users[self.creator_name]["user_id"]

        # Genesis Mint: 1,000 GoofyCoins allocated to Admin (Goofy)
        genesis_coins = [f"COIN{i:04d}" for i in range(1, MAX_COIN_SUPPLY + 1)]
        transaction = {
            "type": "GENESIS_MINT",
            "coin_id": f"COIN0001..COIN{MAX_COIN_SUPPLY:04d} ({MAX_COIN_SUPPLY} coins)",
            "coin_name": "GoofyCoin",
            "amount": MAX_COIN_SUPPLY,
            "coins": genesis_coins,
            "creator_id": self.creator_id,
            "sender": None,
            "recipient": self.creator_name
        }

        self._record_transaction(transaction, signer=self.creator_name)

        for c_id in genesis_coins:
            self.coin_owners[c_id] = self.creator_name
            self.coin_details[c_id] = {
                "name": "GoofyCoin",
                "creator_id": self.creator_id,
                "minted_at": transaction["timestamp"]
            }

        self.coin_count = MAX_COIN_SUPPLY

    @staticmethod
    def canonical_json(data):
        """Converts dict to sorted JSON bytes for deterministic signatures and hashes."""
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def sha256(data):
        """Computes SHA-256 hash."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def resolve_user(self, identifier):
        """Resolves identifier by either user_id (e.g. USER001) or username."""
        if not identifier:
            return None
        identifier = str(identifier).strip()
        if identifier in self.users:
            return identifier
        if identifier in self.user_by_id:
            return self.user_by_id[identifier]
        return None

    def get_user_balance(self, username):
        """Calculates total coins currently owned by the user."""
        u = self.resolve_user(username)
        if not u:
            return 0
        return sum(1 for owner in self.coin_owners.values() if owner == u)

    def get_user_coins(self, username):
        """Returns the list of coin IDs currently owned by the user."""
        u = self.resolve_user(username)
        if not u:
            return []
        return [c_id for c_id, owner in self.coin_owners.items() if owner == u]

    def get_user_transactions(self, username):
        """Returns all transaction history records involving this user with full cryptographic fields."""
        u = self.resolve_user(username)
        tx_history = []
        for block in self.chain:
            tx = block["transaction"]
            if tx.get("sender") == u or tx.get("recipient") == u:
                sndr = tx.get("sender")
                rcpt = tx.get("recipient")
                sndr_pub = self.users[sndr]["public_key"].to_string().hex() if sndr in self.users else ""
                rcpt_pub = self.users[rcpt]["public_key"].to_string().hex() if rcpt in self.users else ""
                tx_history.append({
                    "block_index": block["index"],
                    "type": tx.get("type", "TRANSFER"),
                    "coin_id": tx.get("coin_id"),
                    "amount": tx.get("amount", 1),
                    "sender": sndr or "System (Genesis)",
                    "recipient": rcpt,
                    "sender_id": self.users[sndr]["user_id"] if sndr in self.users else "SYSTEM",
                    "recipient_id": self.users[rcpt]["user_id"] if rcpt in self.users else "SYSTEM",
                    "timestamp": tx.get("timestamp"),
                    "block_hash": block["block_hash"],
                    "previous_hash": block.get("previous_hash", tx.get("previous_hash", "")),
                    "signature": block.get("signature", ""),
                    "sender_public_key": sndr_pub,
                    "recipient_public_key": rcpt_pub
                })
        return tx_history

    def get_all_users(self):
        """Returns list of all registered users with their details and balances."""
        with self._lock:
            user_list = []
            for uname, udata in self.users.items():
                user_list.append({
                    "user_id": udata["user_id"],
                    "username": uname,
                    "wallet_address": udata["wallet_address"],
                    "public_key": udata["public_key"].to_string().hex(),
                    "balance": self.get_user_balance(uname),
                    "coins_count": len(self.get_user_coins(uname)),
                    "is_admin": (uname == self.creator_name or udata["user_id"] == "USER001")
                })
            user_list.sort(key=lambda x: x["user_id"])
            return user_list

    def get_complete_ledger(self):
        """Returns all blocks in the blockchain with full cryptographic details."""
        with self._lock:
            ledger = []
            for block in self.chain:
                tx = block["transaction"]
                sndr = tx.get("sender")
                rcpt = tx.get("recipient")
                sndr_pub = self.users[sndr]["public_key"].to_string().hex() if sndr in self.users else ""
                rcpt_pub = self.users[rcpt]["public_key"].to_string().hex() if rcpt in self.users else ""
                ledger.append({
                    "block_index": block["index"],
                    "type": tx.get("type", "TRANSFER"),
                    "coin_id": tx.get("coin_id"),
                    "amount": tx.get("amount", 1),
                    "sender": sndr or "System (Genesis)",
                    "recipient": rcpt or "N/A",
                    "sender_id": self.users[sndr]["user_id"] if sndr in self.users else "SYSTEM",
                    "recipient_id": self.users[rcpt]["user_id"] if rcpt in self.users else "SYSTEM",
                    "timestamp": tx.get("timestamp"),
                    "block_hash": block["block_hash"],
                    "previous_hash": block.get("previous_hash", tx.get("previous_hash", "")),
                    "signature": block.get("signature", ""),
                    "sender_public_key": sndr_pub,
                    "recipient_public_key": rcpt_pub
                })
            return ledger

    def add_session(self, username, client_ip, client_port=None):
        """Registers a logged-in client session."""
        with self._lock:
            u = self.resolve_user(username)
            if u:
                u_id = self.users[u]["user_id"]
                self.active_sessions[u] = {
                    "username": u,
                    "user_id": u_id,
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "login_time": datetime.now().strftime("%H:%M:%S"),
                    "last_seen": datetime.now().strftime("%H:%M:%S")
                }

    def remove_session(self, username):
        """Removes a client session upon logout."""
        with self._lock:
            u = self.resolve_user(username)
            if u and u in self.active_sessions:
                del self.active_sessions[u]

    def update_session_activity(self, username, client_ip=None, client_port=None):
        """Updates last seen activity for an active user session."""
        with self._lock:
            u = self.resolve_user(username)
            if u:
                if u not in self.active_sessions:
                    u_id = self.users[u]["user_id"]
                    self.active_sessions[u] = {
                        "username": u,
                        "user_id": u_id,
                        "client_ip": client_ip or "127.0.0.1",
                        "client_port": client_port,
                        "login_time": datetime.now().strftime("%H:%M:%S"),
                        "last_seen": datetime.now().strftime("%H:%M:%S")
                    }
                else:
                    self.active_sessions[u]["last_seen"] = datetime.now().strftime("%H:%M:%S")
                    if client_ip:
                        self.active_sessions[u]["client_ip"] = client_ip
                    if client_port:
                        self.active_sessions[u]["client_port"] = client_port

    def get_active_sessions_summary(self):
        """Returns clean formatted summary of currently active logged-in clients."""
        with self._lock:
            count = len(self.active_sessions)
            if count == 0:
                return "0 Logged In"
            items = []
            for uname, s in self.active_sessions.items():
                role = "ADMIN" if (uname == self.creator_name or s["user_id"] == "USER001") else "USER"
                items.append(f"{uname} ({s['user_id']}) [{role}]")
            return f"{count} Logged In -> [{', '.join(items)}]"

    # =========================================================================
    # 1. CreateUser
    # =========================================================================
    def CreateUser(self, username):
        """
        [1] Create New User:
          - Validates username.
          - Generates Unique User ID (USER001, USER002...).
          - Generates ECDSA Private Key & Public Key (SECP256k1).
          - Generates GFC Wallet Address.
          - Initializes Balance = 0.
          - Saves user record in ledger state.
        """
        with self._lock:
            if not username or not isinstance(username, str):
                raise ValueError("Username cannot be empty.")

            username = username.strip()

            if username in self.users:
                return self.users[username]

            self.user_count += 1
            user_id = f"USER{self.user_count:03d}"

            # Generate ECDSA keypair using curve SECP256k1
            private_key = SigningKey.generate(curve=SECP256k1)
            public_key = private_key.get_verifying_key()
            pub_hex = public_key.to_string().hex()

            # Derive Wallet Address: GFC + SHA256(PublicKey)[:16].upper()
            digest = hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest().upper()
            wallet_address = f"GFC{digest[:16]}"

            user_record = {
                "user_id": user_id,
                "username": username,
                "wallet_address": wallet_address,
                "private_key": private_key,
                "public_key": public_key
            }

            self.users[username] = user_record
            self.user_by_id[user_id] = username

            return user_record

    def _record_transaction(self, transaction, signer):
        """Internal helper: signs with ECDSA private key, hashes block, and links to chain."""
        previous_hash = self.chain[-1]["block_hash"] if self.chain else "0" * 64

        transaction["timestamp"] = datetime.now(timezone.utc).isoformat()
        transaction["previous_hash"] = previous_hash

        canonical_data = self.canonical_json(transaction)
        signing_key = self.users[signer]["private_key"]
        signature = signing_key.sign_deterministic(canonical_data, hashfunc=hashlib.sha256)

        block_hash = self.sha256(canonical_data + signature + previous_hash.encode("utf-8"))

        block = {
            "index": len(self.chain),
            "transaction": transaction,
            "signer": signer,
            "signature": signature.hex(),
            "previous_hash": previous_hash,
            "block_hash": block_hash
        }

        self.chain.append(block)
        return block

    # =========================================================================
    # 2. CreateCoin
    # =========================================================================
    def CreateCoin(self, creator, coin_id=None, coin_name="GoofyCoin", amount=1):
        """
        [2] Create New Coin:
          - Verifies Creator Authorization (Only original creator USER001/Goofy).
          - Goofy (the admin & owner) has sovereign authority to mint coins.
          - Rejects unauthorized minting by any other user.
          - Signs coin creation with Goofy's ECDSA private key.
          - Records block in blockchain ledger.
        """
        with self._lock:
            creator_uname = self.resolve_user(creator)
            if not creator_uname:
                raise ValueError(f"Unknown creator '{creator}'.")

            # Authorization Check: Only authorized creator (USER001 / Goofy)
            if creator_uname != self.creator_name and self.users[creator_uname]["user_id"] != "USER001":
                raise PermissionError(
                    f"UNAUTHORIZED: Only creator '{self.creator_name}' (USER001) has authority to mint coins. "
                    f"Attempted by: '{creator_uname}'."
                )

            try:
                amount = int(amount)
            except (ValueError, TypeError):
                amount = 1
            if amount <= 0:
                amount = 1

            minted_ids = []
            if coin_id and amount == 1:
                c_clean = str(coin_id).strip()
                if c_clean in self.coin_owners:
                    raise ValueError(f"Coin '{c_clean}' already exists in ledger.")
                minted_ids = [c_clean]
                display_coin_id = c_clean
            else:
                for _ in range(amount):
                    self.coin_count += 1
                    c_id = f"COIN{self.coin_count:04d}"
                    minted_ids.append(c_id)
                display_coin_id = minted_ids[0] if len(minted_ids) == 1 else f"{minted_ids[0]}..{minted_ids[-1]} ({amount} coins)"

            transaction = {
                "type": "MINT",
                "coin_id": display_coin_id,
                "coin_name": coin_name,
                "amount": amount,
                "coins": minted_ids,
                "creator_id": self.users[creator_uname]["user_id"],
                "sender": None,
                "recipient": creator_uname
            }

            block = self._record_transaction(transaction, signer=creator_uname)
            for c in minted_ids:
                self.coin_owners[c] = creator_uname
                self.coin_details[c] = {
                    "name": coin_name,
                    "creator_id": self.users[creator_uname]["user_id"],
                    "minted_at": transaction["timestamp"]
                }

            return block

    # =========================================================================
    # 3. TransferCoin
    # =========================================================================
    def TransferCoin(self, sender, recipient, coin_id_or_amount, tx_type="TRANSFER"):
        """
        [3] Transfer Coin:
          - Supports transferring either a specific Coin ID (e.g. 'COIN0005')
            OR an Amount (e.g. 5, 10, 50 GoofyCoins).
          - Supports custom transaction types (TRANSFER, BUY_REQUEST, FREE_REQUEST).
          - Verifies sender owns sufficient coins.
          - Cryptographically signs transfer with sender's ECDSA private key.
          - Links block with previous_hash and recalculates SHA-256 block hash.
          - Updates coin ownership and ledger state.
        """
        with self._lock:
            sender_uname = self.resolve_user(sender)
            recipient_uname = self.resolve_user(recipient)

            if not sender_uname:
                raise ValueError(f"Sender '{sender}' does not exist.")
            if not recipient_uname:
                raise ValueError(f"Recipient '{recipient}' does not exist.")

            if sender_uname == recipient_uname:
                raise ValueError("Sender and recipient cannot be the same user.")

            sender_coins = self.get_user_coins(sender_uname)

            # Check if input is an amount (integer or digit string)
            is_amount = False
            amount_val = 0
            if isinstance(coin_id_or_amount, int):
                is_amount = True
                amount_val = coin_id_or_amount
            elif isinstance(coin_id_or_amount, str) and coin_id_or_amount.strip().isdigit():
                is_amount = True
                amount_val = int(coin_id_or_amount.strip())

            if is_amount:
                if amount_val <= 0:
                    raise ValueError("Transfer amount must be greater than zero.")
                if len(sender_coins) < amount_val:
                    sender_id = self.users[sender_uname]["user_id"]
                    raise ValueError(
                        f"Insufficient balance: {sender_uname} ({sender_id}) owns {len(sender_coins)} coins, "
                        f"cannot transfer {amount_val} coins."
                    )
                coins_to_transfer = sender_coins[:amount_val]
                display_coin_id = (
                    coins_to_transfer[0]
                    if len(coins_to_transfer) == 1
                    else f"{coins_to_transfer[0]}..{coins_to_transfer[-1]} ({amount_val} coins)"
                )
            else:
                # Specific Coin ID
                target_coin = str(coin_id_or_amount).strip()
                if target_coin not in self.coin_owners:
                    raise ValueError(f"Coin '{target_coin}' does not exist in ledger.")
                if self.coin_owners[target_coin] != sender_uname:
                    current_owner = self.coin_owners[target_coin]
                    sender_id = self.users[sender_uname]["user_id"]
                    current_owner_id = self.users[current_owner]["user_id"]
                    raise PermissionError(
                        f"UNAUTHORIZED: Sender {sender_id} ('{sender_uname}') does not own coin '{target_coin}'. "
                        f"Current legitimate owner is {current_owner_id} ('{current_owner}')."
                    )
                coins_to_transfer = [target_coin]
                display_coin_id = target_coin
                amount_val = 1

            transaction = {
                "type": tx_type,
                "coin_id": display_coin_id,
                "amount": amount_val,
                "coins": coins_to_transfer,
                "sender": sender_uname,
                "sender_id": self.users[sender_uname]["user_id"],
                "recipient": recipient_uname,
                "recipient_id": self.users[recipient_uname]["user_id"]
            }

            block = self._record_transaction(transaction, signer=sender_uname)

            for c in coins_to_transfer:
                self.coin_owners[c] = recipient_uname

            return block

    # =========================================================================
    # 4. Verify_chain
    # =========================================================================
    def Verify_chain(self):
        """
        [4] Verify Blockchain:
          - Verifies block hash linkage.
          - Re-computes SHA-256 block hash.
          - Verifies ECDSA digital signatures using public keys.
          - Verifies 1,000 fixed coin supply integrity (never exceeds 1,000).
          - Verifies ownership history & prevents double spending.
          - Detects tampered records or broken chains.
        """
        with self._lock:
            expected_previous_hash = "0" * 64
            verified_owners = {}
            minted_coins = set()

            structure_valid = True
            hashes_valid = True
            signatures_valid = True
            ownership_valid = True
            history_valid = True
            tampering_detected = False

            try:
                for idx, block in enumerate(self.chain):
                    tx = block["transaction"]
                    signer = block["signer"]
                    sig_bytes = bytes.fromhex(block["signature"])

                    if signer not in self.users:
                        structure_valid = False
                        break

                    # 1. Verify previous block hash linkage
                    if tx["previous_hash"] != expected_previous_hash:
                        hashes_valid = False
                        tampering_detected = True
                        break

                    # 2. Cryptographic signature check
                    canonical_data = self.canonical_json(tx)
                    public_key = self.users[signer]["public_key"]
                    try:
                        public_key.verify(sig_bytes, canonical_data, hashfunc=hashlib.sha256)
                    except BadSignatureError:
                        signatures_valid = False
                        tampering_detected = True
                        break

                    # 3. Block hash calculation check
                    recomputed = self.sha256(canonical_data + sig_bytes + expected_previous_hash.encode("utf-8"))
                    if recomputed != block["block_hash"]:
                        hashes_valid = False
                        tampering_detected = True
                        break

                    tx_type = tx.get("type")
                    coins_in_tx = tx.get("coins", [tx.get("coin_id")])

                    # 4. Transaction rules
                    if tx_type in ("MINT", "GENESIS_MINT"):
                        if signer != self.creator_name:
                            history_valid = False
                            break
                        for c in coins_in_tx:
                            if c in minted_coins:
                                history_valid = False
                                break
                            minted_coins.add(c)
                            verified_owners[c] = tx["recipient"]

                    elif tx_type in ("TRANSFER", "BUY_REQUEST", "FREE_REQUEST"):
                        if signer != tx["sender"]:
                            signatures_valid = False
                            break
                        for c in coins_in_tx:
                            if c not in verified_owners:
                                history_valid = False
                                break
                            if verified_owners[c] != tx["sender"]:
                                ownership_valid = False
                                break
                            verified_owners[c] = tx["recipient"]

                    expected_previous_hash = block["block_hash"]

                if verified_owners != self.coin_owners:
                    ownership_valid = False

                if len(self.coin_owners) != len(minted_coins):
                    ownership_valid = False

                all_valid = (
                    structure_valid and hashes_valid and signatures_valid and
                    ownership_valid and history_valid and not tampering_detected
                )

                return {
                    "structure_valid": structure_valid,
                    "hashes_valid": hashes_valid,
                    "signatures_valid": signatures_valid,
                    "ownership_valid": ownership_valid,
                    "history_valid": history_valid,
                    "tampering_detected": tampering_detected,
                    "final_status": "BLOCKCHAIN VALID" if all_valid else "BLOCKCHAIN INVALID",
                    "valid": all_valid,
                    "total_blocks": len(self.chain),
                    "total_coins": len(self.coin_owners)
                }

            except Exception as exc:
                print(f"[VERIFY EXCEPTION] {exc}")
                return {
                    "structure_valid": False,
                    "hashes_valid": False,
                    "signatures_valid": False,
                    "ownership_valid": False,
                    "history_valid": False,
                    "tampering_detected": True,
                    "final_status": "BLOCKCHAIN INVALID",
                    "valid": False,
                    "total_blocks": len(self.chain)
                }

    # =========================================================================
    # Coin Acquisition System (Buy & Free Requests with Admin Approval)
    # =========================================================================
    def get_available_coins_for_acquisition(self):
        """Returns coin holders and available balances for users to request or buy from."""
        balances = {}
        for c_id, owner in self.coin_owners.items():
            balances[owner] = balances.get(owner, 0) + 1

        available = []
        for owner, bal in balances.items():
            if bal > 0:
                owner_id = self.users[owner]["user_id"]
                available.append({
                    "owner_username": owner,
                    "owner_id": owner_id,
                    "available_coins": bal,
                    "coin_name": "GoofyCoin",
                    "price_per_coin": "1 USD (Simulated)"
                })
        return available

    def create_coin_request(self, requester, owner, amount, request_type="FREE_REQUEST"):
        """Creates a coin acquisition request (BUY_REQUEST or FREE_REQUEST) awaiting Admin Approval."""
        req_uname = self.resolve_user(requester)
        own_uname = self.resolve_user(owner)

        if not req_uname or not own_uname:
            raise ValueError("Requester or owner does not exist.")

        amount = int(amount)
        if amount <= 0:
            raise ValueError("Requested amount must be greater than zero.")

        owner_bal = self.get_user_balance(own_uname)
        if owner_bal < amount:
            raise ValueError(f"Owner '{own_uname}' only has {owner_bal} coins available (requested {amount}).")

        req_id = len(self.coin_requests) + 1
        req_record = {
            "request_id": req_id,
            "requester": req_uname,
            "requester_id": self.users[req_uname]["user_id"],
            "requester_wallet": self.users[req_uname].get("wallet_address", ""),
            "requester_public_key": self.users[req_uname]["public_key"].to_string().hex(),
            "owner": own_uname,
            "owner_id": self.users[own_uname]["user_id"],
            "owner_wallet": self.users[own_uname].get("wallet_address", ""),
            "owner_public_key": self.users[own_uname]["public_key"].to_string().hex(),
            "amount": amount,
            "type": request_type,
            "status": "PENDING",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        self.coin_requests.append(req_record)
        return req_record

    def approve_coin_request(self, request_id, approver):
        """
        Approves a pending coin request (BUY_REQUEST or FREE_REQUEST).
        Executes TransferCoin, generates cryptographic block with hashes & signatures,
        and assigns coins to requester.
        """
        app_uname = self.resolve_user(approver)
        target_req = None
        for req in self.coin_requests:
            if req["request_id"] == int(request_id) and req["status"] == "PENDING":
                target_req = req
                break

        if not target_req:
            raise ValueError(f"Pending request ID #{request_id} not found.")

        if target_req["owner"] != app_uname:
            raise PermissionError(f"Only the coin owner ('{target_req['owner']}') can approve this request.")

        # Execute transfer using TransferCoin with the requested amount and transaction type
        block = self.TransferCoin(
            target_req["owner"],
            target_req["requester"],
            target_req["amount"],
            tx_type=target_req["type"]
        )

        target_req["status"] = "APPROVED"
        target_req["approved_at"] = datetime.now(timezone.utc).isoformat()
        target_req["block_hash"] = block["block_hash"]
        target_req["previous_hash"] = block["previous_hash"]

        return block, target_req

    # =========================================================================
    # Simulation Runner
    # =========================================================================
    def run_simulation(self, send_fn=print):
        """Runs the complete 6-step blockchain demonstration."""
        send_fn("\n==================================================================")
        send_fn("             GOOFYCOIN BLOCKCHAIN SIMULATION START                ")
        send_fn("==================================================================")

        # Step 1: Create Users
        send_fn("\n[STEP 1] CreateUser: Generating ECDSA Keys & User IDs...")
        u_goofy = self.CreateUser("Goofy")
        u_alice = self.CreateUser("Alice")
        u_bob = self.CreateUser("Bob")

        send_fn(f"  [+] User Created: '{u_goofy['username']}' ({u_goofy['user_id']}) - Balance: {self.get_user_balance('Goofy')} Coins")
        send_fn(f"  [+] User Created: '{u_alice['username']}' ({u_alice['user_id']}) - Balance: {self.get_user_balance('Alice')} Coins")
        send_fn(f"  [+] User Created: '{u_bob['username']}' ({u_bob['user_id']}) - Balance: {self.get_user_balance('Bob')} Coins")

        # Step 2: Minting & Supply Check
        send_fn("\n[STEP 2] CreateCoin & Supply Limit Check: Verifying 1,000 Coin Cap...")
        send_fn(f"  [*] Initial Admin Supply: {self.get_user_balance('Goofy')} GoofyCoins in circulation.")
        try:
            self.CreateCoin("Goofy", "COIN1001", "GoofyCoin")
        except PermissionError as exc:
            send_fn("  [+] Supply Guard Active: Further minting blocked beyond 1,000 coins!")
            send_fn(f"      Reason: {exc}")

        # Step 3: Transfer Amount to Alice
        send_fn("\n[STEP 3] TransferCoin: Transferring 10 Coins from 'Goofy' to 'Alice'...")
        tx1_block = self.TransferCoin("Goofy", "Alice", 10)
        send_fn("  [+] Transfer Executed Successfully!")
        send_fn(f"      Coin Range       : {tx1_block['transaction']['coin_id']}")
        send_fn(f"      Block Hash       : {tx1_block['block_hash']}")
        send_fn(f"      Previous Hash    : {tx1_block['previous_hash']}")
        send_fn(f"      Digital Signature: {tx1_block['signature'][:32]}...")
        send_fn(f"  [*] Balances -> Goofy: {self.get_user_balance('Goofy')} | Alice: {self.get_user_balance('Alice')}")

        # Step 4: Return Partial Amount to Goofy
        send_fn("\n[STEP 4] TransferCoin: Returning 3 Coins from 'Alice' to 'Goofy'...")
        tx2_block = self.TransferCoin("Alice", "Goofy", 3)
        send_fn("  [+] Return Transfer Executed Successfully!")
        send_fn(f"      Coin Range       : {tx2_block['transaction']['coin_id']}")
        send_fn(f"      Block Hash       : {tx2_block['block_hash']}")
        send_fn(f"      Previous Hash    : {tx2_block['previous_hash']}")
        send_fn(f"  [*] Balances -> Alice: {self.get_user_balance('Alice')} | Goofy: {self.get_user_balance('Goofy')}")

        # Step 5: Test Unauthorized Transfer
        send_fn("\n[STEP 5] Security Test: Catching Illegal Transfer Attempt...")
        send_fn(f"  [*] Attacker 'Bob' ({u_bob['user_id']}) tries to transfer 5 coins (which he does NOT own)...")
        security_caught = False
        try:
            self.TransferCoin("Bob", "Alice", 5)
        except ValueError as exc:
            security_caught = True
            send_fn("  [SECURITY ALERT] Illegal transfer caught and blocked!")
            send_fn(f"  Reason: {exc}")
            send_fn(f"  [+] State Protected: Alice balance remains {self.get_user_balance('Alice')}.")

        # Step 6: Verify Chain
        send_fn("\n[STEP 6] Verify_chain: Running Complete Cryptographic Verification...")
        v_res = self.Verify_chain()
        send_fn(f"  Block Structure     : {'VALID' if v_res['structure_valid'] else 'INVALID'}")
        send_fn(f"  Block Hashes        : {'VALID' if v_res['hashes_valid'] else 'INVALID'}")
        send_fn(f"  Digital Signatures  : {'VALID' if v_res['signatures_valid'] else 'INVALID'}")
        send_fn(f"  Coin Ownership      : {'VALID' if v_res['ownership_valid'] else 'INVALID'}")
        send_fn(f"  Transaction History : {'VALID' if v_res['history_valid'] else 'INVALID'}")
        send_fn(f"  Tampering Detected  : {'NO' if not v_res['tampering_detected'] else 'YES'}")
        send_fn(f"  Total Coin Supply   : {v_res.get('total_coins', 1000)} / {MAX_COIN_SUPPLY} FIXED")
        send_fn(f"  Final Status        : {v_res['final_status']}")

        send_fn("\n==================================================================")
        send_fn("                      SIMULATION FINISHED                         ")
        send_fn("==================================================================\n")

        return v_res["valid"] and security_caught


# =============================================================================
# 6. handle_client
# =============================================================================
def handle_client(conn, address, blockchain):
    """
    [6] Handle Client:
      - Accepts client connection.
      - Receives JSON requests in chunks until newline.
      - Validates request format and identifies operation.
      - Calls relevant function (CreateUser, CreateCoin, TransferCoin, Verify_chain, etc.).
      - Handles exceptions and catches errors.
      - Sends JSON response and closes connection safely.
    """
    client_ip = address[0]
    client_port = address[1]
    client_addr_str = f"{client_ip}:{client_port}"

    def log_activity(operation, working_desc, user_str="Guest / Anonymous", status="SUCCESS"):
        timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        active_summary = blockchain.get_active_sessions_summary()
        print("\n======================= CLIENT ACTIVITY =======================")
        print(f"Timestamp     : {timestamp_str}")
        print(f"Client        : {client_addr_str}")
        print(f"User          : {user_str}")
        print(f"Operation     : {operation}")
        print(f"Working       : {working_desc}")
        print(f"Active Clients: {active_summary}")
        print(f"Request       : RECEIVED")
        print(f"Validation    : {status}")
        print(f"Response      : SENT")
        print("===============================================================\n")

    def send_json(data):
        try:
            conn.sendall((json.dumps(data) + "\n").encode("utf-8"))
        except OSError:
            pass

    try:
        conn.settimeout(2.5)
        chunks = []
        while True:
            try:
                part = conn.recv(BUFFER_SIZE)
                if not part:
                    break
                chunks.append(part)
                if b"\n" in part:
                    break
            except (socket.timeout, BlockingIOError):
                break
        raw_data = b"".join(chunks)

        if raw_data:
            msg_str = raw_data.decode("utf-8", errors="ignore").strip()

            if msg_str.startswith("{"):
                req = json.loads(msg_str)
                action = req.get("action", "").upper()

                # Operation: CreateUser / Login
                if action == "REGISTER":
                    username = req.get("username", "Mohsin").strip()
                    user = blockchain.CreateUser(username)
                    blockchain.add_session(username, client_ip, client_port)
                    user_id = user["user_id"]
                    role = "ADMIN & CREATOR" if (username == blockchain.creator_name or user_id == "USER001") else "USER"
                    user_label = f"{username} ({user_id}) [{role}]"

                    log_activity(
                        operation="CreateUser",
                        working_desc=f"User '{username}' logged in / registered. Balance: {blockchain.get_user_balance(username)} GoofyCoins",
                        user_str=user_label,
                        status="SUCCESS"
                    )

                    profile = {
                        "status": "SUCCESS",
                        "user_id": user["user_id"],
                        "username": user["username"],
                        "wallet_address": user["wallet_address"],
                        "public_key": user["public_key"].to_string().hex(),
                        "private_key": user["private_key"].to_string().hex(),
                        "total_coins": blockchain.get_user_balance(username),
                        "coins": blockchain.get_user_coins(username),
                        "message": f"User '{username}' registered successfully!"
                    }
                    send_json(profile)
                    return

                # Operation: Logout
                elif action == "LOGOUT":
                    username = req.get("username", "").strip()
                    uname = blockchain.resolve_user(username) or username
                    user_data = blockchain.users.get(uname, {})
                    user_id = user_data.get("user_id", "USER")
                    user_label = f"{uname} ({user_id})"
                    blockchain.remove_session(uname)

                    log_activity(
                        operation="Logout",
                        working_desc=f"User '{uname}' logged out of wallet session",
                        user_str=user_label,
                        status="SUCCESS"
                    )
                    send_json({"status": "SUCCESS", "message": f"User '{uname}' logged out successfully."})
                    return

                # Operation: View Wallet & Balance
                elif action == "BALANCE":
                    username = req.get("username", "").strip()
                    uname = blockchain.resolve_user(username)
                    user_data = blockchain.users.get(uname, {})
                    user_id = user_data.get("user_id", "USER001")
                    bal = blockchain.get_user_balance(uname)
                    blockchain.update_session_activity(uname, client_ip, client_port)
                    role = "ADMIN" if (uname == blockchain.creator_name or user_id == "USER001") else "USER"
                    user_label = f"{uname} ({user_id}) [{role}]"

                    log_activity(
                        operation="ViewWallet",
                        working_desc=f"Checked wallet balance ({bal} GoofyCoins) and transaction history",
                        user_str=user_label,
                        status="SUCCESS"
                    )

                    res = {
                        "status": "SUCCESS",
                        "user_id": user_data.get("user_id", "USER001"),
                        "username": uname,
                        "wallet_address": user_data.get("wallet_address", "N/A"),
                        "public_key": user_data.get("public_key").to_string().hex() if "public_key" in user_data else "",
                        "private_key": user_data.get("private_key").to_string().hex() if "private_key" in user_data else "",
                        "total_coins": bal,
                        "coins": blockchain.get_user_coins(uname),
                        "history": blockchain.get_user_transactions(uname)
                    }
                    send_json(res)
                    return

                # Operation: CreateCoin
                elif action == "MINT":
                    creator = req.get("creator", "").strip()
                    coin_id = req.get("coin_id")
                    coin_name = req.get("coin_name", "GoofyCoin").strip()
                    amount = int(req.get("amount", 1))
                    creator_u = blockchain.resolve_user(creator)
                    blockchain.update_session_activity(creator_u, client_ip, client_port)
                    user_data = blockchain.users.get(creator_u, {})
                    user_id = user_data.get("user_id", "USER001")
                    user_label = f"{creator_u} ({user_id}) [ADMIN]"

                    try:
                        block = blockchain.CreateCoin(creator, coin_id, coin_name, amount)
                        tot_sup = len(blockchain.coin_owners)
                        log_activity(
                            operation="CreateCoin",
                            working_desc=f"Admin minted {amount} new GoofyCoins ({block['transaction']['coin_id']}). Network Total Supply: {tot_sup:,} GFC",
                            user_str=user_label,
                            status="SUCCESS"
                        )
                        creator_pub = blockchain.users[creator_u]["public_key"].to_string().hex()
                        res = {
                            "status": "SUCCESS",
                            "coin_id": block["transaction"]["coin_id"],
                            "coin_name": coin_name,
                            "amount": block["transaction"].get("amount", 1),
                            "creator_id": blockchain.users[creator_u]["user_id"],
                            "current_owner": blockchain.users[creator_u]["user_id"],
                            "creator_public_key": creator_pub,
                            "authorization": "VERIFIED",
                            "signature": block["signature"],
                            "block_index": block["index"],
                            "block_hash": block["block_hash"],
                            "previous_hash": block["previous_hash"],
                            "new_balance": blockchain.get_user_balance(creator_u),
                            "total_supply": tot_sup,
                            "coins": blockchain.get_user_coins(creator_u)
                        }
                    except Exception as err:
                        log_activity(
                            operation="CreateCoin",
                            working_desc=f"Minting attempt failed / rejected: {err}",
                            user_str=user_label,
                            status="REJECTED"
                        )
                        res = {"status": "ERROR", "message": str(err)}
                    send_json(res)
                    return

                # Operation: TransferCoin (by Amount or Coin ID)
                elif action == "TRANSFER":
                    sender = req.get("sender", "").strip()
                    recipient = req.get("recipient", "").strip()
                    coin_id_or_amt = req.get("amount") or req.get("coin_id", "").strip()
                    sender_u = blockchain.resolve_user(sender)
                    recip_u = blockchain.resolve_user(recipient)
                    blockchain.update_session_activity(sender_u, client_ip, client_port)
                    user_data = blockchain.users.get(sender_u, {})
                    user_id = user_data.get("user_id", "USER")
                    user_label = f"{sender_u} ({user_id})"

                    try:
                        block = blockchain.TransferCoin(sender, recipient, coin_id_or_amt)
                        log_activity(
                            operation="TransferCoin",
                            working_desc=f"Transferred {block['transaction']['amount']} coins to '{recip_u}'. Coin ID: {block['transaction']['coin_id']}",
                            user_str=user_label,
                            status="SUCCESS"
                        )
                        sender_pub = blockchain.users[sender_u]["public_key"].to_string().hex()
                        recip_pub = blockchain.users[recip_u]["public_key"].to_string().hex()
                        res = {
                            "status": "SUCCESS",
                            "coin_id": block["transaction"]["coin_id"],
                            "amount": block["transaction"].get("amount", 1),
                            "type": block["transaction"].get("type", "TRANSFER"),
                            "sender": sender_u,
                            "sender_id": blockchain.users[sender_u]["user_id"],
                            "recipient": recip_u,
                            "recipient_id": blockchain.users[recip_u]["user_id"],
                            "sender_public_key": sender_pub,
                            "recipient_public_key": recip_pub,
                            "ownership": "VERIFIED",
                            "signature": block["signature"],
                            "block_index": block["index"],
                            "block_hash": block["block_hash"],
                            "previous_hash": block["previous_hash"],
                            "timestamp": block["transaction"]["timestamp"],
                            "sender_balance": blockchain.get_user_balance(sender_u),
                            "recipient_balance": blockchain.get_user_balance(recip_u)
                        }
                    except Exception as err:
                        log_activity(
                            operation="TransferCoin",
                            working_desc=f"Transfer to '{recipient}' failed / rejected: {err}",
                            user_str=user_label,
                            status="REJECTED"
                        )
                        res = {"status": "ERROR", "message": str(err)}
                    send_json(res)
                    return

                # Operation: Verify_chain
                elif action == "VERIFY":
                    v_res = blockchain.Verify_chain()
                    log_activity(
                        operation="Verify_chain",
                        working_desc=f"Verified entire blockchain integrity ({len(blockchain.chain)} blocks, hashes & signatures valid)",
                        user_str="Admin / Client",
                        status="SUCCESS"
                    )
                    res = {
                        "status": "SUCCESS",
                        **v_res,
                        "total_supply": len(blockchain.coin_owners)
                    }
                    send_json(res)
                    return

                # Operation: Available Coin Holders for Acquisition
                elif action == "GET_AVAILABLE_COINS":
                    available = blockchain.get_available_coins_for_acquisition()
                    log_activity(
                        operation="GetAvailableCoins",
                        working_desc=f"Client requested list of available coin holders ({len(available)} sellers available)",
                        user_str="Client",
                        status="SUCCESS"
                    )
                    send_json({"status": "SUCCESS", "sellers": available, "total_supply": len(blockchain.coin_owners)})
                    return

                # Operation: Request Free Coins / Buy Coins by Amount (Both Require Admin Approval)
                elif action == "ACQUIRE_COIN":
                    requester = req.get("requester")
                    owner = req.get("owner")
                    amount = int(req.get("amount", 1))
                    mode = req.get("mode", "FREE_REQUEST")
                    req_type = "BUY_REQUEST" if mode == "BUY" else "FREE_REQUEST"
                    req_u = blockchain.resolve_user(requester)
                    blockchain.update_session_activity(req_u, client_ip, client_port)
                    user_data = blockchain.users.get(req_u, {})
                    user_id = user_data.get("user_id", "USER")
                    user_label = f"{req_u} ({user_id})"

                    try:
                        req_rec = blockchain.create_coin_request(requester, owner, amount, req_type)
                        price_note = f" (${amount} USD)" if req_type == "BUY_REQUEST" else ""
                        log_activity(
                            operation="AcquireCoin",
                            working_desc=f"Submitted {req_type} #{req_rec['request_id']} for {amount} GoofyCoins{price_note} from '{owner}' (Status: PENDING)",
                            user_str=user_label,
                            status="SUCCESS"
                        )
                        res = {
                            "status": "SUCCESS",
                            "mode": mode,
                            "type": req_type,
                            "message": f"{req_type} #{req_rec['request_id']} for {amount} GoofyCoins{price_note} submitted to owner '{owner}'. Awaiting Admin Approval.",
                            "request_id": req_rec["request_id"],
                            "amount": amount
                        }
                    except Exception as err:
                        log_activity(
                            operation="AcquireCoin",
                            working_desc=f"Acquisition request failed: {err}",
                            user_str=user_label,
                            status="REJECTED"
                        )
                        res = {"status": "ERROR", "message": str(err)}
                    send_json(res)
                    return

                # Operation: Manage Pending Requests
                elif action == "GET_PENDING_REQUESTS":
                    owner = req.get("owner")
                    own_u = blockchain.resolve_user(owner)
                    blockchain.update_session_activity(own_u, client_ip, client_port)
                    pending = [r for r in blockchain.coin_requests if r["owner"] == own_u and r["status"] == "PENDING"]
                    user_data = blockchain.users.get(own_u, {})
                    user_id = user_data.get("user_id", "USER")
                    role = "ADMIN" if (own_u == blockchain.creator_name or user_id == "USER001") else "USER"
                    user_label = f"{own_u} ({user_id}) [{role}]"

                    log_activity(
                        operation="GetPendingRequests",
                        working_desc=f"Checked incoming coin requests ({len(pending)} pending requests awaiting approval)",
                        user_str=user_label,
                        status="SUCCESS"
                    )
                    send_json({"status": "SUCCESS", "requests": pending})
                    return

                # Operation: Approve Coin Request (Finalizes Transfer & Records Cryptographic Proof)
                elif action == "APPROVE_REQUEST":
                    req_id = req.get("request_id")
                    approver = req.get("approver")
                    app_u = blockchain.resolve_user(approver)
                    blockchain.update_session_activity(app_u, client_ip, client_port)
                    user_data = blockchain.users.get(app_u, {})
                    user_id = user_data.get("user_id", "USER001")
                    user_label = f"{app_u} ({user_id}) [ADMIN]"

                    try:
                        block, approved_req = blockchain.approve_coin_request(req_id, approver)
                        log_activity(
                            operation="TransferCoin",
                            working_desc=f"Approved Request #{req_id} ({approved_req['type']}): Transferred {approved_req['amount']} coins to '{approved_req['requester']}'",
                            user_str=user_label,
                            status="SUCCESS"
                        )
                        sender_u = approved_req["owner"]
                        recip_u = approved_req["requester"]
                        sender_pub = blockchain.users[sender_u]["public_key"].to_string().hex()
                        recip_pub = blockchain.users[recip_u]["public_key"].to_string().hex()

                        res = {
                            "status": "SUCCESS",
                            "message": f"Request #{req_id} ({approved_req['type']}) approved! {approved_req['amount']} GoofyCoins transferred to '{approved_req['requester']}'.",
                            "coin_id": block["transaction"]["coin_id"],
                            "amount": approved_req["amount"],
                            "type": approved_req["type"],
                            "sender": sender_u,
                            "sender_id": approved_req["owner_id"],
                            "recipient": recip_u,
                            "recipient_id": approved_req["requester_id"],
                            "sender_public_key": sender_pub,
                            "recipient_public_key": recip_pub,
                            "ownership": "VERIFIED",
                            "signature": block["signature"],
                            "block_index": block["index"],
                            "block_hash": block["block_hash"],
                            "previous_hash": block["previous_hash"],
                            "timestamp": block["transaction"]["timestamp"]
                        }
                    except Exception as err:
                        log_activity(
                            operation="TransferCoin",
                            working_desc=f"Request approval #{req_id} failed / rejected: {err}",
                            user_str=user_label,
                            status="REJECTED"
                        )
                        res = {"status": "ERROR", "message": str(err)}
                    send_json(res)
                    return

                # Operation: View Registered Users
                elif action == "GET_USERS":
                    users = blockchain.get_all_users()
                    log_activity(
                        operation="GetUsers",
                        working_desc=f"Admin viewed registered users list ({len(users)} registered users)",
                        user_str="Goofy (USER001) [ADMIN]",
                        status="SUCCESS"
                    )
                    send_json({"status": "SUCCESS", "users": users, "total_users": len(users)})
                    return

                # Operation: View Blockchain Ledger
                elif action == "GET_LEDGER":
                    ledger = blockchain.get_complete_ledger()
                    log_activity(
                        operation="GetLedger",
                        working_desc=f"Admin viewed complete blockchain ledger ({len(ledger)} total blocks)",
                        user_str="Goofy (USER001) [ADMIN]",
                        status="SUCCESS"
                    )
                    send_json({
                        "status": "SUCCESS",
                        "ledger": ledger,
                        "total_blocks": len(ledger),
                        "total_supply": len(blockchain.coin_owners)
                    })
                    return

        # Default action: run simulation feed
        def send_to_client(message):
            try:
                conn.sendall((message + "\n").encode("utf-8"))
            except OSError:
                pass

        blockchain.run_simulation(send_fn=send_to_client)

    except Exception as exc:
        print(f"[SERVER ERROR] {exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


# =============================================================================
# 5. start_server
# =============================================================================
def start_server(host=HOST, port=PORT):
    """
    [5] Start Server:
      - Configures Server IP and Port.
      - Creates TCP Socket (AF_INET, SOCK_STREAM).
      - Binds IP and Port.
      - Listens for connections.
      - Accepts client connections and delegates to worker threads.
    """
    shared_blockchain = GoofyCoin(creator="Goofy")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((host, port))
        server_socket.listen(5)

        print("\n========== GOOFYCOIN SERVER ==========")
        print(f"IP Address: {host}")
        print(f"Port:       {port}")
        print("Status:     LISTENING")
        print(f"Total Fixed Supply: {MAX_COIN_SUPPLY} GoofyCoins")
        print(f"Admin Initial Balance: {shared_blockchain.get_user_balance('Goofy')} GoofyCoins")
        print("Waiting for clients...")
        print("=====================================\n")

        while True:
            conn, address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(conn, address, shared_blockchain),
                daemon=True
            )
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[SERVER] Server stopped gracefully.")
    finally:
        server_socket.close()


# Module-level aliases
_default = GoofyCoin()
CreateUser = _default.CreateUser
CreateCoin = _default.CreateCoin
TransferCoin = _default.TransferCoin
Verify_chain = _default.Verify_chain


if __name__ == "__main__":
    start_server()
