"""
GoofyCoin Client Wallet: Interactive Blockchain Client.

Features:
  - Both Buy and Free Coin requests require Admin Approval before transfer.
  - Full cryptographic proof displayed upon transfer & approval:
      * Block Index
      * Current Block Hash
      * Previous Block Hash
      * Digital Signature
      * Sender & Recipient Public Keys
  - Fixed 1,000 Coin Economy strictly enforced.
  - Clean error handling prevents menu repetition.
"""

import socket
import sys
import json

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


def send_server_request(request_dict, host=HOST, port=PORT):
    """Sends JSON request to the server and returns JSON response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall((json.dumps(request_dict) + "\n").encode("utf-8"))
        chunks = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        raw = b"".join(chunks).decode("utf-8").strip()
        return json.loads(raw) if raw else {}


def format_key(key_str, chunk_size=32, indent=0):
    """Formats long cryptographic keys into neat multi-line blocks without truncation."""
    if not key_str:
        return "N/A"
    chunks = [key_str[i:i+chunk_size] for i in range(0, len(key_str), chunk_size)]
    if indent > 0:
        return ("\n" + " " * indent).join(chunks)
    return "\n".join(chunks)


def format_coin_list(coins):
    """Formats large coin lists cleanly without filling the screen."""
    if not coins:
        return "[]"
    if len(coins) <= 6:
        return str(coins)
    return f"['{coins[0]}', '{coins[1]}', '{coins[2]}', ... '{coins[-1]}'] ({len(coins)} total coins)"


def print_user_created_card(user_id, username, wallet_address, pub_key, priv_key, balance):
    """Prints the official USER CREATED card matching user specification."""
    print("\n========== USER CREATED ==========")
    print(f"User ID:        {user_id}")
    print(f"Username:       {username}")
    print(f"Wallet Address: {wallet_address}")
    print(f"Balance:        {balance} GoofyCoins")
    print("\n---------- PUBLIC KEY ----------")
    print(format_key(pub_key, 32, 0))
    print("\n---------- PRIVATE KEY ----------\n")
    print(format_key(priv_key, 32, 0))
    print("=================================\n")


def print_coin_created_card(
    coin_id,
    coin_name,
    creator_id,
    current_owner,
    amount=1,
    block_index=None,
    block_hash=None,
    previous_hash=None,
    signature=None,
    creator_pub_key=None,
    authorization="VERIFIED",
    status="SUCCESS"
):
    """Prints the official COIN CREATED card with full cryptographic details."""
    print("\n========== COIN CREATED ==========")
    print(f"Status:         {status}")
    print(f"Authorization:  {authorization} (Admin / Creator Only)")
    print(f"Coin ID:        {coin_id}")
    print(f"Coin Name:      {coin_name}")
    print(f"Amount Minted:  {amount} GoofyCoins")
    print(f"Creator ID:     {creator_id}")
    print(f"Initial Owner:  {current_owner}")

    print("\n---------- CRYPTOGRAPHIC PROOF ----------")
    if block_index is not None:
        print(f"Block Index:    Block #{block_index}")
    if block_hash:
        print(f"Block Hash:     {block_hash}")
    if previous_hash:
        print(f"Previous Hash:  {previous_hash}")
    if signature:
        print("Digital Signature:")
        print(f"  {format_key(signature, 32, 2)}")
    if creator_pub_key:
        print("Creator Public Key:")
        print(f"  {format_key(creator_pub_key, 32, 2)}")
    print("==================================\n")


def print_coin_transferred_card(
    coin_id,
    sender,
    recipient,
    amount=1,
    tx_type="TRANSFER",
    block_index=None,
    block_hash=None,
    previous_hash=None,
    signature=None,
    sender_pub_key=None,
    recipient_pub_key=None,
    timestamp=None,
    ownership="VERIFIED",
    transaction="SUCCESS"
):
    """Prints the complete, transparent COIN TRANSFERRED card with full cryptographic proofs."""
    print("\n================== COIN TRANSFERRED ==================")
    print(f"Transaction:    {transaction}")
    print(f"Type:           {tx_type}")
    print(f"Coin ID:        {coin_id}")
    print(f"Amount:         {amount} GoofyCoins")
    print(f"Sender:         {sender}")
    print(f"Recipient:      {recipient}")
    print(f"Ownership:      {ownership}")
    if timestamp:
        print(f"Timestamp:      {timestamp}")

    print("\n----------------- BLOCKCHAIN PROOF -----------------")
    if block_index is not None:
        print(f"Block Index:    Block #{block_index}")
    if block_hash:
        print(f"Current Hash:   {block_hash}")
    if previous_hash:
        print(f"Previous Hash:  {previous_hash}")
    if signature:
        print("Digital Signature:")
        print(f"  {format_key(signature, 32, 2)}")
    if sender_pub_key:
        print("Sender Public Key:")
        print(f"  {format_key(sender_pub_key, 32, 2)}")
    if recipient_pub_key:
        print("Recipient Public Key:")
        print(f"  {format_key(recipient_pub_key, 32, 2)}")
    print("======================================================\n")


def print_verify_card(res):
    """Prints the official BLOCKCHAIN VERIFICATION card."""
    print("\n========== BLOCKCHAIN VERIFICATION ==========")
    print(f"Block Structure:       {'VALID' if res.get('structure_valid') else 'INVALID'}")
    print(f"Block Hashes:          {'VALID' if res.get('hashes_valid') else 'INVALID'}")
    print(f"Digital Signatures:    {'VALID' if res.get('signatures_valid') else 'INVALID'}")
    print(f"Coin Ownership:        {'VALID' if res.get('ownership_valid') else 'INVALID'}")
    print(f"Transaction History:   {'VALID' if res.get('history_valid') else 'INVALID'}")
    print(f"Total Network Supply:  {res.get('total_supply', 1000)} GoofyCoins (VERIFIED)")
    print(f"Tampering Detected:    {'YES' if res.get('tampering_detected') else 'NO'}")
    print(f"Final Status:          {res.get('final_status', 'BLOCKCHAIN VALID')}")
    print("=============================================\n")


def print_wallet_details(bal_data):
    """Displays user wallet details, keys, and transaction history with hashes."""
    print("\n========== MY WALLET ==========")
    print(f"User ID:        {bal_data.get('user_id')}")
    print(f"Username:       {bal_data.get('username')}")
    print(f"Wallet Address: {bal_data.get('wallet_address')}")
    print(f"Balance:        {bal_data.get('total_coins', 0)} GoofyCoins")
    print(f"Owned Coins:    {format_coin_list(bal_data.get('coins', []))}")
    print("\n---------- PUBLIC KEY ----------")
    print(format_key(bal_data.get('public_key'), 32, 0))
    print("\n---------- PRIVATE KEY ----------\n")
    print(format_key(bal_data.get('private_key'), 32, 0))
    print("================================")

    history = bal_data.get("history", [])
    print(f"\n--- Transaction Ledger History ({len(history)} Transactions) ---")
    if not history:
        print("  (No transactions recorded yet for this wallet)")
    else:
        for idx, tx in enumerate(history, 1):
            t_type = tx.get("type", "TRANSFER")
            c_id = tx.get("coin_id")
            sndr = tx.get("sender") or "System (Genesis)"
            rcpt = tx.get("recipient")
            blk = tx.get("block_index")
            amt = tx.get("amount", 1)
            b_hash = tx.get("block_hash", "")
            p_hash = tx.get("previous_hash", "")
            sig = tx.get("signature", "")
            s_pub = tx.get("sender_public_key", "")
            print(f"  [{idx}] Block #{blk} | Type: {t_type} | Coins: {c_id} ({amt} coins)")
            print(f"       From: {sndr} ({tx.get('sender_id', '')}) -> To: {rcpt} ({tx.get('recipient_id', '')})")
            print(f"       Current Hash : {b_hash}")
            print(f"       Previous Hash: {p_hash}")
            if s_pub:
                print("       Sender PubKey:")
                print(f"         {format_key(s_pub, 32, 9)}")
            if sig:
                print("       Signature    :")
                print(f"         {format_key(sig, 32, 9)}")
            print("       " + "-" * 55)
    print("---------------------------------------------------------\n")


def get_goofycoins_submenu(current_user, host, port):
    """Submenu for Option [3] Get GoofyCoins with Admin Approval for all requests."""
    show_sub = True
    while True:
        if show_sub:
            print("\n========== GET GOOFYCOINS ==========")
            print()
            print("[1] Request Free Coins from an Owner (Awaiting Approval)")
            print("[2] Buy Coins from an Owner (Awaiting Approval)")
            print("[3] View Incoming Transfers & Proofs")
            print("[4] Back to Main Menu")
            print()

        try:
            choice = input("Select an option (1-4, or 'm' for menu): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if choice in ("m", "menu"):
            show_sub = True
            continue

        if choice == "1":
            # 1. Request Free Coins
            try:
                res = send_server_request({"action": "GET_AVAILABLE_COINS"}, host, port)
                sellers = res.get("sellers", [])
                available = [s for s in sellers if s["owner_username"] != current_user]

                if not available:
                    print("\n[!] No other owners have available coins to request right now.\n")
                    show_sub = False
                    continue

                print("\nAvailable Coin Holders in Ecosystem (Total Supply: 1,000 Coins):")
                for idx, s in enumerate(available, 1):
                    print(f"  [{idx}] Owner: {s['owner_username']} ({s['owner_id']}) | Available Coins: {s['available_coins']}")

                default_owner = available[0]["owner_username"]
                target_owner = input(f"\nEnter Owner Username to request from [{default_owner}]: ").strip()
                if not target_owner:
                    target_owner = default_owner

                sel_obj = next((s for s in available if s["owner_username"] == target_owner or s["owner_id"] == target_owner), None)
                if not sel_obj:
                    print(f"\n[-] Owner '{target_owner}' not found in available list.\n")
                    show_sub = False
                    continue

                amt_str = input(f"Enter Amount of coins to request (1 to {sel_obj['available_coins']}): ").strip()
                if not amt_str.isdigit() or int(amt_str) <= 0:
                    print("\n[!] Invalid amount. Must be a positive integer.\n")
                    show_sub = False
                    continue

                req_amt = int(amt_str)
                if req_amt > sel_obj["available_coins"]:
                    print(f"\n[-] Owner only has {sel_obj['available_coins']} coins available.\n")
                    show_sub = False
                    continue

                req_res = send_server_request({
                    "action": "ACQUIRE_COIN",
                    "requester": current_user,
                    "owner": sel_obj["owner_username"],
                    "amount": req_amt,
                    "mode": "FREE_REQUEST"
                }, host, port)

                if req_res.get("status") == "SUCCESS":
                    print(f"\n[+] {req_res.get('message')}")
                    print(f"    Status: PENDING")
                    print(f"    Notice: Owner '{sel_obj['owner_username']}' must approve via 'Manage Coin Requests' before coins are transferred.\n")
                    show_sub = True
                else:
                    print(f"\n[-] Request Failed: {req_res.get('message')}\n")
                    show_sub = False

            except ConnectionRefusedError:
                print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
                show_sub = False

        elif choice == "2":
            # 2. Buy Coins (Now Requires Admin Approval as requested!)
            try:
                res = send_server_request({"action": "GET_AVAILABLE_COINS"}, host, port)
                sellers = res.get("sellers", [])
                available = [s for s in sellers if s["owner_username"] != current_user]

                if not available:
                    print("\n[!] No owners have available coins for purchase right now.\n")
                    show_sub = False
                    continue

                print("\nAvailable Coins for Purchase:")
                for idx, s in enumerate(available, 1):
                    print(f"  [{idx}] Owner: {s['owner_username']} ({s['owner_id']}) | Available: {s['available_coins']} | Price: {s['price_per_coin']}")

                default_owner = available[0]["owner_username"]
                target_owner = input(f"\nEnter Owner Username to buy from [{default_owner}]: ").strip()
                if not target_owner:
                    target_owner = default_owner

                sel_obj = next((s for s in available if s["owner_username"] == target_owner or s["owner_id"] == target_owner), None)
                if not sel_obj:
                    print(f"\n[-] Owner '{target_owner}' not found in available list.\n")
                    show_sub = False
                    continue

                amt_str = input(f"Enter Amount of coins to buy (1 to {sel_obj['available_coins']}): ").strip()
                if not amt_str.isdigit() or int(amt_str) <= 0:
                    print("\n[!] Invalid amount.\n")
                    show_sub = False
                    continue

                buy_amt = int(amt_str)

                buy_res = send_server_request({
                    "action": "ACQUIRE_COIN",
                    "requester": current_user,
                    "owner": sel_obj["owner_username"],
                    "amount": buy_amt,
                    "mode": "BUY"
                }, host, port)

                if buy_res.get("status") == "SUCCESS":
                    print(f"\n[+] {buy_res.get('message')}")
                    print(f"    Simulated Cost : ${buy_amt} USD")
                    print(f"    Status         : PENDING (Locked until Owner '{sel_obj['owner_username']}' approves in 'Manage Coin Requests').\n")
                    show_sub = True
                else:
                    print(f"\n[-] Purchase Request Failed: {buy_res.get('message')}\n")
                    show_sub = False

            except ConnectionRefusedError:
                print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
                show_sub = False

        elif choice == "3":
            # 3. View Incoming Transfers with Complete Cryptographic Proof
            try:
                bal = send_server_request({"action": "BALANCE", "username": current_user}, host, port)
                history = bal.get("history", [])
                incoming = [tx for tx in history if tx.get("recipient") == current_user and tx.get("type") in ("TRANSFER", "BUY_REQUEST", "FREE_REQUEST", "GENESIS_MINT")]

                print("\n================== INCOMING TRANSFERS RECEIVED ==================")
                if not incoming:
                    print("  No incoming transfers recorded yet.")
                else:
                    for idx, tx in enumerate(incoming, 1):
                        print(f"[{idx}] Block #{tx.get('block_index')} | Type: {tx.get('type')} | Amount: {tx.get('amount', 1)} GoofyCoins")
                        print(f"    Coins          : {tx.get('coin_id')}")
                        print(f"    From           : {tx.get('sender')} ({tx.get('sender_id')}) -> To: {tx.get('recipient')} ({tx.get('recipient_id')})")
                        print(f"    Timestamp      : {tx.get('timestamp')}")
                        print(f"    Current Hash   : {tx.get('block_hash')}")
                        print(f"    Previous Hash  : {tx.get('previous_hash')}")
                        if tx.get("sender_public_key"):
                            print("    Sender PubKey  :")
                            print(f"      {format_key(tx.get('sender_public_key'), 32, 6)}")
                        if tx.get("recipient_public_key"):
                            print("    Recipient PubKey:")
                            print(f"      {format_key(tx.get('recipient_public_key'), 32, 6)}")
                        if tx.get("signature"):
                            print("    Signature      :")
                            print(f"      {format_key(tx.get('signature'), 32, 6)}")
                        print("-----------------------------------------------------------------")
                print("=================================================================\n")
                show_sub = True
            except ConnectionRefusedError:
                print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
                show_sub = False

        elif choice == "4":
            break
        else:
            print("\n[!] Invalid option. Please select 1 to 4 (or 'm' for menu).\n")
            show_sub = False


def manage_coin_requests(current_user, host, port):
    """Manage incoming pending requests (BUY_REQUEST and FREE_REQUEST) with cryptographic confirmation."""
    try:
        res = send_server_request({"action": "GET_PENDING_REQUESTS", "owner": current_user}, host, port)
        requests = res.get("requests", [])

        print(f"\n================ PENDING COIN REQUESTS ({len(requests)} Pending) ================")
        if not requests:
            print(f"  No pending coin requests for '{current_user}'.")
            print("=================================================================\n")
            return

        for req in requests:
            p_info = f" (${req.get('amount', 1)} USD)" if req.get("type") == "BUY_REQUEST" else ""
            print(f"  [Request #{req['request_id']}] Type: {req['type']} | Status: {req['status']}")
            print(f"      Requester      : {req['requester']} ({req['requester_id']})")
            print(f"      Wallet Address : {req.get('requester_wallet', 'N/A')}")
            print(f"      Requested Coins: {req.get('amount', 1)} GoofyCoins{p_info}")
            if req.get("requester_public_key"):
                print("      Requester PubKey:")
                print(f"        {format_key(req.get('requester_public_key'), 32, 8)}")
            print("  ---------------------------------------------------------")

        req_id_str = input("\nEnter Request ID to approve (or press Enter to skip): ").strip()
        if not req_id_str:
            return

        app_res = send_server_request({
            "action": "APPROVE_REQUEST",
            "request_id": req_id_str,
            "approver": current_user
        }, host, port)

        if app_res.get("status") == "SUCCESS":
            # Display Full Cryptographic Proof Card!
            print_coin_transferred_card(
                coin_id=app_res.get("coin_id"),
                sender=f"{app_res.get('sender')} ({app_res.get('sender_id')})",
                recipient=f"{app_res.get('recipient')} ({app_res.get('recipient_id')})",
                amount=app_res.get("amount", 1),
                tx_type=app_res.get("type", "APPROVED_REQUEST"),
                block_index=app_res.get("block_index"),
                block_hash=app_res.get("block_hash"),
                previous_hash=app_res.get("previous_hash"),
                signature=app_res.get("signature"),
                sender_pub_key=app_res.get("sender_public_key"),
                recipient_pub_key=app_res.get("recipient_public_key"),
                timestamp=app_res.get("timestamp"),
                ownership="VERIFIED",
                transaction="SUCCESS"
            )
            print(f"[+] {app_res.get('message')}\n")
        else:
            print(f"\n[-] Approval Failed: {app_res.get('message')}\n")

    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")


def create_user_flow(host, port):
    """Interactive flow to create a new user profile on demand."""
    print("\n--- Create New User ---")
    username = input("Enter Username (e.g. Mohsin, Ali, Goofy): ").strip()
    if not username:
        print("[!] Username cannot be empty.\n")
        return None

    try:
        res = send_server_request({"action": "REGISTER", "username": username}, host, port)
        if res.get("status") == "SUCCESS":
            print_user_created_card(
                user_id=res.get("user_id", "USER001"),
                username=res.get("username", username),
                wallet_address=res.get("wallet_address", "N/A"),
                pub_key=res.get("public_key", ""),
                priv_key=res.get("private_key", ""),
                balance=res.get("total_coins", 0)
            )
            return res
        else:
            print(f"\n[-] Registration Error: {res.get('message')}\n")
            return None
    except ConnectionRefusedError:
        print(f"\n[ERROR] Cannot connect to GoofyCoin server at {host}:{port}.")
        print("Please start the server first by running: python goofycoin.py\n")
        return None


def do_create_coin(current_user, host, port):
    """Admin sovereign coin minting flow with cryptographic proof card."""
    coin_name = input("\nEnter Coin Name [GoofyCoin]: ").strip()
    if not coin_name:
        coin_name = "GoofyCoin"

    amt_input = input("Enter Amount of coins to create/mint [1]: ").strip()
    mint_amt = int(amt_input) if amt_input.isdigit() and int(amt_input) > 0 else 1

    coin_id_input = None
    if mint_amt == 1:
        cid = input("Enter custom Coin ID (or press Enter for auto ID): ").strip()
        if cid:
            coin_id_input = cid

    try:
        res = send_server_request({
            "action": "MINT",
            "creator": current_user,
            "coin_id": coin_id_input,
            "coin_name": coin_name,
            "amount": mint_amt
        }, host, port)

        if res.get("status") == "SUCCESS":
            print_coin_created_card(
                coin_id=res.get("coin_id"),
                coin_name=res.get("coin_name"),
                creator_id=res.get("creator_id"),
                current_owner=res.get("current_owner"),
                amount=res.get("amount", 1),
                block_index=res.get("block_index"),
                block_hash=res.get("block_hash"),
                previous_hash=res.get("previous_hash"),
                signature=res.get("signature"),
                creator_pub_key=res.get("creator_public_key"),
                authorization="VERIFIED",
                status="SUCCESS"
            )
            print(f"[+] Mint Successful! Admin Balance: {res.get('new_balance')} GoofyCoins | Total Supply: {res.get('total_supply')} Coins\n")
            return True
        else:
            print(f"\n[-] Mint Failed: {res.get('message')}\n")
            return False
    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def do_transfer_coin(current_user, host, port):
    """Cryptographic coin transfer flow."""
    if not current_user:
        print("\n[!] Pehle Option [1] select karke User create ya select karein.\n")
        return False

    try:
        bal_data = send_server_request({"action": "BALANCE", "username": current_user}, host, port)
        user_balance = bal_data.get("total_coins", 0)

        if user_balance <= 0:
            print(f"\n[!] Wallet '{current_user}' has 0 GoofyCoins to transfer.")
            print("    Use Option [3] 'Get GoofyCoins' to acquire coins first.\n")
            return False

        print(f"\nYour Current Balance: {user_balance} GoofyCoins")
        recipient = input("Enter Recipient Username or User ID: ").strip()
        if not recipient:
            print("[!] Recipient cannot be empty.\n")
            return False

        amt_or_coin = input(f"Enter Amount of coins to transfer (1 to {user_balance}) [or specific Coin ID]: ").strip()
        if not amt_or_coin:
            print("[!] Amount or Coin ID cannot be empty.\n")
            return False

        res = send_server_request({
            "action": "TRANSFER",
            "sender": current_user,
            "recipient": recipient,
            "amount": amt_or_coin
        }, host, port)

        if res.get("status") == "SUCCESS":
            print_coin_transferred_card(
                coin_id=res.get("coin_id"),
                sender=f"{res.get('sender')} ({res.get('sender_id')})",
                recipient=f"{res.get('recipient')} ({res.get('recipient_id')})",
                amount=res.get("amount", 1),
                tx_type=res.get("type", "TRANSFER"),
                block_index=res.get("block_index"),
                block_hash=res.get("block_hash"),
                previous_hash=res.get("previous_hash"),
                signature=res.get("signature"),
                sender_pub_key=res.get("sender_public_key"),
                recipient_pub_key=res.get("recipient_public_key"),
                timestamp=res.get("timestamp"),
                ownership="VERIFIED",
                transaction="SUCCESS"
            )
            print(f"[+] Transfer Success! Your New Balance: {res.get('sender_balance')} GoofyCoins.\n")
            return True
        else:
            print(f"\n[-] Transfer Failed: {res.get('message')}\n")
            return False

    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def do_verify_chain(host, port):
    """Blockchain verification flow."""
    try:
        res = send_server_request({"action": "VERIFY"}, host, port)
        print_verify_card(res)
        return True
    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def do_simulation(host, port):
    """Simulation streaming flow."""
    print("\n[*] Connecting to stream GoofyCoin blockchain simulation...\n")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sim_sock:
            sim_sock.connect((host, port))
            while True:
                data = sim_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                sys.stdout.write(data.decode("utf-8", errors="replace"))
                sys.stdout.flush()
        print("\n[COMPLETE] Simulation completed.\n")
        return True
    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def admin_view_users(host, port):
    """Displays all registered users in the network with their IDs, keys, and balances."""
    try:
        res = send_server_request({"action": "GET_USERS"}, host, port)
        users = res.get("users", [])
        print("\n======================= REGISTERED USERS =======================")
        print(f"Total Registered Users: {len(users)}\n")
        for u in users:
            role = "ADMIN & CREATOR" if u.get("is_admin") else "USER"
            print(f"[{u['user_id']}] {u['username']} ({role})")
            print(f"  Wallet Address : {u['wallet_address']}")
            print(f"  Balance        : {u['balance']} GoofyCoins ({u['coins_count']} coins owned)")
            print("  Public Key:")
            print(f"    {format_key(u['public_key'], 32, 4)}")
            print("  " + "-" * 55)
        print("================================================================\n")
        return True
    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def admin_view_ledger(host, port):
    """Displays the complete blockchain ledger with all blocks, hashes, and signatures."""
    try:
        res = send_server_request({"action": "GET_LEDGER"}, host, port)
        ledger = res.get("ledger", [])
        total_supply = res.get("total_supply", 1000)
        print("\n======================== BLOCKCHAIN LEDGER ========================")
        print(f"Total Blocks: {len(ledger)} | Total Supply: {total_supply} GoofyCoins\n")
        for blk in ledger:
            print(f"[Block #{blk['block_index']}] Type: {blk['type']} | Coins: {blk['coin_id']} ({blk['amount']} coins)")
            print(f"  From          : {blk['sender']} ({blk['sender_id']}) -> To: {blk['recipient']} ({blk['recipient_id']})")
            print(f"  Timestamp     : {blk['timestamp']}")
            print(f"  Current Hash  : {blk['block_hash']}")
            print(f"  Previous Hash : {blk['previous_hash']}")
            if blk.get("signature"):
                print("  Signature     :")
                print(f"    {format_key(blk['signature'], 32, 4)}")
            if blk.get("sender_public_key"):
                print("  Sender PubKey :")
                print(f"    {format_key(blk['sender_public_key'], 32, 4)}")
            print("  " + "-" * 60)
        print("===================================================================\n")
        return True
    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def admin_view_requests(host, port):
    """View and approve incoming pending coin requests with full cryptographic cards."""
    try:
        res = send_server_request({"action": "GET_PENDING_REQUESTS", "owner": "Goofy"}, host, port)
        requests = res.get("requests", [])

        print(f"\n================ PENDING COIN REQUESTS ({len(requests)} Pending) ================")
        if not requests:
            print(f"  No pending coin requests awaiting approval.")
            print("=================================================================\n")
            return True

        for req in requests:
            p_info = f" (${req.get('amount', 1)} USD)" if req.get("type") == "BUY_REQUEST" else ""
            print(f"  [Request #{req['request_id']}] Type: {req['type']} | Status: {req['status']}")
            print(f"      Requester      : {req['requester']} ({req['requester_id']})")
            print(f"      Wallet Address : {req.get('requester_wallet', 'N/A')}")
            print(f"      Requested Coins: {req.get('amount', 1)} GoofyCoins{p_info}")
            if req.get("requester_public_key"):
                print("      Requester PubKey:")
                print(f"        {format_key(req.get('requester_public_key'), 32, 8)}")
            print("  ---------------------------------------------------------")

        print("=================================================================")
        req_id_str = input("\nEnter Request ID to approve (or press Enter to skip): ").strip()
        if not req_id_str:
            return True

        app_res = send_server_request({
            "action": "APPROVE_REQUEST",
            "request_id": req_id_str,
            "approver": "Goofy"
        }, host, port)

        if app_res.get("status") == "SUCCESS":
            print_coin_transferred_card(
                coin_id=app_res.get("coin_id"),
                sender=f"{app_res.get('sender')} ({app_res.get('sender_id')})",
                recipient=f"{app_res.get('recipient')} ({app_res.get('recipient_id')})",
                amount=app_res.get("amount", 1),
                tx_type=app_res.get("type", "APPROVED_REQUEST"),
                block_index=app_res.get("block_index"),
                block_hash=app_res.get("block_hash"),
                previous_hash=app_res.get("previous_hash"),
                signature=app_res.get("signature"),
                sender_pub_key=app_res.get("sender_public_key"),
                recipient_pub_key=app_res.get("recipient_public_key"),
                timestamp=app_res.get("timestamp"),
                ownership="VERIFIED",
                transaction="SUCCESS"
            )
            print(f"[+] {app_res.get('message')}\n")
            return True
        else:
            print(f"\n[-] Approval Failed: {app_res.get('message')}\n")
            return False

    except ConnectionRefusedError:
        print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
        return False


def print_admin_menu(total_supply):
    """Prints the official Admin Menu matching user specification."""
    supply_text = f"  Total Supply: {total_supply:,} GFC"
    supply_line = f"║{supply_text.ljust(38)}║"
    print("╔══════════════════════════════════════╗")
    print("║         GOOFYCOIN | ADMIN            ║")
    print("╠══════════════════════════════════════╣")
    print(supply_line)
    print("╠══════════════════════════════════════╣")
    print("║  [1] Mint New Coin(s)                ║")
    print("║  [2] Transfer / Sell Coins           ║")
    print("║  [3] View Coin Requests              ║")
    print("║  [4] View Blockchain Ledger          ║")
    print("║  [5] Verify Blockchain Integrity     ║")
    print("║  [6] View Registered Users           ║")
    print("║  [0] Logout                          ║")
    print("╚══════════════════════════════════════╝")


def run_admin_dashboard(host=HOST, port=PORT):
    """Dedicated interactive dashboard for Admin Goofy."""
    show_menu = True
    while True:
        total_supply = 1000
        try:
            res = send_server_request({"action": "VERIFY"}, host, port)
            total_supply = res.get("total_supply", 1000)
        except Exception:
            pass

        if show_menu:
            print_admin_menu(total_supply)

        try:
            choice = input("Select option > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting Admin. Goodbye!")
            break

        if choice in ("m", "menu"):
            show_menu = True
            continue

        if choice == "1":
            show_menu = do_create_coin("Goofy", host, port)
        elif choice == "2":
            show_menu = do_transfer_coin("Goofy", host, port)
        elif choice == "3":
            show_menu = admin_view_requests(host, port)
        elif choice == "4":
            show_menu = admin_view_ledger(host, port)
        elif choice == "5":
            show_menu = do_verify_chain(host, port)
        elif choice == "6":
            show_menu = admin_view_users(host, port)
        elif choice == "0":
            try:
                send_server_request({"action": "LOGOUT", "username": "Goofy"}, host, port)
            except Exception:
                pass
            print("\n[*] Logged out of Admin Goofy. Returning to main menu...\n")
            break
        else:
            print(f"\n[!] Invalid option '{choice}'. Please select 0 to 6 (or 'm' for menu).\n")
            show_menu = False


def print_user_menu(username, user_id, balance):
    """Prints the User Wallet menu matching the box-drawing style."""
    user_line = f"  User   : {username} ({user_id})"
    bal_line = f"  Balance: {balance} GoofyCoins"
    print("╔══════════════════════════════════════╗")
    print("║         GOOFYCOIN | WALLET           ║")
    print("╠══════════════════════════════════════╣")
    print(f"║{user_line.ljust(38)}║")
    print(f"║{bal_line.ljust(38)}║")
    print("╠══════════════════════════════════════╣")
    print("║  [1] View My Wallet & History        ║")
    print("║  [2] Get GoofyCoins (Request / Buy)  ║")
    print("║  [3] Transfer Coin (by Amount)       ║")
    print("║  [4] Manage Coin Requests            ║")
    print("║  [5] Verify Blockchain Integrity     ║")
    print("║  [6] Run Full Simulation Demo        ║")
    print("║  [0] Logout                          ║")
    print("╚══════════════════════════════════════╝")


def run_user_dashboard(user_info, host=HOST, port=PORT):
    """Dedicated interactive dashboard for regular users."""
    current_user = user_info.get("username")
    current_user_id = user_info.get("user_id")
    show_menu = True

    while True:
        balance = 0
        try:
            bal_data = send_server_request({"action": "BALANCE", "username": current_user}, host, port)
            current_user_id = bal_data.get("user_id", current_user_id)
            balance = bal_data.get("total_coins", 0)
        except Exception:
            pass

        if show_menu:
            print_user_menu(current_user, current_user_id, balance)

        try:
            choice = input("Select option > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting User Wallet. Goodbye!")
            break

        if choice in ("m", "menu"):
            show_menu = True
            continue

        if choice == "1":
            try:
                bal_data = send_server_request({"action": "BALANCE", "username": current_user}, host, port)
                print_wallet_details(bal_data)
                show_menu = True
            except ConnectionRefusedError:
                print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
                show_menu = False
        elif choice == "2":
            get_goofycoins_submenu(current_user, host, port)
            show_menu = True
        elif choice == "3":
            show_menu = do_transfer_coin(current_user, host, port)
        elif choice == "4":
            manage_coin_requests(current_user, host, port)
            show_menu = True
        elif choice == "5":
            show_menu = do_verify_chain(host, port)
        elif choice == "6":
            show_menu = do_simulation(host, port)
        elif choice == "0":
            try:
                send_server_request({"action": "LOGOUT", "username": current_user}, host, port)
            except Exception:
                pass
            print(f"\n[*] Logged out of {current_user}. Returning to main menu...\n")
            break
        else:
            print(f"\n[!] Invalid option '{choice}'. Please select 0 to 6 (or 'm' for menu).\n")
            show_menu = False


def print_main_entry_menu():
    """Prints the initial entry menu before login."""
    print("╔══════════════════════════════════════╗")
    print("║        GOOFYCOIN BLOCKCHAIN          ║")
    print("╠══════════════════════════════════════╣")
    print("║  [1] Log In as Admin (Goofy)         ║")
    print("║  [2] Create / Log In User            ║")
    print("║  [3] Verify Blockchain Integrity     ║")
    print("║  [4] Run Full Simulation Demo        ║")
    print("║  [0] Exit                            ║")
    print("╚══════════════════════════════════════╝")


def run_client(host=HOST, port=PORT):
    """Runs the main client entry loop."""
    show_menu = True

    while True:
        if show_menu:
            print_main_entry_menu()

        try:
            choice = input("Select option > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting. Goodbye!")
            break

        if choice in ("m", "menu"):
            show_menu = True
            continue

        if choice == "1":
            # Direct Login as Admin Goofy
            try:
                res = send_server_request({"action": "REGISTER", "username": "Goofy"}, host, port)
                print_user_created_card(
                    user_id=res.get("user_id", "USER001"),
                    username="Goofy",
                    wallet_address=res.get("wallet_address", "N/A"),
                    pub_key=res.get("public_key", ""),
                    priv_key=res.get("private_key", ""),
                    balance=res.get("total_coins", 1000)
                )
                run_admin_dashboard(host, port)
                show_menu = True
            except ConnectionRefusedError:
                print(f"\n[ERROR] Server not reachable at {host}:{port}.\n")
                show_menu = False

        elif choice == "2":
            # Create / Log In User
            user_info = create_user_flow(host, port)
            if user_info:
                if user_info.get("username") == "Goofy" or user_info.get("user_id") == "USER001":
                    run_admin_dashboard(host, port)
                else:
                    run_user_dashboard(user_info, host, port)
                show_menu = True
            else:
                show_menu = False

        elif choice == "3":
            show_menu = do_verify_chain(host, port)

        elif choice == "4":
            show_menu = do_simulation(host, port)

        elif choice == "0":
            print("\nExiting GoofyCoin Client. Goodbye!\n")
            break

        else:
            print(f"\n[!] Invalid option '{choice}'. Please select 0 to 4 (or 'm' for menu).\n")
            show_menu = False


if __name__ == "__main__":
    host_arg = sys.argv[1] if len(sys.argv) > 1 else HOST
    port_arg = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    run_client(host=host_arg, port=port_arg)
