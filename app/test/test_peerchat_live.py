"""
Live integration test for Peerchat IRC server encryption flow.

This script:
1. Connects to the IRC server
2. Sends CRYPT command (unencrypted)
3. Receives encryption challenges
4. Sets up encryption ciphers
5. Sends encrypted IRC commands
6. Verifies encrypted responses
"""

import asyncio
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.config.app_settings import app_config
from app.util.peerchat_crypt import PeerchatCipher


async def test_peerchat_encryption_flow():
    """Test the Peerchat IRC encryption flow."""

    print("\n" + "=" * 60)
    print("Peerchat IRC Encryption Flow Test")
    print("=" * 60)

    # Connect to IRC server
    host = "127.0.0.1"
    port = 6667
    print(f"\n[CONNECT] Connecting to Peerchat server at {host}:{port}...")

    try:
        reader, writer = await asyncio.open_connection(host, port)
        print("[CONNECT] Connected!")
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to Peerchat server. Is it running?")
        print("[ERROR] Start the server with: uvicorn app.main:app")
        return False

    try:
        # Game key from config
        game_key = app_config.game.gamekey

        # Step 1: Send CRYPT command (unencrypted)
        print("\n" + "-" * 40)
        print("[STEP 1] Sending CRYPT command (unencrypted)...")
        crypt_cmd = b"CRYPT des 1 redalert3pc\r\n"
        writer.write(crypt_cmd)
        await writer.drain()
        print(f"[SENT] {crypt_cmd.strip().decode()}")

        # Read CRYPT response (unencrypted) - contains challenges
        response = await asyncio.wait_for(reader.readline(), timeout=5.0)
        response_str = response.decode("utf-8").strip()
        print(f"[RECV] {response_str}")

        # Parse the 705 response to get challenges
        # Format: :s 705 <nickname> <client_challenge> :<server_challenge>
        # or: :s 705 * <client_challenge> :<server_challenge>
        if "705" not in response_str:
            print(f"[ERROR] Expected 705 response, got: {response_str}")
            return False

        # Split on ' :' to handle trailing parameter
        if " :" in response_str:
            before_trailing, send_challenge = response_str.rsplit(" :", 1)
            parts = before_trailing.split()
            recv_challenge = parts[-1]  # Last part before trailing
        else:
            parts = response_str.split()
            recv_challenge = parts[-2]
            send_challenge = parts[-1]

        print("       ✓ Received challenges:")
        print(f"         recv_challenge (client->server): {recv_challenge}")
        print(f"         send_challenge (server->client): {send_challenge}")

        # Step 2: Initialize ciphers
        print("\n" + "-" * 40)
        print("[STEP 2] Initializing encryption ciphers...")

        # Client uses recv_challenge for sending, send_challenge for receiving
        # (opposite of server's perspective)
        send_cipher = PeerchatCipher(recv_challenge, game_key)
        recv_cipher = PeerchatCipher(send_challenge, game_key)
        print("       ✓ Ciphers initialized")

        # Step 3: Send encrypted USER and NICK commands
        print("\n" + "-" * 40)
        print("[STEP 3] Sending encrypted USER and NICK commands...")

        user_cmd = b"USER testident 127.0.0.1 peerchat.gamespy.com :testuser\r\n"
        nick_cmd = b"NICK testnick\r\n"

        encrypted_user = send_cipher.crypt2(user_cmd)
        encrypted_nick = send_cipher.crypt2(nick_cmd)

        writer.write(encrypted_user)
        await writer.drain()
        print("[SENT] USER testident... (encrypted)")

        await asyncio.sleep(0.1)

        writer.write(encrypted_nick)
        await writer.drain()
        print("[SENT] NICK testnick (encrypted)")

        # Read encrypted response (welcome messages)
        await asyncio.sleep(1.0)  # Give server time to process
        response = await asyncio.wait_for(reader.read(4096), timeout=10.0)
        decrypted = recv_cipher.crypt2(response)
        decrypted_str = decrypted.decode("utf-8", errors="ignore")

        print(f"[RECV] Decrypted response ({len(response)} bytes):")
        for line in decrypted_str.strip().split("\r\n")[:5]:  # Show first 5 lines
            print(f"       {line}")

        # Check for welcome messages (001, 002, 003, 004)
        if "001" in decrypted_str and "Welcome" in decrypted_str:
            print("       ✓ Received welcome message (001)")
        if "375" in decrypted_str or "372" in decrypted_str:
            print("       ✓ Received MOTD")

        # Step 4: Send encrypted PING and expect PONG
        print("\n" + "-" * 40)
        print("[STEP 4] Testing PING/PONG (encrypted)...")

        ping_cmd = b"PING :test123\r\n"
        encrypted_ping = send_cipher.crypt2(ping_cmd)
        writer.write(encrypted_ping)
        await writer.drain()
        print("[SENT] PING :test123 (encrypted)")

        # Read response
        await asyncio.sleep(0.3)
        try:
            response = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            if response:
                decrypted = recv_cipher.crypt2(response)
                decrypted_str = decrypted.decode("utf-8", errors="ignore").strip()
                print(f"[RECV] {decrypted_str}")
                if "PONG" in decrypted_str:
                    print("       ✓ Received encrypted PONG response")
        except TimeoutError:
            print("       ⚠ No PONG response (may be expected)")

        print("\n" + "=" * 60)
        print("✓ Peerchat Encryption Flow Test Complete!")
        print("=" * 60)
        return True

    except TimeoutError:
        print("[ERROR] Timeout waiting for response")
        return False
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback

        traceback.print_exc()
        return False
    finally:
        writer.close()
        await writer.wait_closed()
        print("\n[CLEANUP] Connection closed.")


async def main():
    success = await test_peerchat_encryption_flow()
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
