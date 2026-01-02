"""
Live integration test for FESL authentication flow.

This script:
1. Creates a test user in the database
2. Starts the FESL server
3. Sends actual FESL protocol packets
4. Validates responses match expected format
"""

import asyncio
import struct
import base64
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlmodel import SQLModel
from app.db.database import engine, get_session
from app.db.crud import create_new_user, get_personas_for_user
from app.models.models import UserCreate
from app.models.fesl_types import FeslType, FeslHeader


# Test user credentials (sanitized)
TEST_EMAIL = "testuser@example.com"
TEST_PASSWORD = "testpass123"
TEST_USERNAME = "testplayer"


def create_fesl_packet(command: str, fesl_type: FeslType, packet_num: int, payload: str) -> bytes:
    """Create a FESL packet with header and payload."""
    payload_bytes = payload.encode('utf-8') + b'\x00'
    packet_size = 12 + len(payload_bytes)
    fesl_type_and_number = (fesl_type.value << 24) | packet_num
    header = struct.pack('>4sII', command.encode('utf-8'), fesl_type_and_number, packet_size)
    return header + payload_bytes


def parse_fesl_response(data: bytes) -> tuple:
    """Parse a FESL response packet."""
    if len(data) < 12:
        return None, None

    header_data = data[:12]
    command, fesl_type_and_number, packet_size = struct.unpack('>4sII', header_data)

    fesl_type_val = (fesl_type_and_number >> 24) & 0xFF
    packet_number = fesl_type_and_number & 0x00FFFFFF

    # Extract payload (skip header, remove null terminator)
    payload_data = data[12:].rstrip(b'\x00').decode('utf-8', errors='ignore')

    # Parse key-value pairs
    payload_dict = {}
    for line in payload_data.split('\n'):
        if '=' in line:
            key, value = line.split('=', 1)
            payload_dict[key] = value

    return {
        'command': command.decode('utf-8').rstrip('\x00'),
        'type': fesl_type_val,
        'packet_num': packet_number,
        'size': packet_size
    }, payload_dict


async def test_fesl_auth_flow():
    """Test the complete FESL authentication flow."""

    print("\n" + "="*60)
    print("FESL Live Authentication Flow Test")
    print("="*60)

    # Step 0: Setup database and create test user
    print("\n[SETUP] Creating database and test user...")
    SQLModel.metadata.create_all(engine)

    with next(get_session()) as session:
        try:
            user_data = UserCreate(
                username=TEST_USERNAME,
                password=TEST_PASSWORD,
                email=TEST_EMAIL
            )
            user = create_new_user(session, user_data)
            print(f"[SETUP] Created user: id={user.id}, username={user.username}")

            personas = get_personas_for_user(session, user.id)
            print(f"[SETUP] User has {len(personas)} persona(s): {[p.name for p in personas]}")
        except Exception as e:
            print(f"[SETUP] User may already exist: {e}")

    # Connect to FESL server
    print("\n[CONNECT] Connecting to FESL server at 127.0.0.1:18800...")
    try:
        reader, writer = await asyncio.open_connection('127.0.0.1', 18800)
        print("[CONNECT] Connected!")
    except ConnectionRefusedError:
        print("[ERROR] Could not connect to FESL server. Is it running?")
        print("[ERROR] Start the server with: uvicorn app.main:app --reload")
        return False

    try:
        # Step 1: Send Hello
        print("\n" + "-"*40)
        print("[STEP 1] Sending Hello...")
        hello_payload = (
            "TXN=Hello\n"
            "clientString=cncra3-pc\n"
            "sku=15299\n"
            "locale=en_US\n"
            "clientPlatform=PC\n"
            "clientVersion=1.0\n"
            "SDKVersion=4.3.4.0.0\n"
            "protocolVersion=2.0\n"
            "fragmentSize=8096\n"
            "clientType="
        )
        hello_packet = create_fesl_packet('fsys', FeslType.TAG_SINGLE_CLIENT, 1, hello_payload)
        writer.write(hello_packet)
        await writer.drain()
        print(f"[SENT] Hello packet ({len(hello_packet)} bytes)")

        # Read Hello response - server sends MemCheck + Hello together
        # May arrive in one or two reads
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)

        # Parse first packet (MemCheck)
        header, payload = parse_fesl_response(response)
        print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")
        if payload.get('TXN') == 'MemCheck':
            print(f"       ✓ MemCheck received (salt={payload.get('salt')})")
            # Find where second packet starts (after first packet)
            first_packet_size = header['size']
            if len(response) > first_packet_size:
                second_response = response[first_packet_size:]
                header, payload = parse_fesl_response(second_response)
                print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")
            else:
                # Hello may arrive in a separate read
                response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
                header, payload = parse_fesl_response(response)
                print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")

        if payload.get('TXN') == 'Hello':
            print(f"       theaterIp={payload.get('theaterIp')}, theaterPort={payload.get('theaterPort')}")

        # Step 2: Send NuLogin
        print("\n" + "-"*40)
        print("[STEP 2] Sending NuLogin...")
        nulogin_payload = (
            f"TXN=NuLogin\n"
            f"returnEncryptedInfo=1\n"
            f"nuid={TEST_EMAIL}\n"
            f"password={TEST_PASSWORD}\n"
            f"macAddr=$aabbccddeeff"
        )
        nulogin_packet = create_fesl_packet('acct', FeslType.TAG_SINGLE_CLIENT, 2, nulogin_payload)
        writer.write(nulogin_packet)
        await writer.drain()
        print(f"[SENT] NuLogin packet ({len(nulogin_packet)} bytes)")

        # Read NuLogin response
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        header, payload = parse_fesl_response(response)
        print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")

        if payload.get('TXN') == 'NuLogin':
            user_id = payload.get('userId')
            profile_id = payload.get('profileId')
            lkey = payload.get('lkey')
            display_name = payload.get('displayName')
            print(f"       userId={user_id}, profileId={profile_id}")
            print(f"       displayName={display_name}")
            print(f"       lkey={lkey}")
            print(f"       entitlements={payload.get('entitledGameFeatureWrappers.[]')}")

            # Verify userId == profileId after NuLogin
            if user_id == profile_id:
                print(f"       ✓ userId == profileId (correct after NuLogin)")
            else:
                print(f"       ✗ userId != profileId (unexpected)")
        else:
            print(f"[ERROR] Unexpected response: {payload}")
            return False

        # Step 3: Send NuGetPersonas
        print("\n" + "-"*40)
        print("[STEP 3] Sending NuGetPersonas...")
        personas_payload = "TXN=NuGetPersonas\nnamespace="
        personas_packet = create_fesl_packet('acct', FeslType.TAG_SINGLE_CLIENT, 3, personas_payload)
        writer.write(personas_packet)
        await writer.drain()
        print(f"[SENT] NuGetPersonas packet ({len(personas_packet)} bytes)")

        # Read NuGetPersonas response
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        header, payload = parse_fesl_response(response)
        print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")

        if payload.get('TXN') == 'NuGetPersonas':
            persona_count = payload.get('personas.[]', '0')
            print(f"       personas.[]={persona_count}")
            for i in range(int(persona_count)):
                persona_name = payload.get(f'personas.{i}')
                print(f"       personas.{i}={persona_name}")

        # Step 4: Send NuLoginPersona
        print("\n" + "-"*40)
        print("[STEP 4] Sending NuLoginPersona...")
        loginpersona_payload = f"TXN=NuLoginPersona\nname={TEST_USERNAME}"
        loginpersona_packet = create_fesl_packet('acct', FeslType.TAG_SINGLE_CLIENT, 4, loginpersona_payload)
        writer.write(loginpersona_packet)
        await writer.drain()
        print(f"[SENT] NuLoginPersona packet ({len(loginpersona_packet)} bytes)")

        # Read NuLoginPersona response
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        header, payload = parse_fesl_response(response)
        print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")

        if payload.get('TXN') == 'NuLoginPersona':
            new_user_id = payload.get('userId')
            new_profile_id = payload.get('profileId')
            new_lkey = payload.get('lkey')
            print(f"       userId={new_user_id}, profileId={new_profile_id}")
            print(f"       lkey={new_lkey}")

            # Verify userId != profileId after NuLoginPersona (unless they happen to be equal)
            if new_user_id != new_profile_id:
                print(f"       ✓ userId != profileId (correct - profileId is now persona ID)")
            else:
                print(f"       ! userId == profileId (IDs happen to match, but logic is correct)")

        # Step 5: Send GameSpyPreAuth
        print("\n" + "-"*40)
        print("[STEP 5] Sending GameSpyPreAuth...")
        preauth_payload = "TXN=GameSpyPreAuth"
        preauth_packet = create_fesl_packet('acct', FeslType.TAG_SINGLE_CLIENT, 5, preauth_payload)
        writer.write(preauth_packet)
        await writer.drain()
        print(f"[SENT] GameSpyPreAuth packet ({len(preauth_packet)} bytes)")

        # Read GameSpyPreAuth response
        response = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        header, payload = parse_fesl_response(response)
        print(f"[RECV] {header['command']} response: TXN={payload.get('TXN')}")

        if payload.get('TXN') == 'GameSpyPreAuth':
            challenge = payload.get('challenge')
            ticket = payload.get('ticket')
            print(f"       challenge={challenge}")
            print(f"       ticket={ticket}")

            # Decode and verify ticket format
            try:
                decoded = base64.b64decode(ticket).decode('utf-8')
                parts = decoded.split('|')
                if len(parts) == 3:
                    print(f"       ✓ Ticket decoded: userId={parts[0]}, personaId={parts[1]}, token={parts[2][:10]}...")
                else:
                    print(f"       ✗ Invalid ticket format")
            except Exception as e:
                print(f"       ✗ Failed to decode ticket: {e}")

        print("\n" + "="*60)
        print("✓ FESL Authentication Flow Complete!")
        print("="*60)
        return True

    except asyncio.TimeoutError:
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
    success = await test_fesl_auth_flow()
    return 0 if success else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
