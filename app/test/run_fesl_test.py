"""
Standalone FESL server test - starts FESL server and runs authentication flow.
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
from app.raw.fesl_server import FeslServer


# Test user credentials
TEST_EMAIL = "testuser@example.com"
TEST_PASSWORD = "testpass123"
TEST_USERNAME = "testplayer"
FESL_PORT = 18800


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


async def setup_database():
    """Setup database and create test user."""
    print("\n[SETUP] Creating database and test user...")
    SQLModel.metadata.create_all(engine)

    # Try to get existing user first
    from app.db.crud import get_user_by_username_and_password

    session = next(get_session())
    try:
        user = get_user_by_username_and_password(session, TEST_EMAIL, TEST_PASSWORD)
        if user:
            personas = get_personas_for_user(session, user.id)
            print(f"[SETUP] Using existing user: id={user.id}, username={user.username}")
            return user.id, personas[0].id if personas else None

        # User doesn't exist, create new one
        user_data = UserCreate(
            username=TEST_USERNAME,
            password=TEST_PASSWORD,
            email=TEST_EMAIL
        )
        user = create_new_user(session, user_data)
        print(f"[SETUP] Created user: id={user.id}, username={user.username}")

        personas = get_personas_for_user(session, user.id)
        print(f"[SETUP] User has {len(personas)} persona(s): {[p.name for p in personas]}")
        return user.id, personas[0].id if personas else None
    except Exception as e:
        session.rollback()
        print(f"[SETUP] Error: {e}")
        return None, None
    finally:
        session.close()


async def start_fesl_server():
    """Start the FESL server."""
    loop = asyncio.get_running_loop()
    server = await loop.create_server(lambda: FeslServer(), "127.0.0.1", FESL_PORT)
    print(f"[SERVER] FESL server started on port {FESL_PORT}")
    return server


async def run_auth_flow(expected_user_id, expected_persona_id):
    """Run the FESL authentication flow."""
    print("\n" + "="*60)
    print("FESL Live Authentication Flow Test")
    print("="*60)

    # Connect to FESL server
    print(f"\n[CONNECT] Connecting to FESL server at 127.0.0.1:{FESL_PORT}...")
    reader, writer = await asyncio.open_connection('127.0.0.1', FESL_PORT)
    print("[CONNECT] Connected!")

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

        # Read Hello response
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

            # Verify against expected values
            if str(expected_user_id) == user_id:
                print(f"       ✓ userId matches expected ({expected_user_id})")
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

            # Verify against expected persona ID
            if str(expected_persona_id) == new_profile_id:
                print(f"       ✓ profileId matches expected persona ({expected_persona_id})")

            # Verify userId stayed the same
            if str(expected_user_id) == new_user_id:
                print(f"       ✓ userId stayed same after persona selection")

            # Note: userId and profileId might be equal if user.id == persona.id
            if new_user_id != new_profile_id:
                print(f"       ✓ userId != profileId (profileId is now persona ID)")
            else:
                print(f"       ! userId == profileId (IDs happen to match numerically)")

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
                    ticket_user_id, ticket_persona_id, ticket_token = parts
                    print(f"       ✓ Ticket decoded: userId={ticket_user_id}, personaId={ticket_persona_id}")

                    # Verify ticket contains correct IDs
                    if ticket_user_id == str(expected_user_id):
                        print(f"       ✓ Ticket userId matches expected")
                    if ticket_persona_id == str(expected_persona_id):
                        print(f"       ✓ Ticket personaId matches expected")
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
    # Setup database
    user_id, persona_id = await setup_database()
    if not user_id:
        print("[ERROR] Failed to setup test user")
        return 1

    # Start FESL server
    server = await start_fesl_server()

    # Give server a moment to start
    await asyncio.sleep(0.5)

    try:
        # Run auth flow
        success = await run_auth_flow(user_id, persona_id)
        return 0 if success else 1
    finally:
        server.close()
        await server.wait_closed()
        print("[SERVER] FESL server stopped.")


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
