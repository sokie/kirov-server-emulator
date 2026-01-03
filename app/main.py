import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app._version import __version__
from app.config.app_settings import app_config
from app.db.database import create_db_and_tables
from app.rest.routes import router as rest_router
from app.servers.fesl_server import start_fesl_server
from app.servers.gp_server import start_gp_server
from app.servers.natneg_server import start_natneg_server
from app.servers.peerchat_server import start_irc_server
from app.servers.query_master_tcp import start_master_server
from app.servers.query_master_udp import start_heartbeat_server
from app.servers.sessions import SessionManager
from app.soap.service import soap_router
from app.util.logging_helper import setup_logging
from app.util.paths import get_base_path


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("INFO:     Application startup...")

    # Initialize database
    print("INFO:     Initializing database...")
    create_db_and_tables()
    print("INFO:     Database initialized.")

    log_level = getattr(logging, app_config.logging.level.upper(), logging.INFO)
    setup_logging(level=log_level)

    session_manager = SessionManager()

    # Start FESL server
    fesl_host = app_config.fesl.host
    fesl_port = app_config.fesl.port
    print(f"INFO:     Starting FESL server on {fesl_host}:{fesl_port}...")
    fesl_server = await start_fesl_server(fesl_host, fesl_port)
    print(f"INFO:     FESL server is listening on {fesl_host}:{fesl_port}")

    # Start Peerchat IRC server
    irc_host = app_config.irc.host
    irc_port = app_config.irc.port
    print(f"INFO:     Starting Peerchat IRC server on {irc_host}:{irc_port}...")
    irc_server = await start_irc_server(host=irc_host, port=irc_port)
    print(f"INFO:     Peerchat IRC server is listening on {irc_host}:{irc_port}")

    # Start GameSpy Protocol server
    gp_host = app_config.gp.host
    gp_port = app_config.gp.port
    print(f"INFO:     Starting GameSpy server on {gp_host}:{gp_port}...")
    gp_server = await start_gp_server(gp_host, gp_port, session_manager)
    print(f"INFO:     GameSpy server is listening on {gp_host}:{gp_port}")

    # Start NAT Negotiation server
    natneg_transport = None
    if app_config.natneg.enabled:
        natneg_host = app_config.natneg.host
        natneg_port = app_config.natneg.port
        print(f"INFO:     Starting NAT Negotiation server on {natneg_host}:{natneg_port}...")
        natneg_transport, natneg_protocol = await start_natneg_server(host=natneg_host, port=natneg_port)
        print(f"INFO:     NAT Negotiation server is listening on {natneg_host}:{natneg_port}")

    # Start Master Server (GameSpy server/room list queries)
    master_server = None
    heartbeat_transport = None
    if app_config.master.enabled:
        master_host = app_config.master.host
        master_port = app_config.master.port
        master_udp_port = app_config.master.udp_port

        # Start TCP server for queries
        print(f"INFO:     Starting Master Server (TCP) on {master_host}:{master_port}...")
        master_server = await start_master_server(host=master_host, port=master_port)
        print(f"INFO:     Master Server (TCP) is listening on {master_host}:{master_port}")

        # Start UDP server for heartbeats
        print(f"INFO:     Starting Heartbeat Server (UDP) on {master_host}:{master_udp_port}...")
        heartbeat_transport, heartbeat_protocol = await start_heartbeat_server(host=master_host, port=master_udp_port)
        print(f"INFO:     Heartbeat Server (UDP) is listening on {master_host}:{master_udp_port}")

    yield

    # Shutdown - consistent pattern for all servers
    print("INFO:     Application shutdown...")
    servers = [fesl_server, irc_server, gp_server]
    if master_server:
        servers.append(master_server)
    for server in servers:
        server.close()
    await asyncio.gather(*[s.wait_closed() for s in servers])

    # Close UDP transports
    if natneg_transport:
        natneg_transport.close()
    if heartbeat_transport:
        heartbeat_transport.close()


# Create the main FastAPI application
app = FastAPI(
    title="Red Alert 3 LAN Server",
    description="EA server emulator with FESL authentication and Peerchat IRC support.",
    version=__version__,
    lifespan=lifespan,
)

# Mount the REST API router
app.include_router(rest_router, prefix="/api/rest")

# Mount the SOAP router (native FastAPI integration)
app.include_router(soap_router)

# Mount the static files directory
static_path = os.path.join(get_base_path(), "static")
app.mount("/", StaticFiles(directory=static_path), name="static")


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
