import struct
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


class GameType:
    CNC3 = "cnc3"
    KANESWRATH = "cnc3ep1"
    RA3 = "cncra3"


# clientString -> GameType
CLIENT_STRING_MAP = {
    "cnc3-pc": GameType.CNC3,
    "cnc3-ep1-pc": GameType.KANESWRATH,
    "cncra3-pc": GameType.RA3,
}

# GameType -> subDomain for Hello response
SUBDOMAIN_MAP = {
    GameType.CNC3: "cnc3",
    GameType.KANESWRATH: "cnc3ep1",
    GameType.RA3: "CNCRA3",
}

# GameType -> default gameFeatureId for entitlements
GAME_FEATURE_ID_MAP = {
    GameType.CNC3: 2588,
    GameType.KANESWRATH: None,  # TODO: find KW gameFeatureId
    GameType.RA3: 6014,
}

# GameType -> gamekeys config dict key
GAMEKEY_MAP = {
    GameType.CNC3: "cnc3pc",
    GameType.KANESWRATH: "cnc3ep1pc",
    GameType.RA3: "cncra3pc",
}

# GameSpy game name -> gamekeys config dict key
# These names are used by peerchat (CRYPT), GP server (gamename), gamestats, and master server
GAMESPY_GAME_KEY_MAP = {
    "redalert3pc": "cncra3pc",
    "redalert3ps3": "cncra3pc",
    "cncra3pc": "cncra3pc",
    "cc3": "cnc3pc",
    "cnc3pc": "cnc3pc",
    "cc3xp1": "cnc3ep1pc",
    "cnc3ep1pc": "cnc3ep1pc",
}


class FeslError(IntEnum):
    """
    FESL error codes based on OpenSpy implementation.
    See: https://github.com/openspy/openspy-core/blob/master/code/FESL/server/FESLPeer.h
    """

    NO_ERROR = 0
    NOT_AUTHENTICATED = 20  # User not authenticated yet
    CUSTOM = 21
    SYSTEM_ERROR = 99
    ACCOUNT_NOT_FOUND = 101
    ACCOUNT_DISABLED = 102
    ACCOUNT_BANNED = 103
    ACCOUNT_NOT_CONFIRMED = 105
    TOO_MANY_LOGIN_ATTEMPTS = 121
    AUTH_FAILURE = 122  # Password mismatch
    GAME_NOT_REGISTERED = 123
    ACCOUNT_EXISTS = 160


@dataclass
class FeslErrorResponse:
    """
    FESL error response model.
    Sent when a command fails (e.g., authentication failure).
    """

    txn: str
    errorCode: FeslError
    errorContainer: str = "[]"

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"errorContainer={self.errorContainer}")
        output_lines.append(f"errorCode={self.errorCode.value}")
        return "\n".join(output_lines)


@dataclass
class FeslBaseModel:
    """Base class for data models to ensure a consistent interface."""

    txn: str

    def to_key_value_string(self):
        pass


@dataclass
class HelloClient(FeslBaseModel):
    clientString: str = None
    sku: int = None
    locale: str = None
    clientPlatform: str = None
    clientVersion: str = None
    SDKVersion: str = None
    protocolVersion: str = None
    fragmentSize: int = None
    clientType: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HelloClient":
        return cls(
            txn=data.get("TXN"),
            clientString=data.get("clientString"),
            sku=data.get("sku"),
            locale=data.get("locale"),
            clientPlatform=data.get("clientPlatform"),
            clientVersion=data.get("clientVersion"),
            SDKVersion=data.get("SDKVersion"),
            protocolVersion=data.get("protocolVersion"),
            fragmentSize=data.get("fragmentSize"),
            clientType=data.get("clientType"),
        )

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"clientString={self.clientString}")
        output_lines.append(f"sku={self.sku}")
        output_lines.append(f"locale={self.locale}")
        output_lines.append(f"clientPlatform={self.clientPlatform}")
        output_lines.append(f"clientVersion={self.clientVersion}")
        output_lines.append(f"SDKVersion={self.SDKVersion}")
        output_lines.append(f"protocolVersion={self.protocolVersion}")
        output_lines.append(f"fragmentSize={self.fragmentSize}")
        output_lines.append(f"clientType={self.clientType}")

        return "\n".join(output_lines)


@dataclass
class DomainPartition:
    domain: str
    subDomain: str


@dataclass
class HelloServer(FeslBaseModel):
    theaterPort: int
    messengerIp: str
    messengerPort: int
    activityTimeoutSecs: int
    curTime: str
    theaterIp: str
    domainPartition: DomainPartition

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HelloServer":
        domainPartition = DomainPartition(
            domain=data.get("domainPartition.domain"), subDomain=data.get("domainPartition.subDomain")
        )

        return cls(
            txn=data.get("TXN"),
            theaterPort=data.get("theaterPort"),
            messengerIp=data.get("messengerIp"),
            messengerPort=data.get("messengerPort"),
            activityTimeoutSecs=data.get("activityTimeoutSecs"),
            curTime=data.get("curTime"),
            theaterIp=data.get("theaterIp"),
            domainPartition=domainPartition,
        )

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"theaterPort={self.theaterPort}")
        output_lines.append(f"messengerIp={self.messengerIp}")
        output_lines.append(f"messengerPort={self.messengerPort}")
        output_lines.append(f"activityTimeoutSecs={self.activityTimeoutSecs}")
        output_lines.append(f'curTime="{self.curTime}"')
        output_lines.append(f"theaterIp={self.theaterIp}")
        output_lines.append(f"domainPartition.domain={self.domainPartition.domain}")
        output_lines.append(f"domainPartition.subDomain={self.domainPartition.subDomain}")

        return "\n".join(output_lines)


@dataclass
class MemcheckServer(FeslBaseModel):
    type: int = None
    salt: int = None
    memcheck: int = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemcheckServer":
        return cls(txn=data.get("TXN"), type=data.get("type"), salt=data.get("salt"), memcheck=data.get("memcheck"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"type={self.type}")
        output_lines.append(f"salt={self.salt}")
        # not handled more for now1
        output_lines.append("memcheck.[]=0")

        return "\n".join(output_lines)


@dataclass
class MemcheckClient(FeslBaseModel):
    result: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemcheckClient":
        return cls(txn=data.get("TXN"), result=data.get("result"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"result={self.result}")

        return "\n".join(output_lines)


@dataclass
class NuLoginClient(FeslBaseModel):
    returnEncryptedInfo: int = None
    nuid: str = None
    password: str = None
    macAddr: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuLoginClient":
        return cls(
            txn=data.get("TXN"), nuid=data.get("nuid"), password=data.get("password"), macAddr=data.get("macAddr")
        )

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"nuid={self.nuid}")
        output_lines.append(f"password={self.password}")
        output_lines.append(f"macAddr={self.macAddr}")

        return "\n".join(output_lines)


@dataclass
class LoginClient(FeslBaseModel):
    """Login model for CNC3/KW - uses 'name' instead of 'nuid'."""

    name: str = None
    password: str = None
    macAddr: str = None
    returnEncryptedInfo: int = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LoginClient":
        return cls(
            txn=data.get("TXN"),
            name=data.get("name"),
            password=data.get("password"),
            macAddr=data.get("macAddr"),
        )

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"name={self.name}")
        output_lines.append(f"password={self.password}")
        output_lines.append(f"macAddr={self.macAddr}")

        return "\n".join(output_lines)


@dataclass
class EntitledGameFeatureWrapper:
    """
    Represents a single entitled game feature.
    """

    gameFeatureId: int
    entitlementExpirationDays: int = -1
    entitlementExpirationDate: str | None = ""
    message: str | None = ""
    status: int = 0  # 0 = active


@dataclass
class NuLoginServer(FeslBaseModel):
    nuid: int = None
    profileId: int = None
    userId: int = None
    displayName: str = None
    lkey: str = None
    """
    Contains a list of EntitledGameFeatureWrapper objects and can generate
    the key-value string format.
    """
    entitledGameFeatureWrappers: list[EntitledGameFeatureWrapper] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuLoginServer":
        return cls(
            txn=data.get("TXN"),
            nuid=data.get("nuid"),
            profileId=data.get("profileId"),
            userId=data.get("userId"),
            displayName=data.get("displayName"),
            lkey=data.get("lkey"),
        )

    def to_key_value_string(self) -> str:
        """
        Generates the key-value string from the list of feature wrappers.

        Returns:
            A string in the specified key-value format.
        """
        feature_count = len(self.entitledGameFeatureWrappers)

        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"nuid={self.nuid}")
        output_lines.append(f"profileId={self.profileId}")
        output_lines.append(f"userId={self.userId}")
        output_lines.append(f"displayName={self.displayName}")
        output_lines.append(f"lkey={self.lkey}")

        output_lines.append(f"entitledGameFeatureWrappers.[]={feature_count}")

        for i, wrapper in enumerate(self.entitledGameFeatureWrappers):
            # Construct the base key for the current wrapper
            base_key = f"entitledGameFeatureWrappers.{i}"

            # Append each field to the output lines
            output_lines.append(f"{base_key}.entitlementExpirationDate={wrapper.entitlementExpirationDate or ''}")
            output_lines.append(f"{base_key}.entitlementExpirationDays={wrapper.entitlementExpirationDays}")
            output_lines.append(f"{base_key}.gameFeatureId={wrapper.gameFeatureId}")
            output_lines.append(f"{base_key}.message={wrapper.message or ''}")
            output_lines.append(f"{base_key}.status={wrapper.status}")

        return "\n".join(output_lines)


@dataclass
class NuGetPersonasClient(FeslBaseModel):
    namespace: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuGetPersonasClient":
        return cls(txn=data.get("TXN"), namespace=data.get("namespace"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"namespace={self.namespace}")

        return "\n".join(output_lines)


@dataclass
class NuGetPersonasServer(FeslBaseModel):
    personas: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuGetPersonasServer":
        return cls(txn=data.get("TXN"))

    def to_key_value_string(self) -> str:
        personas_count = len(self.personas)

        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"personas.[]={personas_count}")

        for i, persona in enumerate(self.personas):
            # Append each field to the output lines
            output_lines.append(f"personas.{i}={persona or ''}")

        return "\n".join(output_lines)


@dataclass
class GetSubAccountsClient(FeslBaseModel):
    """CNC3/KW equivalent of NuGetPersonas - no extra fields."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GetSubAccountsClient":
        return cls(txn=data.get("TXN"))

    def to_key_value_string(self) -> str:
        return f"TXN={self.txn}"


@dataclass
class GetSubAccountsServer(FeslBaseModel):
    """CNC3/KW equivalent of NuGetPersonasServer - uses 'subAccounts' instead of 'personas'."""

    subAccounts: list[str] = field(default_factory=list)

    def to_key_value_string(self) -> str:
        count = len(self.subAccounts)

        output_lines = [f"TXN={self.txn}"]

        output_lines.append(f"subAccounts.[]={count}")

        for i, name in enumerate(self.subAccounts):
            output_lines.append(f"subAccounts.{i}={name or ''}")

        return "\n".join(output_lines)


@dataclass
class AddSubAccountClient(FeslBaseModel):
    """CNC3/KW equivalent of NuAddPersona."""

    name: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AddSubAccountClient":
        return cls(txn=data.get("TXN"), name=data.get("name"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"name={self.name}")
        return "\n".join(output_lines)


@dataclass
class LoginSubAccountClient(FeslBaseModel):
    """CNC3/KW equivalent of NuLoginPersona."""

    name: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LoginSubAccountClient":
        return cls(txn=data.get("TXN"), name=data.get("name"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"name={self.name}")
        return "\n".join(output_lines)


@dataclass
class NuLoginPersonaClient(FeslBaseModel):
    name: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuLoginPersonaClient":
        return cls(txn=data.get("TXN"), name=data.get("name"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"name={self.name}")

        return "\n".join(output_lines)


@dataclass
class NuLoginPersonaServer(FeslBaseModel):
    userId: int = None
    lkey: str = None
    profileId: int = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuLoginPersonaServer":
        return cls(
            txn=data.get("TXN"), userId=data.get("userId"), lkey=data.get("lkey"), profileId=data.get("profileId")
        )

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"userId={self.userId}")
        output_lines.append(f"lkey={self.lkey}")
        output_lines.append(f"profileId={self.profileId}")

        return "\n".join(output_lines)


@dataclass
class GameSpyPreAuthClient(FeslBaseModel):
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GameSpyPreAuthClient":
        return cls(
            txn=data.get("TXN"),
        )

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        return "\n".join(output_lines)


@dataclass
class GameSpyPreAuthServer(FeslBaseModel):
    challenge: str = None
    ticket: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "GameSpyPreAuthServer":
        return cls(txn=data.get("TXN"), challenge=data.get("challenge"), ticket=data.get("ticket"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"challenge={self.challenge}")
        output_lines.append(f"ticket={self.ticket}")

        return "\n".join(output_lines)


@dataclass
class NuAddPersonaClient(FeslBaseModel):
    name: str = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuAddPersonaClient":
        return cls(txn=data.get("TXN"), name=data.get("name"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]
        output_lines.append(f"name={self.name}")

        return "\n".join(output_lines)


@dataclass
class NuAddPersonaServer(FeslBaseModel):
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NuAddPersonaServer":
        return cls(txn=data.get("TXN"))

    def to_key_value_string(self) -> str:
        output_lines = [f"TXN={self.txn}"]

        return "\n".join(output_lines)


class FeslType(Enum):
    """
    Enumeration for FeslType as per the data specification.
    These values identify the nature of the FESL packet.
    """

    TAG_SINGLE_CLIENT = 0xC0
    TAG_SINGLE_SERVER = 0x80
    TAG_MULTI_CLIENT = 0xF0
    TAG_MULTI_SERVER = 0xB0
    UNKNOWN = 0xFF


class FeslHeader:
    """
    Represents the FeslHeader structure and provides methods for parsing.
    The header is a fixed 12-byte structure at the beginning of the packet.
    """

    HEADER_FORMAT = ">4sII"  # Format string for struct unpacking:
    # >: big-endian
    # 4s: 4-byte string for FeslCommand
    # I: 4-byte unsigned int for FeslTypeAndNumber
    # I: 4-byte unsigned int for PaketSize
    HEADER_SIZE = 12

    def __init__(self, fesl_command, fesl_type, packet_number, packet_size):
        """Initializes the FeslHeader object with parsed data."""
        self.fesl_command = fesl_command
        self.fesl_type = fesl_type
        self.packet_number = packet_number
        self.packet_size = packet_size

    @classmethod
    def from_bytes(cls, data):
        """
        Parses a byte array to extract the FeslHeader.

        Args:
            data (bytes): The byte array containing the header.

        Returns:
            A tuple containing the FeslHeader object and the starting index of the data payload,
            or (None, -1) if the header cannot be parsed.
        """
        if len(data) < cls.HEADER_SIZE:
            print("Error: Data is too short to contain a FeslHeader.")
            return None, -1

        header_data = data[: cls.HEADER_SIZE]
        try:
            fesl_command, fesl_type_and_number, packet_size = struct.unpack(cls.HEADER_FORMAT, header_data)
        except struct.error as e:
            print(f"Error unpacking header: {e}")
            return None, -1

        # Extract FeslType and PacketNumber from the combined 4-byte field
        fesl_type_val = (fesl_type_and_number >> 24) & 0xFF
        packet_number = fesl_type_and_number & 0x00FFFFFF

        try:
            fesl_type = FeslType(fesl_type_val)
        except ValueError:
            print(f"Warning: Unknown FeslType value: {hex(fesl_type_val)}")
            fesl_type = FeslType.UNKNOWN

        # The packet size in the header includes the 12-byte header itself.
        # The data size is therefore packet_size - 12.
        expected_data_size = packet_size - cls.HEADER_SIZE

        return cls(fesl_command.decode("utf-8", "ignore"), fesl_type, packet_number, packet_size), expected_data_size

    def __repr__(self):
        """Provides a developer-friendly string representation of the header."""
        return (
            f"FeslHeader(\n"
            f"  FeslCommand: '{self.fesl_command}',\n"
            f"  FeslType: {self.fesl_type.name} ({hex(self.fesl_type.value)}),\n"
            f"  PacketNumber: {self.packet_number},\n"
            f"  PacketSize: {self.packet_size}\n"
            f")"
        )


# 1. Define a ContextVar
client_data_var = ContextVar("client_data", default={})
