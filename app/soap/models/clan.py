"""
Pydantic-XML models for Clan Service.

Endpoint: /clans/ClanActions.asmx/ClanInfoByProfileID

Note: This endpoint returns plain XML (not SOAP-wrapped).
"""

from pydantic_xml import BaseXmlModel, attr, element

CLAN_NS = "http://gamespy.net"


class ClanResult(BaseXmlModel, tag="result"):
    """Result element containing status text and code."""

    result_text: str = element(tag="resultText")
    result_value: int = element(tag="resultValue")

    @classmethod
    def success(cls) -> "ClanResult":
        """Create a success result."""
        return cls(result_text="None: No error", result_value=0)

    @classmethod
    def not_member(cls) -> "ClanResult":
        """Create a not-member error result."""
        return cls(result_text="NotMember: Specified profileid is not a member", result_value=-305)


class ClanMember(BaseXmlModel, tag="Member"):
    """Member element with rank attribute."""

    rank: int = attr(name="rank", default=0)


class ClanElement(BaseXmlModel, tag="clan"):
    """Clan element with attributes for clan info."""

    clanid: int = attr(name="clanid")
    clantag: str = attr(name="clantag")
    clanname: str = attr(name="clanname")
    arena_team_id: int = attr(name="ArenaTeamId", default=0)
    arena_member_id: int = attr(name="ArenaMemberId")
    picid: int = attr(name="picid", default=0)
    member: ClanMember = element(tag="Member")


class ClanInfoResponse(BaseXmlModel, tag="ClanInfo"):
    """
    Response model for ClanInfoByProfileID when the player is in a clan.

    Returns clan info with member details.
    """

    result: ClanResult = element(tag="result")
    asof: str = element(tag="asof")
    clan: ClanElement = element(tag="clan")

    @classmethod
    def for_member(
        cls,
        clan_id: int,
        clan_tag: str,
        clan_name: str,
        member_id: int,
        member_rank: int,
        asof: str,
    ) -> "ClanInfoResponse":
        """Create a response for a clan member."""
        return cls(
            result=ClanResult.success(),
            asof=asof,
            clan=ClanElement(
                clanid=clan_id,
                clantag=clan_tag,
                clanname=clan_name,
                arena_team_id=clan_id,
                arena_member_id=member_id,
                member=ClanMember(rank=member_rank),
            ),
        )


class NotMemberResponse(BaseXmlModel, tag="result"):
    """
    Response model for ClanInfoByProfileID when the player is not in a clan.

    This is a standalone <result> element (not wrapped in ClanInfo).
    """

    result_text: str = element(tag="resultText")
    result_value: int = element(tag="resultValue")

    @classmethod
    def create(cls) -> "NotMemberResponse":
        """Create the standard not-member response."""
        return cls(
            result_text="NotMember: Specified profileid is not a member",
            result_value=-305,
        )
