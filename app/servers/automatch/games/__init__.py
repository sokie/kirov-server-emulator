"""Game factory registry for automatch bots."""

from app.servers.automatch.games.generals import GeneralsGameFactory
from app.servers.automatch.games.ra3 import RA3GameFactory

ALL_GAME_FACTORIES = [RA3GameFactory(), GeneralsGameFactory()]
