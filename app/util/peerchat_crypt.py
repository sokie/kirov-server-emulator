import random
from array import array


class PeerchatCipherFactory:
    def __init__(self, gamekey):
        self.gamekey = gamekey

    def getCipher(self):
        return PeerchatCipher(PeerchatCipher.makeChallenge(), self.gamekey)


class PeerchatCipher:
    @staticmethod
    def makeChallenge():
        ## from ';' to '~' -- this is pretty close to exact range.
        ## ':' at the beginning is def. not included (IRC significance)
        alphabet = "".join(chr(i) for i in range(ord(";"), ord("~")))
        return "".join(random.choice(alphabet) for _ in range(16))

    def __init__(self, challenge, gamekey):
        self.challenge = challenge
        self.pc1 = 0
        self.pc2 = 0

        gamekey = [ord(x) for x in gamekey]
        chall = [ord(challenge[i]) ^ gamekey[i % len(gamekey)] for i in range(len(challenge))]

        self.table = list(reversed(range(256)))
        # scramble up the table based on challenge
        tmp = 0
        for i in range(len(self.table)):
            tmp = (tmp + chall[i % len(chall)] + self.table[i]) & 0xFF

            # now just swap
            tmp2 = self.table[tmp]
            self.table[tmp] = self.table[i]
            self.table[i] = tmp2

    def crypt(self, data):
        outdata = array("B")

        for datum in data:
            self.pc1 = (self.pc1 + 1) & 0xFF
            tmp = self.table[self.pc1]
            self.pc2 = (self.pc2 + tmp) & 0xFF
            self.table[self.pc1] = self.table[self.pc2]
            self.table[self.pc2] = tmp
            tmp = (tmp + self.table[self.pc1]) & 0xFF
            outdata.append(ord(datum) ^ self.table[tmp])

        return outdata.tostring()

    def crypt2(self, data):
        outdata = bytearray()

        for datum in data:
            self.pc1 = (self.pc1 + 1) & 0xFF
            tmp = self.table[self.pc1]
            self.pc2 = (self.pc2 + tmp) & 0xFF
            self.table[self.pc1] = self.table[self.pc2]
            self.table[self.pc2] = tmp
            tmp = (tmp + self.table[self.pc1]) & 0xFF
            outdata.append(datum ^ self.table[tmp])

        return outdata


# --- For unit testing ---
if __name__ == "__main__":
    from app.config.app_settings import app_config

    game_key = app_config.game.gamekey

    client_challenge = "bUjvfmi]RSITUbC?"
    server_challenge = "p^uHZUJDnDAhvOUP"
    client_cipher = PeerchatCipher(client_challenge, game_key)
    server_cipher = PeerchatCipher(server_challenge, game_key)
