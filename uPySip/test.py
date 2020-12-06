import os
import md5

def _randomChr(size):
    ret = ""
    a = 0
    while a < size:
        b = os.urandom(10)[5]

        if (bytes([b]).isalpha()):
            ret = '{}{}'.format(ret, chr(b))
            a = a+1
    return ret

class User:
    """Base User Class."""

    telNr = None
    agent = None
    cSeq = 0
    callId = None
    tagTo = ""
    tagFrom = _randomChr(30)

class UserB(User):
    toB = None
    viaB = None
    fromB = None
    sdp_o = None

class Auth:
    __RN = '\r\n'
    user = "relleum"
    pwd = "jutkk7x1"
    realm = "Home"
    types = "REGISTER"
    nonce = "535a8a2bb603502035ed0cbb"
    qop = "auth"

    def __getUri(self, userB: UserB):
        if userB.telNr is None:
            return userB.agent
        return '{}@{}'.format(userB.telNr, userB.agent)

    def __getAuth(self, userB: UserB):
        a1 = '{}:{}:{}'.format(self.user, self.realm, self.pwd)
        ha1 = md5.md5(a1.encode()).hexdigest()
        a2 = '{}:sip:{}'.format(self.types, self.__getUri(userB))
        ha2 = md5.md5(a2.encode()).hexdigest()
        a3 = '{}:{}:{:0>8}:{}:{}:{}'.format(
            ha1, self.nonce, self.nonceCount, self.cnonce, self.qop, ha2)
        return md5.md5(a3.encode()).hexdigest()

    def getAuthorization(self, userB: UserB) -> str:
        """function getAuthorization
        Args:
            userB (UserB): UserB with telNr and agent

        Returns:
            str: Sip Line for Authorization
        """
        self.nonceCount = 1
        self.cnonce = md5.md5('das ist ein Chaos'.encode()).hexdigest()
        response = self.__getAuth(userB)
        ret = 'Authorization: Digest username="{}"'.format(self.user)
        ret = '{},realm="{}"'.format(ret, self.realm)
        ret = '{},nonce="{}"'.format(ret, self.nonce)
        ret = '{},opaque="",uri="sip:{}"'.format(ret, self.__getUri(userB))
        ret = '{},cnonce="{}"'.format(ret, self.cnonce)
        ret = '{},nc={:0>8}'.format(ret, self.nonceCount)
        ret = '{},algorithm=MD5,qop="auth",response="{}"{}'.format(
            ret, response, self.__RN)
        return ret

user =UserB()
user.agent='192.168.1.1'
aut=Auth()
k=aut.getAuthorization(user)
print(k)

