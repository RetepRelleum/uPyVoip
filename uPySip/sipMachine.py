
import _thread
import uPySip.md5
import uPySip.tools
import utime
import socket
import select
import uPySip.aLaw
import uPySip.DTMF 


class User:
    telNr = None
    agent = None
    cSeq = 0
    callId = None
    tagTo = ""
    tagFrom = uPySip.tools.randomChr(30)


class UserA(User):
    userClient = None
    branch = 'z9hG4bK-{}'.format(uPySip.tools.randomChr(30))


class UserB(User):
    toB = None
    viaB = None
    fromB = None
    sdp_o = None


class Auth:
    __RN = '\r\n'
    def __init__(self):
        self.logger = uPySip.tools.getLogger(__name__)
    user = None
    pwd = None
    realm = None
    types = None
    nonce = None
    qop = None
    proxyServer = None
    proxyRegistrar = None
    port = 5060
    expires = 3600

    def getUri(self, userB: UserB):
        if userB.telNr == None:
            return self.proxyRegistrar
        else:
            return '{}@{}'.format(userB.telNr, userB.agent)

    def __getAuth(self, userB: UserB):
        a1 = '{}:{}:{}'.format(self.user, self.realm, self.pwd)
        ha1 = uPySip.md5.md5(a1.encode()).hexdigest()
        a2 = '{}:sip:{}'.format(self.types, self.getUri(userB))
        ha2 = uPySip.md5.md5(a2.encode()).hexdigest()
        a3 = '{}:{}:{:0>8}:{}:{}:{}'.format(ha1, self.nonce, self.nonceCount, self.cnonce, self.qop, ha2)
        response = uPySip.md5.md5(a3.encode()).hexdigest()

        self.logger.info("a1 :{} ".format(a1))
        self.logger.info("ha1 :{} ".format(ha1))
        self.logger.info("a2 :{} ".format(a2))
        self.logger.info("ha2 :{} ".format(ha2))
        self.logger.info("a3 {} ".format(a3))
        self.logger.info("response :{} {}".format(response, '\r\n'))
        return response

    def getAuthorization(self, userB: UserB) -> str:
        self.nonceCount = 1
        self.cnonce = uPySip.md5.md5('das ist ein Chaos'.encode()).hexdigest()

        response = self.__getAuth(userB)
        return 'Authorization: Digest username="{}",realm="{}",nonce="{}",opaque="",uri="sip:{}",cnonce="{}",nc={:0>8},algorithm=MD5,qop="auth",response="{}"{}'.format(
            self.user, self.realm, self.nonce, self.getUri(userB), self.cnonce, self.nonceCount, response, self.__RN)


class SipMachine:
    REGISTER = 0
    IDLE = 1
    RINGING = 2
    CALLING = 3
    TRYING = 4
    CALL_ACCEPT = 5
    ON_CALL = 6
    __userB = UserB()
    __userA = UserA()
    __auth = Auth()
    __RN = '\r\n'
    __INVITE = 'INVITE'
    __REGISTER = 'REGISTER'
    __status = REGISTER

    def __init__(self, user='', pwd='', telNr=225, userAgent="b2b.domain", userClient="192.168.1.130", proxyServer='192.168.1.1', proxyRegistrar='192.168.1.1', port=5060):
        self.logger = uPySip.tools.getLogger(__name__)
        self.__auth.user = user
        self.__auth.pwd = pwd
        self.__auth.proxyServer = proxyServer
        self.__auth.proxyRegistrar = proxyRegistrar
        self.__auth.port = port
        self.__userA.telNr = telNr
        self.__userA.agent = userAgent
        self.__userA.userClient = userClient

        self.sockW = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_read = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = socket.getaddrinfo('0.0.0.0', port)[0][-1]
        self.sock_read.bind(server_address)
        self.server_addressR = socket.getaddrinfo(
        self.__userA.userClient, 17000)[0][-1]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.server_addressR)

        self.SSRC = uPySip.tools.randomChr(4).encode()

        self.polling_object = select.poll()
        self.polling_object.register(self.sock_read)
        self.polling_object.register(self.sock)

        self.logger.debug('Start thread ')
        self.__sipRegister(self.__userA, self.__auth)
        self.logg = False
        self.call = False

    #    path=__file__.replace('sipMachine.py','data.pcmA')
    #    f=open(path,'wb')
    #    b=bytearray()
    #    for d in range(1,50*5*160):
    #        k=bytes([uPySip.aLaw.linear2alaw( uPySip.aLaw.getSin(d))])
    #        f.write(k)
    #    f.close()

    def loop(self):
        ready_list = self.polling_object.poll()
        for fd in ready_list:
            if fd[1] & select.POLLIN:
                if fd[0] == self.sock_read.fileno() or fd[0] == self.sock_read:
                    self.__readSIPdata(self.__auth.port)
                elif fd[0] == self.sock.fileno() or fd[0] == self.sock:
                    self.__recive()
        self.call = False   
        if self.call:
            path = '/sd/data.pcmA'
            f = open(path, 'rb')
            b = f.read(160)
            t = utime.ticks_ms()
            while len(b) == 160:
                if utime.ticks_ms()-t >= 20:
                    t = utime.ticks_ms()
                    self.__send(self.server_addressS, b)
                    b = f.read(160)
            f.close()
            self.call = False
        return self.__status

    def __sipRegister(self, userA: UserA, auth: Auth = None):
        userB = UserB()
        userB.telNr = None
        userB.agent = auth.proxyRegistrar
        if auth.nonce != None:
            userA.cSeq += 1
            auth.types = self.__REGISTER
        else:
            userA.callId = uPySip.tools.randomChr(7)
        ret = '{}'.format(
            'REGISTER sip:{} SIP/2.0{}'.format(auth.proxyRegistrar, self.__RN))
        ret = '{}{}'.format(ret, self.__getVia(userA, auth))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getTo(userA))
        ret = '{}{}'.format(ret, self.__getFrom(userA))
        ret = '{}{}'.format(ret, self.__getCallID(userA))

        ret = '{}{}'.format(ret, self.__getCSeq(userA.cSeq, self.__REGISTER))
        ret = '{}{}'.format(ret, self.__getContact(userA))
        ret = '{}{}'.format(ret, self.__getAllow())
        if auth.nonce != None:
            ret = '{}{}'.format(ret, self.__auth.getAuthorization( userB))
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def __sipOK(self, userB: UserB, userA: UserA = None):
        contentLength = 0
        ret = '{}{}'.format('SIP/2.0 200 OK', self.__RN)
        ret = '{}{}'.format(ret, userB.viaB)
        ret = '{}{}'.format(ret, userB.fromB)
        ret = '{}{}'.format(ret, userB.toB)
        ret = '{}{}'.format(ret, userB.callId)
        ret = '{}{}'.format(ret, userB.cSeq)
        if userA != None:
            conten = self.getConten(userB, userA.userClient)
            contentLength = len(conten)
            ret = '{}{}'.format(ret, self.__getContact(userA))
            ret = '{}{}'.format(ret, self.__getContentType())
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        if userA != None:
            ret = '{}{}'.format(ret, conten)
        self.__writeSIPdata(ret.encode())

    def getConten(self, userB: UserB, userClient):
        conten = ''
        conten = '{}{}{}'.format(conten, 'v=0', self.__RN)
        conten = '{}{} {} {} IN IP4 {}{}'.format(
            conten, 'o=-', int(userB.sdp_o)+1, int(userB.sdp_o)+1, userClient, self.__RN)
        conten = '{}{}{}'.format(conten, 's=-', self.__RN)
        conten = '{}{} {}{}'.format(conten, 'c=IN IP4 ', userClient, self.__RN)
        conten = '{}{}{}'.format(conten, 't=0 0', self.__RN)
        conten = '{}{}{}'.format(conten, 'm=audio 17000 RTP/AVP 8 127', self.__RN)
        conten = '{}{}{}'.format(conten, 'a=rtpmap:8 PCMA/8000', self.__RN)
        conten = '{}{}{}'.format(conten, 'a=rtpmap:127 telephone-event/8000', self.__RN)
        conten = '{}{}{}'.format(conten, 'a=fmtp:127 0-15', self.__RN, self.__RN)
        return conten

    def __sipRinging(self, userB: UserB, userA: UserA):
        ret = '{}{}'.format('SIP/2.0 180 Ringing', self.__RN)
        ret = '{}{}'.format(ret, userB.viaB)
        ret = '{}{}'.format(ret, userB.fromB)
        ret = '{}{}'.format(ret, userB.toB)
        ret = '{}{}'.format(ret, userB.callId)
        ret = '{}{}'.format(ret, userB.cSeq)
        ret = '{}{}'.format(ret, self.__getContact(userA))
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def invite(self, telNr, userAgent=None):
        self.__userB.sdp_o = 25
        self.__userB.telNr = telNr

        if userAgent == None:
            self.__userB.agent = self.__userA.agent
        else:
            self.__userB.agent = userAgent
        self.__userA.callId = uPySip.tools.randomChr(7)
        self.__userA.tagFrom = uPySip.tools.randomChr(30)
        self.__userA.cSeq += 1
        self.__auth.nonce = None
        self.__sipInvite(self.__userB, self.__userA, self.__auth)
        self.__status = self.CALLING

    def __sipInvite(self, userB: UserB, userA: UserA, auth: Auth = None):
        self.__userB.tagTo = ''
        conten = self.getConten(userB, userA.userClient)
        contentLength = len(conten)

        if auth.nonce != None:
            userA.cSeq += 1
            auth.types = self.__INVITE

        ret = '{}'.format(self.__getInvite(userB))
        ret = '{}{}'.format(ret, self.__getVia(userA, auth))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getFrom(userA))
        ret = '{}{}'.format(ret, self.__getTo(userB))
        ret = '{}{}'.format(ret, self.__getCallID(userA))
        ret = '{}{}'.format(ret, self.__getCSeq(userA.cSeq, self.__INVITE))
        if auth.nonce != None:
            ret = '{}{}'.format(
                ret, self.__auth.getAuthorization( userB))
        ret = '{}{}'.format(ret, self.__getContact(userA))
        ret = '{}{}'.format(ret, self.__getContentType())
        ret = '{}{}'.format(ret, self.__getContentLength(contentLength))
        ret = '{}{}'.format(ret, self.__RN)
        ret = '{}{}'.format(ret, conten)
        self.__writeSIPdata(ret.encode())
    def __sipACK(self, userB: UserB, userA: UserA, auth: Auth):
        ret = '{}'.format(self.__getACK(userB.telNr, userB.agent, auth.port))
        ret = '{}{}'.format(ret, self.__getVia(userA, auth))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getTo(userB))
        ret = '{}{}'.format(ret, self.__getFrom(userA))
        ret = '{}{}'.format(ret, self.__getCallID(userA))
        ret = '{}{}'.format(ret, self.__getCSeq(userA.cSeq, 'ACK'))
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def __getVia(self, user, auth) -> str:
        return 'Via: SIP/2.0/UDP {}:{};branch={}{}'.format(user.userClient, auth.port, user.branch, self.__RN)

    def __getMaxForwards(self) -> str:
        return 'Max-Forwards: 70{}'.format(self.__RN)

    def __getTo(self, user: User) -> str:
        if len(user.tagTo) > 0:
            return 'To: <sip:{}@{}>;tag={}{}'.format(user.telNr, user.agent, user.tagTo, self.__RN)
        else:
            return 'To: <sip:{}@{}>{}'.format(user.telNr, user.agent, self.__RN)

    def __getFrom(self, userA: UserA) -> str:
        return 'From: <sip:{}@{}>;tag={}{}'.format(userA.telNr, userA.agent, userA.tagFrom, self.__RN)

    def __getCallID(self, userA: UserA) -> str:
        return 'Call-ID: {}@{}{}'.format(userA.callId, userA.agent, self.__RN)

    def __getCSeq(self, cSeq, typ) -> str:
        return 'CSeq: {} {}{}'.format(cSeq, typ, self.__RN)

    def __getContact(self, user: User) -> str:
        return 'Contact: <sip:{}@{}>{}'.format(user.telNr, user.userClient, self.__RN)

    def __getExpires(self, expires) -> str:
        return 'Expires: {}{}'.format(expires, self.__RN)

    def __getContentLength(self, contentLength=0) -> str:
        return 'Content-Length: {}{}'.format(contentLength, self.__RN)

    def __getACK(self, telNr, agent, port) -> str:
        return 'ACK sip:{}@{}:{} SIP/2.0{}'.format(telNr, agent, port, self.__RN)

    def __getAllow(self) -> str:
        return 'Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING{}'.format(self.__RN)

    def __getInvite(self, user: User) -> str:
        return 'INVITE sip:{}@{} SIP/2.0{}'.format(user.telNr, user.agent, self.__RN)

    def __getContentType(self) -> str:
        return 'Content-Type: application/sdp{}'.format(self.__RN)

    def __parser(self, message):
        viaB = ''
        message = message.decode().split(self.__RN)
        for messageStr in message:
            if messageStr.find('Authenticate') >= 0:
                authenticateArray = messageStr.split(',')
                for authenticateStr in authenticateArray:
                    if authenticateStr.find('realm') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.__auth.realm = homeArray[1]
                    elif authenticateStr.find('domain') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.__auth.domain = homeArray[1]
                    elif authenticateStr.find('nonce') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.__auth.nonce = homeArray[1]
                    elif authenticateStr.find('stale') >= 0:
                        homeArray = authenticateStr.split('=')
                        self.__auth.stale = homeArray[1]
                    elif authenticateStr.find('algorithm') >= 0:
                        homeArray = authenticateStr.split('=')
                        self.__auth.algorithm = homeArray[1]
                    elif authenticateStr.find('qop=') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.__auth.qop = homeArray[1]
            if messageStr.find('Contact') >= 0:
                if messageStr.find('expires') >= 0:
                    contactArray = messageStr.split(';')
                    self.__auth.expires = int(contactArray[1].split('=')[1])
            if messageStr.find('SIP/2.0 ') >= 0:
                responseCodesArray = messageStr.split(' ')
                self.responseCodes = responseCodesArray[1]
            if messageStr.find('CSeq') >= 0:
                CSeqArray = messageStr.split(' ')
                self.CSeqTyp = CSeqArray[2]
            if messageStr.find('To:') >= 0:
                if messageStr.find('tag') >= 0:
                    toArray = messageStr.split('=')
                    self.__userB.tagTo = toArray[1]
            if messageStr.find('BYE sip:') >= 0:
                self.responseCodes = 'BYE sip:'
            if messageStr.find('INVITE sip:') >= 0:
                self.responseCodes = 'INVITE sip:'
            if messageStr.find('ACK sip:') >= 0:
                self.responseCodes = 'ACK sip:'
            if messageStr.find('CANCEL sip:') >= 0:
                self.responseCodes = 'CANCEL sip:'
            if messageStr.find('Via:') >= 0:
                viaB = '{}{}{}'.format(viaB, messageStr, self.__RN)
            if messageStr.find('From:') >= 0:
                self.__userB.fromB = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('To:') >= 0:
                self.__userB.toB = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('Call-ID:') >= 0:
                self.__userB.callId = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('CSeq:') >= 0:
                self.__userB.cSeq = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('o=') >= 0:
                self.__userB.sdp_o = messageStr.split(' ')[1]
            if messageStr.find('m=') >= 0:
                self.pcmuPort = messageStr.split(' ')[1]
        if viaB != '':
            self.__userB.viaB = viaB
        message = None
        if self.CSeqTyp == self.__REGISTER and self.responseCodes == '401':
            self.__sipRegister(self.__userA, self.__auth)

        elif self.CSeqTyp == self.__REGISTER and self.responseCodes == '200':
            self.__status = self.IDLE
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '407':
            self.__sipACK(self.__userB, self.__userA, self.__auth)
            self.__sipInvite(self.__userB, self.__userA, self.__auth)
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '100':
            pass
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '200':
            self.call = True
            self.server_addressS = socket.getaddrinfo(
                self.__auth.proxyServer, self.pcmuPort)[0][-1]
            self.__sipACK(self.__userB, self.__userA, self.__auth)
            self.__status = self.ON_CALL
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == 'INVITE sip:':
            self.__sipRinging(self.__userB, self.__userA)
            self.__status = self.RINGING
        elif self.CSeqTyp == 'ACK' and self.responseCodes == 'ACK sip:':
            self.call = True
            self.server_addressS = socket.getaddrinfo(self.__auth.proxyServer, self.pcmuPort)[0][-1]
        elif self.CSeqTyp == 'BYE' and self.responseCodes == 'BYE sip:':
            self.__sipOK(self.__userB)
            self.call = False
            self.__status = self.IDLE
        elif self.CSeqTyp == 'CANCEL' and self.responseCodes == 'CANCEL sip:':
            self.__sipOK(self.__userB)
            self.call = False
            self.__status = self.IDLE

    def __readSIPdata(self, port):
        try:
            (data, proxyServer) = self.sock_read.recvfrom(1024)
            self.logger.info("__readSIPdata form {}:{}{}{}".format(
                proxyServer, self.__RN, self.__RN, data.decode()))
            self.__parser(data)
        except OSError as e:
            self.logger.error("exception from sock_read.recvfrom {}".format(e))

    def __writeSIPdata(self, message):
        server_address = socket.getaddrinfo(
            self.__auth.proxyServer, self.__auth.port)[0][-1]
        __send = self.sockW.sendto(message, server_address)
        self.logger.info("WriteData to {} : {}{}{}".format(
            (self.__auth.proxyServer, self.__auth.port), self.__RN, self.__RN, message.decode()))

    def __send(self, server_addressS, ba):

        b = bytearray(b'\x80\x08')
        t = utime.ticks_ms()
        tt = int(t/20) % 10000
        b.extend(tt.to_bytes(2, 'big'))
        tt = int(t*8-t*8 % 160) % 1000000000
        b.extend(tt.to_bytes(4, 'big'))
        b.extend(self.SSRC)
        b.extend(ba)

        __send = self.sock.sendto(b, server_addressS)
        if self.logg:
            print('s {:08b} {:08b} {:08b} {:08b}'.format(
                bytes(b)[0], bytes(b)[1], bytes(b)[2], bytes(b)[3]), end='')
            print('  {: >10} '.format(int.from_bytes(
                bytes(b)[0:4], byteorder='big')), end='')
            print(' {:08b} {:08b} {:08b} {:08b}'.format(
                bytes(b)[4], bytes(b)[5], bytes(b)[6], bytes(b)[7]), end='')
            print('  {: >10} '.format(int.from_bytes(
                bytes(b)[4:8], byteorder='big')), end='')
            print(' {:08b} {:08b} {:08b} {:08b}'.format(
                bytes(b)[8], bytes(b)[9], bytes(b)[10], bytes(b)[11]), end='')
            print('  {: >10} '.format(int.from_bytes(
                bytes(b)[8:12], byteorder='big')), end='')
            print(' {:08b} {:08b} {:08b} {:08b}'.format(
                bytes(b)[12], bytes(b)[13], bytes(b)[14], bytes(b)[15]), end='')
            print('  {: >10} '.format(int.from_bytes(
                bytes(b)[12:16], byteorder='big')))

    def __recive(self):
        try:
            (data, proxyServer) = self.sock.recvfrom(180)
            a=uPySip.DTMF.DTMF().getKey(data)
            if a[1]>500000:
                print(a[0] )


            if self.logg:
                print('r {:08b} {:08b} {:08b} {:08b}'.format(
                    data[0], data[1], data[2], data[3]), end='')
                print('  {: >10} '.format(int.from_bytes(
                    data[0:4], byteorder='big')), end='')
                print(' {:08b} {:08b} {:08b} {:08b}'.format(
                    data[4], data[5], data[6], data[7]), end='')
                print('  {: >10} '.format(int.from_bytes(
                    data[4:8], byteorder='big')), end='')
                print(' {:08b} {:08b} {:08b} {:08b}'.format(
                    data[8], data[9], data[10], data[11]), end='')
                print('  {: >10} '.format(int.from_bytes(
                    data[8:12], byteorder='big')), end='')
                print(' {:08b} {:08b} {:08b} {:08b}'.format(
                    data[12], data[13], data[14], data[15]), end='')
                print('  {: >10} '.format(
                    int.from_bytes(data[12:16], byteorder='big')))
#                print(' {:08b} {:08b} {:08b} {:08b}'.format(data[16], data[17], data[18], data[19]),end='')
#                print('  {: >10} '.format(int.from_bytes(data[16:20], byteorder='big' )))

        except OSError as msg:
            print("Socket Error: {}".format(msg))

    def acceptCall(self):
        self.__sipOK(self.__userB, self.__userA)
        self.__status = self.CALL_ACCEPT

    def getTelNrB(self):
        return self.__userB.fromB.split('sip:')[1].split('@')[0]
