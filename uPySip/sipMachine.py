
import _thread
import uPySip.md5
import uPySip.tools
import utime
import socket
import select
import uPySip.aLaw
class B:
    toB=None
    viaB=None
    fromB=None
    cSeqB=None
    callIdB=None
    sdp_o=None


class SipMachine:
    REGISTER=0
    IDLE=1
    RINGING=2
    CALLING=3
    TRYING=4
    CALL_ACCEPT=5
    ON_CALL=6
    __b=B()
    
    __RN = '\r\n'
    __INVITE = 'INVITE'
    __REGISTER = 'REGISTER'
    __status=REGISTER

    def __init__(self, user='', pwd='', telNrA=225, UserAgentA="b2b.domain", userClient="192.168.1.130", server='192.168.1.1', port=5060):
        self.logger = uPySip.tools.getLogger(__name__)
        self.user = user
        self.pwd = pwd
        self.telNrA = telNrA
        self.telNrB = telNrA
        self.UserAgentA = UserAgentA
        self.UserAgentB = UserAgentA
        self.userClient = userClient
        self.server = server

        self.port = port

        self.cSeq = 1
        self.branch = 'z9hG4bK-{}'.format(uPySip.tools.randomChr(30))
        self.tagFrom = uPySip.tools.randomChr(30)
        self.tagTo = ''
        self.callId = uPySip.tools.randomChr(6)
        self.expires = 3600
        self.sockW = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_read = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = socket.getaddrinfo('0.0.0.0', port)[0][-1]
        self.sock_read.bind(server_address)
        self.server_addressR = socket.getaddrinfo(
            self.userClient, 17000)[0][-1]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.server_addressR)

        self.SSRC = uPySip.tools.randomChr(4).encode()

        self.polling_object = select.poll()
        self.polling_object.register(self.sock_read)
        self.polling_object.register(self.sock)

        self.logger.debug('Start thread ')
        self.__sipRegister(self.server, self.port, self.branch, self.telNrB, self.UserAgentB, self.tagTo, self.telNrA,
                         self.UserAgentA, self.tagFrom, self.callId, self.cSeq, self.__REGISTER, self.userClient, self.expires)
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
                    self.__readSIPdata(self.port)
                elif fd[0] == self.sock.fileno() or fd[0] == self.sock:
                    self.__recive()
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

    def __sipOKBy(self, b:B):
        ret = '{}{}'.format('SIP/2.0 200 OK', self.__RN)
        ret = '{}{}'.format(ret, b.viaB)
        ret = '{}{}'.format(ret, b.fromB)
        ret = '{}{}'.format(ret, b.toB)
        ret = '{}{}'.format(ret, b.callIdB)
        ret = '{}{}'.format(ret, b.cSeqB)
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def __sipOKInvite(self, b:B, userClient, telNrA):
        conten = ''
        conten = '{}{}{}'.format(conten, 'v=0', self.__RN)
        conten = '{}{} {} {} IN IP4 {}{}'.format(conten, 'o=-', int(b.sdp_o)+1, int(b.sdp_o)+1, userClient, self.__RN)
        conten = '{}{}{}'.format(conten, 's=-', self.__RN)
        conten = '{}{} {}{}'.format(conten, 'c=IN IP4 ', userClient, self.__RN)
        conten = '{}{}{}'.format(conten, 't=0 0', self.__RN)
        conten = '{}{}{}'.format(conten, 'm=audio 17000 RTP/AVP 8', self.__RN)
        conten = '{}{}{}{}'.format(conten, 'a=rtpmap:8 PCMA/8000', self.__RN, self.__RN)
        contentLength = len(conten)
        ret = '{}{}'.format('SIP/2.0 200 OK', self.__RN)
        ret = '{}{}'.format(ret, b.viaB)
        ret = '{}{}'.format(ret, b.fromB)
        ret = '{}{}'.format(ret, b.toB)
        ret = '{}{}'.format(ret, b.callIdB)
        ret = '{}{}'.format(ret, b.cSeqB)
        ret = '{}{}'.format(ret, self.__getContact(telNrA, userClient))
        ret = '{}{}'.format(ret, self.__getContentType())
        ret = '{}{}'.format(ret, self.__getContentLength(contentLength))
        ret = '{}{}'.format(ret, self.__RN)
        ret = '{}{}'.format(ret, conten)
        self.__writeSIPdata(ret.encode())

    def __sipRinging(self,b:B , userClient, telNrA):
        ret = '{}{}'.format('SIP/2.0 180 Ringing', self.__RN)
        ret = '{}{}'.format(ret, b.viaB)
        ret = '{}{}'.format(ret, b.fromB)
        ret = '{}{}'.format(ret, b.toB)
        ret = '{}{}'.format(ret, b.callIdB)
        ret = '{}{}'.format(ret, b.cSeqB)
        ret = '{}{}'.format(ret, self.__getContact(telNrA, userClient))
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def invite(self,telNr):
        self.telNrB=telNr
        self.__sipInvite(self.telNrB, self.UserAgentB, self.userClient, self.port, self.branch, self.telNrA, self.UserAgentA)
        self.__status=self.CALLING

    def __sipInvite(self, telNrB, UserAgentB, userClient, port, branch, telNrA, UserAgentA):
        conten = ''
        conten = '{}v=0{}'.format(conten, self.__RN)
        conten = '{}o=- 1454 1454 IN IP4 {}{}'.format(conten, userClient, self.__RN)
        conten = '{}s=-{}'.format(conten, self.__RN)
        conten = '{}c=IN IP4 {}{}'.format(conten, userClient, self.__RN)
        conten = '{}t=0 0{}'.format(conten, self.__RN)
        conten = '{}m=audio 17000 RTP/AVP 8{}'.format(conten, self.__RN)
        conten = '{}a=rtpmap:0 PCMA/8000{}'.format(conten, self.__RN)
        conten = '{}{}'.format(conten, self.__RN)
        contentLength = len(conten)
        self.cSeq = 1
        tagTo = ''
        self.callId = uPySip.tools.randomChr(6)
        ret = '{}'.format(self.__getInvite(telNrB, UserAgentB))
        ret = '{}{}'.format(ret, self.__getVia(userClient, port, branch))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getFrom(telNrA, UserAgentA, self.tagFrom))
        ret = '{}{}'.format(ret, self.__getTo(telNrB, UserAgentB, tagTo))
        ret = '{}{}'.format(ret, self.__getCallID(self.callId, UserAgentA))
        ret = '{}{}'.format(ret, self.__getCSeq(self.cSeq, self.__INVITE))
        ret = '{}{}'.format(ret, self.__getContact(self.telNrA, self.userClient))
        ret = '{}{}'.format(ret, self.__getContentType())
        ret = '{}{}'.format(ret, self.__getContentLength(contentLength))
        ret = '{}{}'.format(ret, self.__RN)
        ret = '{}{}'.format(ret, conten)
        self.__writeSIPdata(ret.encode()

    def __sipInviteA(self):
        conten = ''
        conten = '{}v=0{}'.format(conten, self.__RN)
        conten = '{}o=- 1454 1454 IN IP4 {}{}'.format(conten, self.userClient, self.__RN)
        conten = '{}s=-{}'.format(conten, self.__RN)
        conten = '{}c=IN IP4 {}{}'.format(conten, self.userClient, self.__RN)
        conten = '{}t=0 0{}'.format(conten, self.__RN)
        conten = '{}m=audio 17000 RTP/AVP 8{}'.format(conten, self.__RN)
        conten = '{}a=rtpmap:0 PCMA/8000{}'.format(conten, self.__RN)
        conten = '{}{}'.format(conten, self.__RN)
        contentLength = len(conten)
        self.cSeq = self.cSeq+1
        self.tagTo = ''
        self.branch = 'z9hG4bK-{}'.format(uPySip.tools.randomChr(30))
        ret = '{}'.format(self.__getInvite(self.telNrB, self.UserAgentB))
        ret = '{}{}'.format(ret, self.__getVia(self.userClient, self.port, self.branch))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getFrom(self.telNrA, self.UserAgentA, self.tagFrom))
        ret = '{}{}'.format(ret, self.__getTo(self.telNrB, self.UserAgentB, self.tagTo))
        ret = '{}{}'.format(ret, self.__getCallID(self.callId, self.UserAgentA))
        ret = '{}{}'.format(ret, self.__getCSeq(self.cSeq, self.__INVITE))
        ret = '{}{}'.format(ret, self.__getAuthorization(self.user, self.realm, self.pwd, self.__INVITE, self.nonce, self.qop,  self.UserAgentB,self.telNrB))
        ret = '{}{}'.format(ret, self.__getContact(self.telNrA, self.userClient))
        ret = '{}{}'.format(ret, self.__getContentType())
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        ret = '{}{}'.format(ret, conten)
        self.__writeSIPdata(ret.encode())
        a=5

    def __sipACK(self):
        ret = '{}'.format(self.__getACK(self.telNrB, self.UserAgentB, self.port))
        ret = '{}{}'.format(ret, self.__getVia(self.userClient, self.port, self.branch))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getTo(self.telNrB, self.UserAgentB, self.tagTo))
        ret = '{}{}'.format(ret, self.__getFrom(self.telNrA, self.UserAgentA, self.tagFrom))
        ret = '{}{}'.format(ret, self.__getCallID(self.callId, self.UserAgentA))
        ret = '{}{}'.format(ret, self.__getCSeq(self.cSeq, 'ACK'))
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def __sipRegister(self, server, port, branch, telNrB, UserAgentB, tagTo, telNrA, UserAgentA, tagFrom, callId, cSeq, REGISTER, userClient, expires, user=None, realm=None, pwd=None, nonce=None, qop=None):
        ret = '{}'.format('REGISTER sip:{} SIP/2.0{}'.format(server, self.__RN))
        ret = '{}{}'.format(ret, self.__getVia(userClient, port, branch))
        ret = '{}{}'.format(ret, self.__getMaxForwards())
        ret = '{}{}'.format(ret, self.__getTo(telNrB, UserAgentB, tagTo))
        ret = '{}{}'.format(ret, self.__getFrom(telNrA, UserAgentA, tagFrom))
        ret = '{}{}'.format(ret, self.__getCallID(callId, UserAgentA))
        if user != None:
            self.cSeq += 1
        ret = '{}{}'.format(ret, self.__getCSeq(self.cSeq, REGISTER))
        ret = '{}{}'.format(ret, self.__getContact(telNrA, userClient))
        ret = '{}{}'.format(ret, self.__getAllow())
        if user != None:
            ret = '{}{}'.format(ret, self.__getAuthorization(
                user, realm, pwd, REGISTER, nonce, qop, server))
        ret = '{}{}'.format(ret, self.__getExpires(expires))
        ret = '{}{}'.format(ret, self.__getContentLength())
        ret = '{}{}'.format(ret, self.__RN)
        self.__writeSIPdata(ret.encode())

    def __getVia(self, userClient, port, branch) -> str:
        return 'Via: SIP/2.0/UDP {}:{};branch={}{}'.format(userClient, port, branch, self.__RN)

    def __getMaxForwards(self) -> str:
        return 'Max-Forwards: 70{}'.format(self.__RN)

    def __getTo(self, telNrB, UserAgentB, tagTo) -> str:
        if len(tagTo) > 0:
            return 'To: <sip:{}@{}>;tag={}{}'.format(telNrB, UserAgentB, tagTo, self.__RN)
        else:
            return 'To: <sip:{}@{}>{}'.format(telNrB, UserAgentB, self.__RN)

    def __getFrom(self, telNrA, UserAgentA, tagFrom) -> str:
        return 'From: <sip:{}@{}>;tag={}{}'.format(telNrA, UserAgentA, tagFrom, self.__RN)

    def __getCallID(self, callId, UserAgentA) -> str:
        return 'Call-ID: {}@{}{}'.format(callId, UserAgentA, self.__RN)

    def __getCSeq(self, cSeq, typ) -> str:
        return 'CSeq: {} {}{}'.format(cSeq, typ, self.__RN)

    def __getContact(self, telNrA, userClient) -> str:
        return 'Contact: <sip:{}@{}>{}'.format(telNrA, userClient, self.__RN)

    def __getExpires(self, expires) -> str:
        return 'Expires: {}{}'.format(expires, self.__RN)

    def __getContentLength(self, contentLength=0) -> str:
        return 'Content-Length: {}{}'.format(contentLength, self.__RN)

    def __getACK(self, telNrB, UserAgentB, port) -> str:
        return 'ACK sip:{}@{}:{} SIP/2.0{}'.format(telNrB, UserAgentB, port, self.__RN)

    def __getAuthorization(self, user, realm, pwd, INVITE, nonce, qop, server, telNrB=None) -> str:
        nonceCount = 1
        cnonce = uPySip.md5.md5('das ist ein Chaos'.encode()).hexdigest()
        if telNrB == None:
            uri = server
        else:
            uri = '{}@{}'.format(telNrB, server)
        response = self.__getAuth(user, realm, pwd, INVITE,uri, nonce, nonceCount, cnonce, qop)
        return 'Authorization: Digest username="{}",realm="{}",nonce="{}",opaque="",uri="sip:{}",cnonce="{}",nc={:0>8},algorithm=MD5,qop="auth",response="{}"{}'.format(
            user, realm, nonce, uri, cnonce, nonceCount, response, self.__RN)

    def __getAuth(self, user, realm, pwd, typ, uri, nonce, nonceCount, cnonce, qop):
        a1 = '{}:{}:{}'.format(user, realm, pwd)
        ha1 = uPySip.md5.md5(a1.encode()).hexdigest()
        a2 = '{}:sip:{}'.format(typ, uri)
        ha2 = uPySip.md5.md5(a2.encode()).hexdigest()
        a3 = '{}:{}:{:0>8}:{}:{}:{}'.format(ha1, nonce, nonceCount, cnonce, qop, ha2)
        response = uPySip.md5.md5(a3.encode()).hexdigest()

        self.logger.info("a1 :{} ".format(a1))
        self.logger.info("ha1 :{} ".format(ha1))
        self.logger.info("a2 :{} ".format(a2))
        self.logger.info("ha2 :{} ".format(ha2))
        self.logger.info("a3 {} ".format(a3))
        self.logger.info("response :{} {}".format(response, self.__RN))
        return response

    def __getAllow(self) -> str:
        return 'Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING{}'.format(self.__RN)

    def __getInvite(self, telNrB, UserAgentB) -> str:
        return 'INVITE sip:{}@{} SIP/2.0{}'.format(telNrB, UserAgentB, self.__RN)

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
                        self.realm = homeArray[1]
                    elif authenticateStr.find('domain') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.domain = homeArray[1]
                    elif authenticateStr.find('nonce') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.nonce = homeArray[1]
                    elif authenticateStr.find('stale') >= 0:
                        homeArray = authenticateStr.split('=')
                        self.stale = homeArray[1]
                    elif authenticateStr.find('algorithm') >= 0:
                        homeArray = authenticateStr.split('=')
                        self.algorithm = homeArray[1]
                    elif authenticateStr.find('qop=') >= 0:
                        homeArray = authenticateStr.split('"')
                        self.qop = homeArray[1]
            if messageStr.find('Contact') >= 0:
                if messageStr.find('expires') >= 0:
                    contactArray = messageStr.split(';')
                    self.expires = int(contactArray[1].split('=')[1])
            if messageStr.find('SIP/2.0 ') >= 0:
                responseCodesArray = messageStr.split(' ')
                self.responseCodes = responseCodesArray[1]
            if messageStr.find('CSeq') >= 0:
                CSeqArray = messageStr.split(' ')
                self.CSeqTyp = CSeqArray[2]
            if messageStr.find('To:') >= 0:
                if messageStr.find('tag') >= 0:
                    toArray = messageStr.split('=')
                    self.tagTo = toArray[1]
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
                self.__b.fromB = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('To:') >= 0:
                self.__b.toB = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('Call-ID:') >= 0:
                self.__b.callIdB = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('CSeq:') >= 0:
                self.__b.cSeqB = '{}{}'.format(messageStr, self.__RN)
            if messageStr.find('o=') >= 0:
                self.__b.sdp_o = messageStr.split(' ')[1]
            if messageStr.find('m=') >= 0:
                self.pcmuPort = messageStr.split(' ')[1]
        if viaB!='':
            self.__b.viaB=viaB
        message = None
        if self.CSeqTyp == self.__REGISTER and self.responseCodes == '401':
            self.__sipRegister(self.server, self.port, self.branch, self.telNrB, self.UserAgentB, self.tagTo, self.telNrA, self.UserAgentA, self.tagFrom,
                             self.callId, self.cSeq, self.__REGISTER, self.userClient, self.expires, self.user, self.realm, self.pwd, self.nonce, self.qop)
        elif self.CSeqTyp == self.__REGISTER and self.responseCodes == '200':
            self.__status=self.IDLE
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '407':
            self.__sipACK()
            self.__sipInviteA()
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '100':
            pass
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '200':
            self.call = True
            self.server_addressS = socket.getaddrinfo(self.server, self.pcmuPort)[0][-1]
            self.__sipACK()
            self.__status=self.ON_CALL
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == 'INVITE sip:':
            self.__sipRinging(self.__b,self.userClient, self.telNrA)
            self.__status=self.RINGING
        elif self.CSeqTyp == 'ACK' and self.responseCodes == 'ACK sip:':
            self.call = True
            self.server_addressS = socket.getaddrinfo(self.server, self.pcmuPort)[0][-1]
        elif self.CSeqTyp == 'BYE' and self.responseCodes == 'BYE sip:':
            self.__sipOKBy(self.__b)
            self.call = False
            self.__status=self.IDLE
        elif self.CSeqTyp == 'CANCEL' and self.responseCodes == 'CANCEL sip:':
            self.__sipOKBy(self.__b)
            self.call = False
            self.__status=self.IDLE

    def __readSIPdata(self, port):
        try:
            (data, server) = self.sock_read.recvfrom(1024)
            self.logger.info("__readSIPdata form {}:{}{}{}".format(
                server, self.__RN, self.__RN, data.decode()))
            self.__parser(data)
        except OSError as e:
            self.logger.error("exception from sock_read.recvfrom {}".format(e))

    def __writeSIPdata(self, message):
        server_address = socket.getaddrinfo(self.server, self.port)[0][-1]
        __send = self.sockW.sendto(message, server_address)
        self.logger.info("WriteData to {} : {}{}{}".format(
            (self.server, self.port), self.__RN, self.__RN, message.decode()))

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
            (data, server) = self.sock.recvfrom(180)
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
        self.__sipOKInvite(self.__b, self.userClient, self.telNrA)
        self.__status=self.CALL_ACCEPT

    def getTelNrB(self):
        return   self.__b.fromB.split('sip:')[1].split('@')[0]