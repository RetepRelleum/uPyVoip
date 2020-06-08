
import _thread
import uPySip.md5
import uPySip.tools
import utime
import socket
import select
import uPySip.aLaw
import uPySip.DTMF 
import gc

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
        return response

    def getAuthorization(self, userB: UserB) -> str:
        self.nonceCount = 1
        self.cnonce = uPySip.md5.md5('das ist ein Chaos'.encode()).hexdigest()
        response = self.__getAuth(userB)
        return 'Authorization: Digest username="{}",realm="{}",nonce="{}",opaque="",uri="sip:{}",cnonce="{}",nc={:0>8},algorithm=MD5,qop="auth",response="{}"{}'.format(
            self.user, self.realm, self.nonce, self.getUri(userB), self.cnonce, self.nonceCount, response, self.__RN)


class SipMachine:
    REGISTER = 0x00
    IDLE = 0x01
    RINGING = 0x02
    CALLING = 0x03
    TRYING = 0x0
    CALL_ACCEPT = 0x05
    ON_CALL = 0x06
    __userB = UserB()
    __userA = UserA()
    __auth = Auth()
    __RN = '\r\n'
    __INVITE = 'INVITE'
    __REGISTER = 'REGISTER'
    __status = REGISTER
    __key=''
    __record=False
    __buffer=bytearray([0]*172)
    __buffer[0] = 0x80
    __buffer[1] = 0x08

    __buffer[8] = 0x80
    __buffer[9] = 0x15   
    __buffer[10] = 0x00
    __buffer[11] = 0x71  
    __sock_SIP=None
    __f_sip=None


    def __init__(self, user='', pwd='', telNr=225, userAgent="b2b.domain", userClient="192.168.1.130", proxyServer='192.168.1.1', proxyRegistrar='192.168.1.1', port=5060):

        self.__auth.user = user
        self.__auth.pwd = pwd
        self.__auth.proxyServer = proxyServer
        self.__auth.proxyRegistrar = proxyRegistrar
        self.__auth.port = port
        self.__userA.telNr = telNr
        self.__userA.agent = userAgent
        self.__userA.userClient = userClient

 

        self.sock_sip_r= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = socket.getaddrinfo( self.__userA.userClient , port)[0][-1]

        self.sock_sip_r.bind(server_address)
        self.sock_sip_r.listen()


        self.server_addressR = socket.getaddrinfo(
        self.__userA.userClient, 17000)[0][-1]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.server_addressR)

        self.SSRC = uPySip.tools.randomChr(4).encode()

        self.polling_object = select.poll()

        self.polling_object.register(self.sock)
        self.polling_object.register(self.sock_sip_r)

        self.__sipRegister(self.__userA, self.__auth)
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
                if self.__f_sip!=None:
                    if fd[0] == self.__f_sip.fileno() or fd[0] == self.__f_sip:
                        self.__readSIPdata()
                if fd[0] == self.sock.fileno() or fd[0] == self.sock:
                    self.__recive()
                if fd[0] == self.sock_sip_r.fileno() or fd[0] == self.sock_sip_r:
                    if self.__f_sip!=None:
                        self.closeConnection()
                    (a,b)=self.sock_sip_r.accept()
                    self.setConnection(a)
        if  self.call:
            gc.collect()
            print('start')
            path = '/sd/data.pcmA'
            f = open(path, 'rb')
            v=memoryview(self.__buffer)
            l=f.readinto(v[12:])
            t = utime.ticks_ms()
            while l== 160:
                if utime.ticks_ms()-t >= 20:
                    t = utime.ticks_ms()
                    self.__send(self.server_addressS)
                    v=memoryview(self.__buffer)
                    l=f.readinto(v[12:])
            f.close()
            self.call = False
            print('end')
        return self.__status

    def __sipRegister(self, userA: UserA, auth: Auth = None):
        self.setConnection()
        userB = UserB()
        userB.telNr = None
        userB.agent = auth.proxyRegistrar
        if auth.nonce != None:
            userA.cSeq += 1
            auth.types = self.__REGISTER
        else:
            userA.callId = uPySip.tools.randomChr(7)
        self.__writeSIPdata('REGISTER sip:{} SIP/2.0{}'.format(auth.proxyRegistrar, self.__RN))
        self.__getVia(userA, auth)
        self.__getMaxForwards()
        self.__getTo(userA)
        self.__getFrom(userA)
        self.__getCallID(userA)
        self.__getCSeq(userA.cSeq, self.__REGISTER)
        self.__getContact(userA)
        self.__getAllow()
        if auth.nonce != None:
            self.__writeSIPdata( self.__auth.getAuthorization( userB))
        self.__getContentLength()
        self.__writeSIPdata( self.__RN)
         

    def __sipOK(self, userB: UserB, userA: UserA = None):
        contentLength = 0
        self.__writeSIPdata('SIP/2.0 200 OK{}'.format( self.__RN))
        self.__writeSIPdata( userB.viaB)
        self.__writeSIPdata( userB.fromB)
        self.__writeSIPdata( userB.toB)
        self.__writeSIPdata( userB.callId)
        self.__writeSIPdata( userB.cSeq)
        if userA != None:
            conten = self.getConten(userB, userA.userClient)
            contentLength = len(conten)
            self.__getContact(userA)
            self.__getContentType()
        self.__getContentLength(contentLength)
        self.__writeSIPdata( self.__RN)
        if userA != None:
            self.__writeSIPdata( conten)


    def getConten(self, userB: UserB, userClient):
        conten = ''
        conten = '{}{}{}'.format(conten, 'v=0', self.__RN)
        conten = '{}{} {} {} {} {}{}'.format(conten, 'o=-', int(userB.sdp_o)+1, int(userB.sdp_o)+1,'IN IP4', userClient, self.__RN)
        conten = '{}{}{}'.format(conten, 's=-', self.__RN)
        conten = '{}{} {}{}'.format(conten, 'c=IN IP4', userClient, self.__RN)
        conten = '{}{}{}'.format(conten, 't=0 0', self.__RN)
        conten = '{}{}{}'.format(conten, 'm=audio 17000 RTP/AVP 8 127', self.__RN)
        conten = '{}{}{}'.format(conten, 'a=rtpmap:8 PCMA/8000', self.__RN)
        conten = '{}{}{}'.format(conten, 'a=rtpmap:127 telephone-event/8000', self.__RN)
        conten = '{}{}{}{}'.format(conten, 'a=fmtp:127 0-15', self.__RN,self.__RN)
        return conten

    def __sipRinging(self, userB: UserB, userA: UserA):
        self.__writeSIPdata('SIP/2.0 180 Ringing {}'.format( self.__RN))
        self.__writeSIPdata( userB.viaB)
        self.__writeSIPdata( userB.fromB)
        self.__getTo(userA)
        self.__writeSIPdata( userB.callId)
        self.__writeSIPdata( userB.cSeq)
        self.__getContact(userA)
        self.__getContentLength()
        self.__writeSIPdata( self.__RN)


    def invite(self, telNr, userAgent=None):
        self.setConnection()

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

        self.__getInvite(userB)
        self.__getVia(userA, auth)
        self.__getMaxForwards()
        self.__getFrom(userA)
        self.__getTo(userB)
        self.__getCallID(userA)
        self.__getCSeq(userA.cSeq, self.__INVITE)
        if auth.nonce != None:
            self.__writeSIPdata(self.__auth.getAuthorization( userB))
        self.__getContact(userA)
        self.__getContentType()
        self.__getContentLength(contentLength)
        self.__writeSIPdata( self.__RN)
        self.__writeSIPdata( conten)
         
    def __sipACK(self, userB: UserB, userA: UserA, auth: Auth):
        self.__getACK(userB.telNr, userB.agent, auth.port)
        self.__getVia(userA, auth)
        self.__getMaxForwards()
        self.__getTo(userB)
        self.__getFrom(userA)
        self.__getCallID(userA)
        self.__getCSeq(userA.cSeq, 'ACK')
        self.__getContentLength()
        self.__writeSIPdata( self.__RN)
         

    def __getVia(self, user, auth) -> str:
        self.__writeSIPdata( 'Via: SIP/2.0/TCP {}:{};branch={}{}'.format(user.userClient, auth.port, user.branch, self.__RN))

    def __getMaxForwards(self) -> str:
        self.__writeSIPdata( 'Max-Forwards: 70{}'.format(self.__RN))

    def __getTo(self, user: User) -> str:
        if len(user.tagTo) > 0:
            self.__writeSIPdata('To: <sip:{}@{}>;tag={}{}'.format(user.telNr, user.agent, user.tagTo, self.__RN))
        else:
            self.__writeSIPdata( 'To: <sip:{}@{}>{}'.format(user.telNr, user.agent, self.__RN))

    def __getFrom(self, userA: UserA) -> str:
        self.__writeSIPdata(  'From: <sip:{}@{}>;tag={}{}'.format(userA.telNr, userA.agent, userA.tagFrom, self.__RN))

    def __getCallID(self, userA: UserA) -> str:
        self.__writeSIPdata(   'Call-ID: {}@{}{}'.format(userA.callId, userA.agent, self.__RN))

    def __getCSeq(self, cSeq, typ) -> str:
        self.__writeSIPdata( 'CSeq: {} {}{}'.format(cSeq, typ, self.__RN))

    def __getContact(self, user: User) -> str:
        self.__writeSIPdata(  'Contact: <sip:{}@{};transport=tcp>{}'.format(user.telNr, user.userClient, self.__RN))

    def __getExpires(self, expires) -> str:
        return 'Expires: {}{}'.format(expires, self.__RN)

    def __getContentLength(self, contentLength=0) -> str:
        self.__writeSIPdata(  'Content-Length: {}{}'.format(contentLength, self.__RN))

    def __getACK(self, telNr, agent, port) -> str:
        self.__writeSIPdata(   'ACK sip:{}@{}:{} SIP/2.0{}'.format(telNr, agent, port, self.__RN))

    def __getAllow(self) -> str:
        self.__writeSIPdata(   'Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,SUBSCRIBE,NOTIFY,REFER,MESSAGE,INFO,PING{}'.format(self.__RN))

    def __getInvite(self, user: User) -> str:
        self.__writeSIPdata(   'INVITE sip:{}@{} SIP/2.0{}'.format(user.telNr, user.agent, self.__RN))

    def __getContentType(self) -> str:
        self.__writeSIPdata(   'Content-Type: application/sdp{}'.format(self.__RN))

    def __parser(self, messageStr):
        messageStr=messageStr.decode()
        messageStr=messageStr.replace("\r\n", "")
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
                self.__auth.expires = int(contactArray[2].split('=')[1])
        if messageStr.find('SIP/2.0 ') >= 0:
            responseCodesArray = messageStr.split(' ')
            self.responseCodes = responseCodesArray[1]
            self.__userB.viaB=''
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
            self.__userB.viaB=''
        if messageStr.find('ACK sip:') >= 0:
            self.responseCodes = 'ACK sip:'
        if messageStr.find('CANCEL sip:') >= 0:
            self.responseCodes = 'CANCEL sip:'
        if messageStr.find('Via:') >= 0:
            self.__userB.viaB = '{}{}{}'.format(self.__userB.viaB, messageStr, self.__RN)
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
        if messageStr.find('Content-Length:')>=0:
            self.___contentLenght=int(messageStr.split(' ')[1])


      
    def __exec(self):
        if self.CSeqTyp == self.__REGISTER and self.responseCodes == '401':
            self.__sipRegister(self.__userA, self.__auth)
        elif self.CSeqTyp == self.__REGISTER and self.responseCodes == '200':
            self.__status = self.IDLE
            self.closeConnection()
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '407':
            self.__sipACK(self.__userB, self.__userA, self.__auth)
            self.__sipInvite(self.__userB, self.__userA, self.__auth)
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '486':
            self.__sipACK(self.__userB, self.__userA, self.__auth)
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '100':
            pass
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == '200':
            self.call = True
            self.server_addressS = socket.getaddrinfo(self.__auth.proxyServer, self.pcmuPort)[0][-1]
            self.__sipACK(self.__userB, self.__userA, self.__auth)
            self.__status = self.ON_CALL
            self.closeConnection()     
        elif self.CSeqTyp == self.__INVITE and self.responseCodes == 'INVITE sip:':
            self.__userA.tagTo=uPySip.tools.randomChr(30)
            self.__sipRinging(self.__userB, self.__userA)
            self.__status = self.RINGING
        elif self.CSeqTyp == 'ACK' and self.responseCodes == 'ACK sip:':
            self.server_addressS = socket.getaddrinfo(self.__auth.proxyServer, self.pcmuPort)[0][-1]
            self.call = True
            self.closeConnection()   
        elif self.CSeqTyp == 'BYE' and self.responseCodes == 'BYE sip:':
            self.__sipOK(self.__userB)
            self.call = False
            self.__status = self.IDLE
            self.closeConnection()
        elif self.CSeqTyp == 'CANCEL' and self.responseCodes == 'CANCEL sip:':
            self.__sipOK(self.__userB)
            self.call = False
            self.__status = self.IDLE

    def __readSIPdata(self):
        try:
            data = self.__f_sip.readline()
            print('-',data.decode(),end='')
            if (data==b'\r\n'):
                if (self.___contentLenght>0):
                    data=self.__f_sip.read(self.___contentLenght).decode()
                    for k in data.split('\r\n'):
                        print('*',k)
                        self.__parser(k.encode())
                self.__exec()
            elif len(data)>0:
                self.__parser(data)
            
        except OSError as e:
            self.logger.error("exception from sock_read.recvfrom {}".format(e))



    def __writeSIPdata(self, message):
        print(message,end='')
        __send = self.__f_sip.write(message.encode())


    def __send(self, server_addressS):
        t = utime.ticks_ms()
        tt = int(t/20) % 10000
        tt=tt.to_bytes(2, 'big')
        self.__buffer[2]=tt[0]
        self.__buffer[3]=tt[1]
        tt = int(t*8-t*8 % 160) % 1000000000
        tt=tt.to_bytes(4, 'big')
        self.__buffer[4]=tt[0]
        self.__buffer[5]=tt[1]
        self.__buffer[6]=tt[2]
        self.__buffer[7]=tt[3]
        __send = self.sock.sendto(self.__buffer, server_addressS)

    def __recive(self):
        try:       
            (data, proxyServer) = self.sock.recvfrom(180)
            a=uPySip.DTMF.DTMF().getKey(data)
            if a[1]>500000:
                self.__key=a[0]
                print(a[0])


        except OSError as msg:
            print("Socket Error: {}".format(msg))

    def acceptCall(self):
        self.__sipOK(self.__userB, self.__userA)
        self.__status = self.CALL_ACCEPT

    def getTelNrB(self):
        return self.__userB.fromB.split('sip:')[1].split('@')[0]
    

    def getKeyPressed(self):
        key=self.__key
        self.__key=''
        return key

    def record(self):
        self.__record=True
    
    def setConnection(self,__sock_SIP=None):

        if self.__sock_SIP==None:
            self.__sock_SIP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__sock_SIP.connect(socket.getaddrinfo( self.__auth.proxyServer , self.__auth.port)[0][-1])   
        if __sock_SIP!=None:        
            self.__sock_SIP=__sock_SIP
        if self.__f_sip==None:
            print('** on')
            self.__f_sip=self.__sock_SIP.makefile(mode='wrb', buffering=0)
            self.polling_object.register(self.__f_sip)
        self.__userB.viaB=''
   

    def closeConnection(self):
        print('** off')
        self.polling_object.unregister(self.__f_sip)
        self.__f_sip.close()
        self.__sock_SIP.close()
        self.__f_sip=None
        self.__sock_SIP=None
