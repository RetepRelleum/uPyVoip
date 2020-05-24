import uPySip.tools
import socket
import time

import _thread
import os
import uPySip.aLaw



class PcmA:
    def __init__(self, port: int, serverIp: str, clientIp):
        self.logg = False
        self.logger = uPySip.tools.getLogger(__name__)
        self.logger.info("__init_pcmu port {} server {}: \r\n\r\n".format(port, serverIp))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_addressR = socket.getaddrinfo(clientIp, 17000)[0][-1]
        self.server_addressS = socket.getaddrinfo(serverIp, port)[0][-1]
        self.sock.settimeout(10)
        self.sock.bind(self.server_addressR)

        self.run = True
        self.SSRC = uPySip.tools.randomChr(4).encode()
        self.threadIdSend = _thread.start_new_thread(self.send, ())
        self.threadIdRecive = _thread.start_new_thread(self.recive, ())


    def send(self):
        self.logger = uPySip.tools.getLogger(__name__)
        self.logger.info("pcmu send start: \r\n\r\n")

        b = bytearray()
        b.append(0x80)
        b.append(0x08)
        t = time.time()
        tt = int(t*50) % 10000
        b.extend(tt.to_bytes(2, 'big'))
        tt = int(t*8000-t*8000 % 160) % 1000000000
        b.extend(tt.to_bytes(4, 'big'))
        b.append(self.SSRC[0])
        b.append(self.SSRC[1])
        b.append(self.SSRC[2])
        b.append(self.SSRC[3])
        tx = time.time()
        x=0
        while self.run:
            try:
                for x in range(0,160):
                    b.append(uPySip.aLaw.linear2alaw(uPySip.aLaw.getSin(x)))
                if (len(b) == 172):
                    x=0
                    tx += 0.02
                    if (time.time()-tx < 0):
                        time.sleep(abs(time.time()-tx))
                    send = self.sock.sendto(bytes(b), self.server_addressS)
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
                    b=bytearray()
                    b.append(0x80)
                    b.append(0x08)
                    t = time.time()
                    tt = int(t*50) % 10000
                    b.extend(tt.to_bytes(2, 'big'))
                    tt = int(t*8000-t*8000 % 160) % 1000000000
                    b.extend(tt.to_bytes(4, 'big'))
                    b.append(self.SSRC[0])
                    b.append(self.SSRC[1])
                    b.append(self.SSRC[2])
                    b.append(self.SSRC[3])

            except OSError  as msg:
                print("Socket Error: {}".format( msg))
        self.sock.close()
        self.logger.info("pcmu send end: \r\n\r\n")

    def recive(self):
        self.logger = uPySip.tools.getLogger(__name__)
        self.logger.info("pcmu recive start: \r\n\r\n")

        while self.run:
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

            except OSError as msg :
                print("Socket Error: {}".format(msg))

        self.logger.info("pcmu recive end: \r\n\r\n")

