import uPySip.sipMachine
import sys
import utime
import gc

port=5060
server='192.168.1.1'
client1='192.168.1.113'
client2='192.168.1.119'
telId1=225
telid2=226
if sys.platform=='linux':
    client=client1
    telId=telId1
else:
    client=client2
    telId=telid2

sipMachine=uPySip.sipMachine.SipMachine(user='relleum', pwd='jutkk7x1',telNr=telId,userAgent="b2b.domain",userClient=client,proxyServer=server,proxyRegistrar=server)
loop=True
first =False
warte=False

while loop>=0:
    loop=sipMachine.loop()
    if loop==sipMachine.RINGING:
        if int(sipMachine.getTelNrB())<300:
            sipMachine.acceptCall()
            warte=False
    if sipMachine.IDLE!=loop:
        pass
        #print(loop)
    if sipMachine.IDLE==loop:
        if first:
            sipMachine.invite('222')
            first=False
    if sipMachine.ON_CALL==loop:
        if warte and utime.ticks_ms()%5000==0:
            sipMachine.play('/sd/warte.aLaw')
        keyPressed=sipMachine.getKeyPressed()
        if keyPressed!='':
            if keyPressed=='0':
               sipMachine.play('/sd/wilk.aLaw')
            if keyPressed=='1':
               sipMachine.play('/sd/info.aLaw')
            if keyPressed=='2':
               sipMachine.play('/sd/info.aLaw')
            if keyPressed=='3':
                sipMachine.play('/sd/warte.aLaw')
                warte=True
