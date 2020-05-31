import uPySip.tools
import uPySip.sipMachine
import sys
import time

logger = uPySip.tools.getLogger(__name__)

port=5060
server='192.168.1.1'
client1='192.168.1.113'
client2='192.168.1.119'
telId1=225
telid2=226
if sys.platform=='linux':
    client=client1
    telId=telId1
    uPySip.tools.basicConfig(level=uPySip.tools.DEBUG)
else:
    client=client2
    telId=telid2
    uPySip.tools.basicConfig(level=uPySip.tools.WARNING)

sipMachine=uPySip.sipMachine.SipMachine(user='relleum', pwd='jutkk7x1',telNrA=telId,UserAgentA="b2b.domain",userClient=client,proxyServer=server,proxyRegistrar=server)


loop=True

first =True

while loop>=0:
    loop=sipMachine.loop()
    if loop==sipMachine.RINGING:
        if sipMachine.getTelNrB()=='222':
            sipMachine.acceptCall()
    if sipMachine.IDLE!=loop:
        pass
        #print(loop)
    if sipMachine.IDLE==loop:
        if first:
            sipMachine.invite('222')
            first=False

           

  
