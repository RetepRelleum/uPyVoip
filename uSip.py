import uPySip.tools
import uPySip.sipMachine
import sys
import time


logger = uPySip.tools.getLogger(__name__)
uPySip.tools.basicConfig(level=uPySip.tools.DEBUG)


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

sipMachine=uPySip.sipMachine.SipMachine(user='relleum', pwd='jutkk7x1',telNrA=telId,UserAgentA="b2b.domain",userClient=client,ProxyServer=server)
timestamp= time.time()

while timestamp+9900>time.time():
 #   sipMachine.run()
    time.sleep(0.1)
