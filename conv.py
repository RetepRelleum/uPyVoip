import uPySip.aLaw
l=open('/sd/info.aLaw','wb')
f=open('/sd/info.raw','rb')
b=True
while b:
    b=f.read(2)
    a=int.from_bytes(b, byteorder='little',signed=True)
    c=uPySip.aLaw.linear2alaw(a)
    l.write(bytes([c]))
l.close()
f.close()

