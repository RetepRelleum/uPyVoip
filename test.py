import utime
path='/sd/data.pcmA'
f=open(path,'rb')
b=f.read(160)
t=utime.ticks_ms()

while len(b)==160:

    if utime.ticks_ms()-t>=200:
        t=utime.ticks_ms()
        for i in range(0,10):
            b=f.read(160)
            if len(b)!=160:
                break
            print(b[i],end='')
        print()
        print ('{:5}'.format(utime.ticks_ms()-t))

f.close()
