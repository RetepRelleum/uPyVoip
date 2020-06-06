import cmath,math
import time
import uPySip.aLaw

class DTMF:
    def __fft(self,x):
        N = len(x)
        if N <= 1: return x
        even = self.__fft(x[0::2])
        odd =  self.__fft(x[1::2])
        T= [cmath.exp(-2j*cmath.pi*k/N)*odd[k] for k in range(N//2)]
        return [even[k] + T[k] for k in range(N//2)] + [even[k] - T[k] for k in range(N//2)]

    def getKey(self,x):
        if len(x)<128:
            if x[2]==0x1:
                return '1',600000
            elif x[2]==0x2:
                return '2',600000
            elif x[2]==0x3:
                return '3',600000
            elif x[2]==0x4:
                return '4',600000
            elif x[2]==0x5:
                return '5',600000
            elif x[2]==0x6:
                return '6',600000
            elif x[2]==0x7:
                return '7',600000
            elif x[2]==0x8:
                return '8',600000
            elif x[2]==0x9:
                return '9',600000
            else:
                return '0',600000
        x=uPySip.aLaw.alawArr2linearArry( x[12:172])
        list=[['1',19,11],['2',21,11],['3',24,11],['4',19,12],['5',21,12],['6',24,12],['7',19,14],['8',21,14],['9',24,14],['*',19,15],['0',21,15],['#',24,15]]
        res=self.__fft(x[0:128])
        max=0
        ret=''
        for b in list:
            temp=abs(res[b[1]])+abs(res[b[2]])
            if max< temp:
                max=temp
                ret=b[0]
        return ret,max
    
    def keyPressed(self,key):
        Fs = 8000
        if key=='1':
            f1 = 1209
            f2= 697
        elif key=='2':
            f1 = 1336
            f2= 697
        elif key=='3':
            f1 = 1477
            f2= 697
        elif key=='4':
            f1 = 1209
            f2= 770
        elif key=='5':
            f1 = 1336
            f2= 770
        elif key=='6':
            f1 = 1477
            f2= 770
        elif key=='7':
            f1 = 1209
            f2= 852
        elif key=='8':
            f1 = 1336
            f2= 852
        elif key=='9':
            f1 = 1477
            f2= 852
        elif key=='*':
            f1 = 1209
            f2= 941
        elif key=='0':
            f1 = 1336
            f2= 941
        elif key=='#':
            f1 = 1477
            f2= 941
        else:
            return None
        ff=[]
        for x in range(0,160):
            ff.append(16383* math.sin(2 * cmath.pi * f1 * x / Fs)+16383* math.sin(2 * cmath.pi * f2 * x / Fs))
        return ff

 
#          1209 Hz 1336 Hz 1477 Hz 1633 Hz
# 697  Hz  1       2       3       A 
# 770  Hz  4       5       6       B 
# 852  Hz  7       8       9       C 
# 941  Hz  *       0       #       D 




