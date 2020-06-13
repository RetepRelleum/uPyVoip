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
        ret=''
        if len(x)<128:
            ret='{}'.format(x[12])
            if x[12]==10:
                ret='{}'.format('*')      
            elif x[12]==11:
                ret='{}'.format('#')             
            return ret,600000
        x=uPySip.aLaw.alawArr2linearArry( x[12:172])
        list=[['1',19,11],['2',21,11],['3',24,11],['4',19,12],['5',21,12],['6',24,12],['7',19,14],['8',21,14],['9',24,14],['*',19,15],['0',21,15],['#',24,15]]
        res=self.__fft(x[0:128])
        max=0
        for b in list:
            temp=abs(res[b[1]])+abs(res[b[2]])
            if max< temp:
                max=temp
                ret=b[0]
        return ret,max
    
    def keyPressed(self,key):
        Fs = 8000
        if key=='*':
            key=10
        if key=='0':
            key=11
        if key=='#':
            key==12
        key=int(key)-1
        toene=[697,770,852,941,1209,1336,1477]
        map=[[4,0],[5,0],[6,0],[4,1],[5,1],[6,1],[4,2],[5,2],[6,2],[4,3],[5,3],[6,3]]
        ff=[]
        for x in range(0,160):
            ff.append(16383* math.sin(2 * cmath.pi * toene[map[key][0]] * x / Fs)+16383* math.sin(2 * cmath.pi * toene[map[key][1]]  * x / Fs))
        return ff

 
#          1209 Hz 1336 Hz 1477 Hz 1633 Hz
# 697  Hz  1       2       3       A 
# 770  Hz  4       5       6       B 
# 852  Hz  7       8       9       C 
# 941  Hz  *       0       #       D 




