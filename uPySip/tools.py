import sys
import os




def randomChr(size):
    ret = ""
    a = 0
    while a < size:
        try:
            b = os.urandom(10)[5]
            if (b >= 48 and b < 58) or (b > 64 and b < 91) or (b > 97 and b < 123):
                ret = '{}{}'.format(ret, chr(b))
                a = a+1
        except:
            pass
    return ret

