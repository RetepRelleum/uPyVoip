
import math
seg_aend = (0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF)
SEG_SHIFT = 4
QUANT_MASK = 0xf
SEG_MASK=	0x70	
SIGN_BIT=	0x80

def search(val, table, size):
    for i in range(0, size):
        if val <= table[i]:
	        return i
    return size


def linear2alaw(pcm_val):

    pcm_val = pcm_val >> 3

    if pcm_val >= 0:
        mask = 0xD5		# sign (7th) bit = 1 */
    else:
        mask = 0x55;		# sign bit = 0 */
        pcm_val = -pcm_val - 1

   # Convert the scaled magnitude to segment number. */
    seg = search(pcm_val, seg_aend, 8)

   # Combine the sign, segment, and quantization bits. */

    if (seg >= 8):		# out of range, return maximum value. */
        return (0x7F ^ mask)
    else:
        aval = seg << SEG_SHIFT
        if seg < 2:
	        aval |= (pcm_val >> 1) & QUANT_MASK
        else:
	        aval |= (pcm_val >> seg) & QUANT_MASK
        return (aval ^ mask)


def alaw2linear(a_val):

    a_val ^= 0x55
    t = (a_val & QUANT_MASK) << 4
    seg = (a_val & SEG_MASK) >> SEG_SHIFT
    if seg==0:
        t += 8
    elif seg== 1:
        t += 0x108
    else:
        t += 0x108
        t <<= seg - 1
    if (a_val & SIGN_BIT):
        return t
    else:
        return -t

           
def getSin(x):
    Fs = 8000
    f = 500
    return int(32768*math.sin(2 * math.pi* f * x / Fs))