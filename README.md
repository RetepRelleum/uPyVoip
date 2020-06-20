# uPyVoip
Voip for MicroPython ESP32 and Python 3

It is an interactive voice response for Micropython and Python 3

Voip API for MicroPython tested on a Lolin d32 Pro under MicroPython version 1.12

Installation
Copy aLAW.py, md5.py, sipMachine.py and DTMF.py into the directory / lib / uPySip.
The file uSipB2Bua.py
Copy to the root directory. As well as your language files in Alaw format on the SD card.

uPyVoip is a real Python implementation and adapted to MicroPython.

You can create the language files using Audacity in PCM16 bit format with a sample rate of 8000 Hz and save them via Export-> Raw data. using conv.py you have to change them to Alaw format.

