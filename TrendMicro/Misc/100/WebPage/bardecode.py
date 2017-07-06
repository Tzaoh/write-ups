#!python

from PIL import Image
import struct
import bitstring

img = Image.open("barcode1.png");

pix = img.load();

max_x, max_y = img.size
s = ''
for y in range(0, max_y):
    for x in range(0, max_x):
        _, _, _, value = pix[x, y]        
        s += '0' if value == 0 else '1'

result = bitstring.BitArray(bin=s).tobytes()
print(result)