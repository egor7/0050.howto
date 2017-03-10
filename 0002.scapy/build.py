from scapy.all import *

a=IP(dst="ya.ru", id=0x42)
print(repr(a))
a.show()
