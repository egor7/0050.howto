from scapy.all import *
conf.color_theme=NoTheme()

class P9(Packet):
    name = "P9"
    fields_desc=[LEIntField("size",0),
                 ByteField("type",0),
                 LEShortField("tag",0)]

#p1=P9(size=11, type=1, tag=123)
#hexdump(p1)

bind_layers(TCP, P9, sport=5640)
bind_layers(TCP, P9, dport=5640)
p=rdpcap('5640.pcap')
p[0][TCP].show()
hexdump(p[0][P9])
