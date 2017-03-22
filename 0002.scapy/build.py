from scapy.all import *
conf.color_theme=NoTheme()

p9types = { 100 : "Tversion",  # size[4] Tversion tag[2]        msize[4] version[s]
            101 : "Rversion",  # size[4] Rversion tag[2]        msize[4] version[s]
            102 : "Tauth",     # size[4] Tauth    tag[2]                 afid[4] uname[s] aname[s]
            103 : "Rauth",     # size[4] Rauth    tag[2]                 aqid[13]
            104 : "Tattach",   # size[4] Tattach  tag[2] fid[4]          afid[4] uname[s] aname[s]
            105 : "Rattach",   # size[4] Rattach  tag[2]                 qid[13]
            106 : "Terror",    # illegal                                 
            107 : "Rerror",    # size[4] Rerror   tag[2]                 ename[s]
            108 : "Tflush",    # size[4] Tflush   tag[2]                 oldtag[2]
            109 : "Rflush",    # size[4] Rflush   tag[2]                 
            110 : "Twalk",     # size[4] Twalk    tag[2] fid[4]          newfid[4] nwname[2] nwname*(wname[s])
            111 : "Rwalk",     # size[4] Rwalk    tag[2]                 nwqid[2] nwqid*(wqid[13])
            112 : "Topen",     # size[4] Topen    tag[2] fid[4]          mode[1]
            113 : "Ropen",     # size[4] Ropen    tag[2]                 qid[13] iounit[4]
            114 : "Tcreate",   # size[4] Tcreate  tag[2] fid[4]          name[s] perm[4] mode[1]
            115 : "Rcreate",   # size[4] Rcreate  tag[2]                 qid[13] iounit[4]
            116 : "Tread",     # size[4] Tread    tag[2] fid[4]          offset[8] count[4]
            117 : "Rread",     # size[4] Rread    tag[2]                           count[4] data[count]
            118 : "Twrite",    # size[4] Twrite   tag[2] fid[4]          offset[8] count[4] data[count]
            119 : "Rwrite",    # size[4] Rwrite   tag[2]                           count[4]
            120 : "Tclunk",    # size[4] Tclunk   tag[2] fid[4]          
            121 : "Rclunk",    # size[4] Rclunk   tag[2]                 
            122 : "Tremove",   # size[4] Tremove  tag[2] fid[4]          
            123 : "Rremove",   # size[4] Rremove  tag[2]                 
            124 : "Tstat",     # size[4] Tstat    tag[2] fid[4]          
            125 : "Rstat",     # size[4] Rstat    tag[2]                 stat[n]
            126 : "Twstat",    # size[4] Twstat   tag[2] fid[4]          stat[n]
            127 : "Rwstat" }   # size[4] Rwstat   tag[2]


class P9(Packet):
    name = "P9"
    fields_desc=[LEIntField("size",0),
                 ByteEnumField("type",106,p9types),
                 LEShortField("tag",0),
                 ConditionalField(LEIntField("fid", None), lambda pkt:pkt.type in [104,110,112,114,116,118,120,122,124,126]),
                 ConditionalField(LEIntField("msize", None), lambda pkt:pkt.type in [100,101]),
                 ConditionalField(LEShortField("vsize",0), lambda pkt:pkt.type in [100,101]),
				 ConditionalField(StrLenField("version", "", length_from=lambda pkt:pkt.vsize), lambda pkt:pkt.type in [100,101])
                ]
    def mysummary(self):
        #cond = '{0}'.format()
        s = self.sprintf("%P9.tag% %P9.type%") # TODO: add conditional %P9.msize
        return s

                                            
bind_layers(TCP, P9, sport=5640)
bind_layers(TCP, P9, dport=5640)

p=rdpcap('5640-2.pcap')
p=p.filter(lambda x:x.haslayer(P9))[:]

p.summary()
p[0][P9].show()
hexdump(p[0][P9])
#p[3][TCP].show()
#p[3][TCP].show()
#p[5][TCP].show()
#hexdump(p[3][P9])
#hexdump(p[5][P9])
