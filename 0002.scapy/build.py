import struct
from scapy.all import *
conf.color_theme=NoTheme()

# === convert BYTE to STR
# s=chr(5) + chr(0) + "hello" + "world"
# print(":".join("{:02x}".format(ord(c)) for c in s))
# print(struct.unpack("<H", s[:2])[0])

# === convert BYTE to 8BIT
# print bin(int('ff', base=16))[2:]
# print bin(int('0f', base=16))[2:].zfill(8)
# print "{:0>8}".format(bin(int('0f', base=16))[2:])


# === 9Ps
# p=P9s("test", "default")
# print(p.getfield(None,s))
# s2=p.addfield(None,"","555")
# print(p.getfield(None,s2))

# === Field access
# p=rdpcap('5640-4.pcap')
# p=p.filter(lambda x:x.haslayer(P9))[:]
# print(p[23][P9].sprintf("%P9.wqid%"))
# print(p[23][P9].wqid)
# print(repr(p[23][P9].wqid))
# print("type = " + p[23][P9].fieldtype["wqid"].__repr__())
# print(p[23][P9].fields["wqid"])
# p.nsummary()
# hexdump(p[12][P9])
# hexdump(p[23][P9])
# p[23][P9].show()
# print(p[23][P9].sprintf("%P9.wqid%"))

p9types = { 100: "Tversion",  # size[4] Tversion tag[2]        msize[4] version[s]
            101: "Rversion",  # size[4] Rversion tag[2]        msize[4] version[s]
            102: "Tauth",     # size[4] Tauth    tag[2]                 afid[4] uname[s] aname[s]
            103: "Rauth",     # size[4] Rauth    tag[2]                 aqid[13]
            104: "Tattach",   # size[4] Tattach  tag[2] fid[4]          afid[4] uname[s] aname[s]
            105: "Rattach",   # size[4] Rattach  tag[2]                 qid[13]
            106: "Terror",    # illegal
            107: "Rerror",    # size[4] Rerror   tag[2]                 ename[s]
            108: "Tflush",    # size[4] Tflush   tag[2]                 oldtag[2]
            109: "Rflush",    # size[4] Rflush   tag[2]
            110: "Twalk",     # size[4] Twalk    tag[2] fid[4]          newfid[4] nwname[2] nwname*(wname[s])
            111: "Rwalk",     # size[4] Rwalk    tag[2]                 nwqid[2] nwqid*(wqid[13])
            112 : "Topen",     # size[4] Topen    tag[2] fid[4]          mode[1]
            113: "Ropen",     # size[4] Ropen    tag[2]                 qid[13] iounit[4]
            114 : "Tcreate",   # size[4] Tcreate  tag[2] fid[4]          name[s] perm[4] mode[1]
            115: "Rcreate",   # size[4] Rcreate  tag[2]                 qid[13] iounit[4]
            116 : "Tread",     # size[4] Tread    tag[2] fid[4]          offset[8] count[4]
            117 : "Rread",     # size[4] Rread    tag[2]                           count[4] data[count]
            118 : "Twrite",    # size[4] Twrite   tag[2] fid[4]          offset[8] count[4] data[count]
            119 : "Rwrite",    # size[4] Rwrite   tag[2]                           count[4]
            120: "Tclunk",    # size[4] Tclunk   tag[2] fid[4]
            121: "Rclunk",    # size[4] Rclunk   tag[2]
            122: "Tremove",   # size[4] Tremove  tag[2] fid[4]
            123: "Rremove",   # size[4] Rremove  tag[2]
            124: "Tstat",     # size[4] Tstat    tag[2] fid[4]
            125 : "Rstat",     # size[4] Rstat    tag[2]                 stat[n]
            126 : "Twstat",    # size[4] Twstat   tag[2] fid[4]          stat[n]
            127: "Rwstat" }   # size[4] Rwstat   tag[2]

# === stat[n]
# size[2]:      total byte count of the following data
# type[2]:      for kernel use
# dev[4]:       for kernel use
# qid.type[1]:  the type of the file (directory, etc.), represented as a bit vector corresponding to the high 8 bits of the files mode word.
# qid.vers[4]:  version number for given path
# qid.path[8]:  the file servers unique identification for the file
# mode[4]:      permissions and flags
# atime[4]:     last access time
# mtime[4]:     last modification time
# length[8]:    length of file in bytes
# name[ s ]:    file name; must be / if the file is the root directory of the server
# uid[ s ]:     owner name
# gid[ s ]:     group name
# muid[ s ]:    name of the user who last modified the file

class P9s(StrField):
    def m2i(self, pkt, x):
        return x[2:2+struct.unpack("<H", x[:2])[0]]
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        elif type(x) is not str:
            x=str(x)
        return "" + struct.pack("<H", len(x)) + x
    def getfield(self, pkt, s):
        str = self.m2i(pkt, s)
        return s[2+len(str):],str

class P9qid(StrFixedLenField):
    def i2repr(self, pkt, v):
        # type[1].version[4].path[8](summary[13])
        s  = "{0:0>8}".format(bin(ord(v[0:1]))[2:])
        s += '.' + "{0:0>10}".format(struct.unpack("<I", v[1:5])[0])
        s += '.' + "{0:0>20}".format(struct.unpack("<Q", v[5:])[0])
        s += '(' + ":".join("{0:02x}".format(ord(c)) for c in v[:]) + ')'
        return s

class P9lst(FieldListField):
    def i2repr(self, pkt, val):
        return '[%s]' % ', '.join(map(lambda v:self.field.i2repr(pkt, v), val))

class P9(Packet):
    name = "P9"
    fields_desc=[LEIntField("size",0),
                 ByteEnumField("type",106,p9types),
                 LEShortField("tag",0),
                 ConditionalField(LEIntField("fid", None), lambda pkt:pkt.type in [104,110,112,114,116,118,120,122,124,126]),
                 # Tversion, Rversion
                 ConditionalField(LEIntField("msize", None), lambda pkt:pkt.type in [100,101]),
                 ConditionalField(P9s("version", ""), lambda pkt:pkt.type in [100,101]),
                 # Tauth, Tattach
                 ConditionalField(LEIntField("afid", None), lambda pkt:pkt.type in [102,104]),
                 ConditionalField(P9s("uname", ""), lambda pkt:pkt.type in [102,104]),
                 ConditionalField(P9s("aname", ""), lambda pkt:pkt.type in [102,104]),
                 # Tflush
                 ConditionalField(LEShortField("oldtag",0), lambda pkt:pkt.type in [108]),
                 # Rerror
                 ConditionalField(LEShortField("esize",0), lambda pkt:pkt.type in [107]),
                 ConditionalField(StrLenField("ename", "", length_from=lambda pkt:pkt.esize), lambda pkt:pkt.type in [107]),
                 # Rauth
                 ConditionalField(P9qid("aqid", None, 13), lambda pkt:pkt.type in [103]),
                 # Rattach, Ropen, Rcreate
                 ConditionalField(P9qid("qid", None, 13), lambda pkt:pkt.type in [105,113,115]),
                 # Ropen, Rcreate
                 ConditionalField(LEIntField("iounit", None), lambda pkt:pkt.type in [113,115]),
                 # Twalk
                 ConditionalField(LEIntField("newfid", None), lambda pkt:pkt.type in [110]),
                 ConditionalField(FieldLenField("nwname", 0, count_of="wname", fmt="<H"), lambda pkt:pkt.type in [110]),
                 ConditionalField(P9lst("wname", [], P9s("", ""), count_from=lambda pkt:pkt.nwname), lambda pkt:pkt.type in [110]),
                 # Rwalk
                 ConditionalField(FieldLenField("nwqid", 0, count_of="wqid", fmt="<H"), lambda pkt:pkt.type in [111]),
                 ConditionalField(P9lst("wqid", [], P9qid("", None, 13), count_from=lambda pkt:pkt.nwqid), lambda pkt:pkt.type in [111]),
                ]
    def mysummary(self):
        s = self.sprintf("%2s,P9.tag% %P9.type%")
        #? replace uppper s += self.sprintf(" %7s,P9.type%")
        #where is fid? [104,110,112,114,116,118,120,122,124,126]
        if self.type in [100,101]:
            s += self.sprintf(" %P9.version%")
        if self.type in [102,104]:
            s += self.sprintf(" %P9.uname%")
        if self.type in [107]:
            s += self.sprintf(" %P9.ename%")
        if self.type in [108]:
            s += self.sprintf(" %P9.oldtag%")
        if self.type in [103]:
            s += self.sprintf(" %P9.aqid%")
        if self.type in [105,113,115]:
            s += self.sprintf(" %P9.qid%")
        if self.type in [113,115]:
            s += self.sprintf(" %P9.iounit%")
        if self.type in [110]:
            s += self.sprintf(" %P9.newfid%")
            s += self.sprintf(" %P9.nwname%")
            s += self.sprintf(" %P9.wname%")
        if self.type in [111]:
            s += self.sprintf(" %P9.nwqid%")
            s += self.sprintf(" %P9.wqid%")
        return s


bind_layers(TCP, P9, sport=5640)
bind_layers(TCP, P9, dport=5640)

p=rdpcap('5640-4.pcap')
p=p.filter(lambda x:x.haslayer(P9))[:]
#p.nsummary()
p[518][P9].show()
hexdump(p[518][P9])
hexdump(p[518][P9][Raw])
