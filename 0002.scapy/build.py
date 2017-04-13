import struct
from scapy.all import *
conf.color_theme=NoTheme()

# === convert BYTE to STR
# s=chr(5) + chr(0) + "hello" + "world"
# print(":".join("{:02x}".format(ord(c)) for c in s))
# print(struct.unpack("<H", s[:2])[0])

# === convert BYTE to CHAR
# print(chr(int('7a',16)))

# === convert BYTE to 8BIT
# print bin(int('ff', base=16))[2:]
# print bin(int('0f', base=16))[2:].zfill(8)
# print "{:0>8}".format(bin(int('0f', base=16))[2:])

# === QID
# s  = "{0:0>8}".format(bin(x.type)[2:])
# s  = "{0:0>8}".format(bin(ord(v[0:1]))[2:])
# s += '.' + "{0:0>10}".format(struct.unpack("<I", v[1:5])[0])
# s += '.' + "{0:0>20}".format(struct.unpack("<Q", v[5:])[0])
# s += '(' + ":".join("{0:02x}".format(ord(c)) for c in v[:]) + ')'

# === QID test
# a = P9C("qid", None, QID)
# s = a.addfield(None, "", QID(QID.DIR | QID.TMP, 16, 32))
# s = a.addfield(None, s, QID(QID.FILE | QID.TMP, 64, 128))
# s,v1 = a.getfield(None, s)
# s,v2 = a.getfield(None, s)
# print(a.i2h(None, v1))
# print(a.i2h(None, v2))

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

#class P9stat(P9s):
#    pass
# === stat[n]
# size[2]:      total byte count of the following data
# type[2]:      for kernel use
# dev[4]:       for kernel use
# qid.type[1]:  the type of the file (directory, etc.)
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

# === param[n]: n-const
class P9N(Field):
    def __init__(self, name, size, default=-1):
        if size == 2:
            Field.__init__(self, name, default, "<H")
        elif size == 4:
            Field.__init__(self, name, default, "<I")
        else:
            warning("This type is not handled")
            Field.__init__(self, name, default)

class P9Ntag(P9N):
    # all
    # distinct concurrent messages
    def __init__(self):
        P9N.__init__(self, "tag", 2)

class P9Noldtag(P9N):
    # 108:Tflush
    # force tag to be free
    def __init__(self):
        P9N.__init__(self, "oldtag", 2)

class P9Nsize(P9N):
    # all
    # TODO: add lambda function to calculate package size
    def __init__(self):
        P9N.__init__(self, "size", 4)

class P9Nmsize(P9N):
    # 100:Tversion, 101:Rversion
    # maximum supported length
    def __init__(self):
        P9N.__init__(self, "msize", 4, 8192)

class P9Nfid(P9N):
    # 104:Tattach, 110:Twalk, 112:Topen, 114:Tcreate, 116:Tread, 118:Twrite, 120:Tclunk, 122:Tremove, 124:Tstat, 126:Twstat
    # file id, choosen by client
    def __init__(self):
        P9N.__init__(self, "fid", 4)

class P9Nafid(P9N):
    # 102:Tauth, 104:Tattach
    # auth file id
    def __init__(self):
        P9N.__init__(self, "afid", 4)

class P9Nnewfid(P9N):
    # 110:Twalk
    # new approved file id
    def __init__(self):
        P9N.__init__(self, "newfid", 4)

class P9Niounit(P9N):
    # 113:Ropen, 115:Rcreate
    # TODO: what is that
    def __init__(self):
        P9N.__init__(self, "iounit", 4)

class P9Nnwname(P9N):
    # 110:Twalk
    # size
    def __init__(self, count_of):
        P9N.__init__(self, "nwname", 2, 0)
        self.count_of=count_of
    def i2m(self, pkt, x):
        if x is None:
            fld,fval = pkt.getfield_and_val(self.count_of)
            x = fld.i2count(pkt, fval)
        return x

class P9Nnwqid(P9N):
    # 111:Rwalk
    # size
    def __init__(self, count_of):
        P9N.__init__(self, "nwqid", 2, 0)
        self.count_of=count_of
    def i2m(self, pkt, x):
        if x is None:
            fld,fval = pkt.getfield_and_val(self.count_of)
            x = fld.i2count(pkt, fval)
        return x

# === string[s]: s[2] + s bytes
class P9S(Field):
    def m2i(self, pkt, x):
        return x[2:2+struct.unpack("<H", x[:2])[0]]
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        elif type(x) is not str:
            x=str(x)
        return "" + struct.pack("<H", len(x)) + x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def getfield(self, pkt, s):
        str = self.m2i(pkt, s)
        return s[2+len(str):],str

class P9Sversion(P9S):
    def __init__(self, default="9P2000"):
        P9S.__init__(self, "version", default)
class P9Suname(P9S):
    def __init__(self, default=""):
        P9S.__init__(self, "uname", default)
class P9Saname(P9S):
    def __init__(self, default=""):
        P9S.__init__(self, "aname", default)
class P9Sename(P9S):
    def __init__(self, default=""):
        P9S.__init__(self, "ename", default)
class P9Sstat(P9S):
    def __init__(self, default=""):
        P9S.__init__(self, "stat", default)

# === composed with subfields
#class P9C(Field):
#    def __init__(self, name, default, length, cls):
#        Field.__init__(self, name, default, "%is"%length)
#        self.cls = cls

class P9qid(StrFixedLenField):
    def i2repr(self, pkt, v):
        # type[1].version[4].path[8](summary[13])
        s  = "{0:0>8}".format(bin(ord(v[0:1]))[2:])
        s += '.' + "{0:0>10}".format(struct.unpack("<I", v[1:5])[0])
        s += '.' + "{0:0>20}".format(struct.unpack("<Q", v[5:])[0])
        s += '(' + ":".join("{0:02x}".format(ord(c)) for c in v[:]) + ')'
        return s

# === list
# TODO: pack into one field
class P9L(Field):
    def __init__(self, name, field, count_from):
        default = []
        Field.__init__(self, name, default)
        self.count_from = count_from
        self.field = field

    def i2count(self, pkt, val):
        if type(val) is list:
            return len(val)
        return 1
    def i2len(self, pkt, val):
        return sum( self.field.i2len(pkt,v) for v in val )
    def i2m(self, pkt, val):
        if val is None:
            val = []
        return val
    def any2i(self, pkt, x):
        if type(x) is not list:
            return [x]
        return x
    def i2repr(self, pkt, val):
        return '[%s]' % ', '.join(map(lambda v:self.field.i2repr(pkt, v), val))

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        for v in val:
            s = self.field.addfield(pkt, s, v)
        return s
    def getfield(self, pkt, s):
        #c = self.count_from(pkt)
        c = pkt.getfieldval(self.count_from)
        val = []
        while s:
            if c <= 0:
                break

            c -= 1
            s,v = self.field.getfield(pkt, s)
            val.append(v)
        return s, val

class P9Lwname(P9L):
    def __init__(self, count_from):
        P9L.__init__(self, "wname", P9S("", ""), count_from=count_from)

class P9Lwqid(P9L):
    def __init__(self, count_from):
        P9L.__init__(self, "wqid", P9qid("", None, 13), count_from=count_from)


class P9(Packet):
    name = "P9"
    fields_desc=[P9Nsize(),
                 ByteEnumField("type",106,p9types),
                 P9Ntag(),
                 ConditionalField(P9Nfid(), lambda pkt:pkt.type in [104,110,112,114,116,118,120,122,124,126]),
                 # Tversion, Rversion
                 ConditionalField(P9Nmsize(), lambda pkt:pkt.type in [100,101]),
                 ConditionalField(P9Sversion(), lambda pkt:pkt.type in [100,101]),
                 # Tauth, Tattach
                 ConditionalField(P9Nafid(), lambda pkt:pkt.type in [102,104]),
                 ConditionalField(P9Suname(), lambda pkt:pkt.type in [102,104]),
                 ConditionalField(P9Saname(), lambda pkt:pkt.type in [102,104]),
                 # Tflush
                 ConditionalField(P9Noldtag(), lambda pkt:pkt.type in [108]),
                 # Rerror
                 ConditionalField(P9Sename(), lambda pkt:pkt.type in [107]),
                 # Rauth
                 ConditionalField(P9qid("aqid", None, 13), lambda pkt:pkt.type in [103]),
                 # Rattach, Ropen, Rcreate
                 ConditionalField(P9qid("qid", None, 13), lambda pkt:pkt.type in [105,113,115]),
                 # Ropen, Rcreate
                 ConditionalField(P9Niounit(), lambda pkt:pkt.type in [113,115]),
                 # Twalk
                 ConditionalField(P9Nnewfid(), lambda pkt:pkt.type in [110]),
                 ConditionalField(P9Nnwname(count_of="wname"), lambda pkt:pkt.type in [110]),
                 ConditionalField(P9Lwname(count_from="nwname"), lambda pkt:pkt.type in [110]),
                 # Rwalk
                 ConditionalField(P9Nnwqid(count_of="wqid"), lambda pkt:pkt.type in [111]),
                 ConditionalField(P9Lwqid(count_from="nwqid"), lambda pkt:pkt.type in [111]),
                 # Rstat, Twstat
                 ConditionalField(P9Sstat(), lambda pkt:pkt.type in [125,126]),
                ]
    def mysummary(self):
        s = self.sprintf("%2s,P9.tag% %P9.type%")
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
        if self.type in [125,126]:
            s += self.sprintf(" %P9.stat%")
        return s


bind_layers(TCP, P9, sport=5640)
bind_layers(TCP, P9, dport=5640)

#p=rdpcap('5640-4.pcap')
#p=p.filter(lambda x:x.haslayer(P9))[:]
#p.nsummary()
##p[518][P9].show()


class P9C(Field):
    """13-bytes qid"""
    length  = 13

    DIR     = 0x80 # directories
    APPEND  = 0x40 # append only files
    EXCL    = 0x20 # exclusive use files
    MOUNT   = 0x10 # mounted channel
    AUTH    = 0x08 # authentication file
    TMP     = 0x04 # non-backed-up file
    SYMLINK = 0x02 # symbolic link
    FILE    = 0x00 # plain file

    def __init__(self, name, default):
        Field.__init__(self, name, default, "13s")
    def i2m(self, pkt, x):
        """Convert internal(class) representation to machine(then packed by fmt) value"""
        (type, vers, path) = x
        return struct.pack("<BIQ", type, vers, path)
    def m2i(self, pkt, x):
        """Convert unpacked(fmt, from machine value) to internal(class) representation"""
        if x == '': return None
        type = ord(x[0:1])
        vers = struct.unpack("<I", x[1:5])[0]
        path = struct.unpack("<Q", x[5:])[0]
        return (type, vers, path)
    def getfield(self, pkt, s):
        l = self.length
        return s[l:], self.m2i(pkt,s[:l])
    def addfield(self, pkt, s, val):
        l = self.length
        return s+struct.pack("%is"%l,self.i2m(pkt, val))
    def i2h(self, pkt, x):
        (type, vers, path) = x
        s = ":".join("{0:02x}".format(ord(c)) for c in self.i2m(pkt, x))
        s += ' ('
        if (P9C.DIR & type): s += 'DIR'
        else: s += 'FILE'
        if (P9C.APPEND & type): s += '|APPEND'
        if (P9C.EXCL & type): s += '|EXCL'
        if (P9C.MOUNT & type): s += '|MOUNT'
        if (P9C.AUTH & type): s += '|AUTH'
        if (P9C.TMP & type): s += '|TMP'
        if (P9C.SYMLINK & type): s += '|SYMLINK'
        s += ',' + str(vers)
        s += ',' + str(path)
        s += ')'
        return s

a = P9C("qid", None)
s = a.addfield(None, "", (P9C.DIR | P9C.TMP, 16, 32))
s = a.addfield(None, s, (P9C.FILE | P9C.TMP, 64, 128))
s,v1 = a.getfield(None, s)
s,v2 = a.getfield(None, s)
print(a.i2h(None, v1))
print(a.i2h(None, v2))




#class P92000(Packet):
#    name = "P92000"
#    fields_desc=[P9C("qid", None, P9C)]
#p2 = P92000(qid=P9C(P9C.FILE | P9C.TMP, 16, 32))
#print(repr(P9C.fromstr(str(p2))))
