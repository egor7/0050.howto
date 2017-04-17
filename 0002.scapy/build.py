import struct,string,re
from scapy.all import *
from time import strftime,gmtime
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

# === QID test
# a = P9qid("qid")
# s = a.addfield(None, "", (P9qid.DIR | P9qid.TMP, 16, 32))
# s = a.addfield(None, s, (P9qid.FILE | P9qid.TMP, 64, 128))
# s,v1 = a.getfield(None, s)
# s,v2 = a.getfield(None, s)
# print(a.i2h(None, v1))
# print(a.i2h(None, v2))
#
# class P92000(Packet):
#     name = "P92000"
#     fields_desc=[P9C("qid", None, P9C)]
# p2 = P92000(qid=P9C(P9qid.FILE | P9qid.TMP, 16, 32))
# print(repr(P9qid.fromstr(str(p2))))

# # === P9stat test
# a = P9stat("stat")
# s = a.addfield(None, "", ((P9qid.DIR | P9qid.TMP, 16, 32),0,0,0,0,'t1','e1','s1','t1'))
# s = a.addfield(None, s, ((P9qid.FILE | P9qid.TMP, 64, 128),0,0,0,0,'t2','e2','s2','t2'))
# s,v1 = a.getfield(None, s)
# s,v2 = a.getfield(None, s)
# print(a.i2h(None, v1))
# print(a.i2h(None, v2))
# print(a.i2repr(None, v1))
# print(a.i2repr(None, v2))

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

# === Build/dissect
# 1.#p=p.filter(lambda x:x.haslayer(Raw))[:]
# 2. #p=p.filter(lambda x:x.haslayer(P9))[:]
# 1.#print "\n".join(":".join("{0:02x}".format(ord(c)) for c in str(pkt[Raw])) for pkt in p)
# 2. #print "\n".join(":".join("{0:02x}".format(ord(c)) for c in str(pkt[P9])) for pkt in p)


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
            112: "Topen",     # size[4] Topen    tag[2] fid[4]          mode[1]
            113: "Ropen",     # size[4] Ropen    tag[2]                 qid[13] iounit[4]
            114: "Tcreate",   # size[4] Tcreate  tag[2] fid[4]          name[s] perm[4] mode[1]
            115: "Rcreate",   # size[4] Rcreate  tag[2]                 qid[13] iounit[4]
            116: "Tread",     # size[4] Tread    tag[2] fid[4]          offset[8] count[4]
            117 : "Rread",     # size[4] Rread    tag[2]                           count[4] data[count]
            118 : "Twrite",    # size[4] Twrite   tag[2] fid[4]          offset[8] count[4] data[count]
            119: "Rwrite",    # size[4] Rwrite   tag[2]                           count[4]
            120: "Tclunk",    # size[4] Tclunk   tag[2] fid[4]
            121: "Rclunk",    # size[4] Rclunk   tag[2]
            122: "Tremove",   # size[4] Tremove  tag[2] fid[4]
            123: "Rremove",   # size[4] Rremove  tag[2]
            124: "Tstat",     # size[4] Tstat    tag[2] fid[4]
            125: "Rstat",     # size[4] Rstat    tag[2]                 stat[n]
            126: "Twstat",    # size[4] Twstat   tag[2] fid[4]          stat[n]
            127: "Rwstat" }   # size[4] Rwstat   tag[2]

# === param[n]: n-const
class P9N(Field):
    def __init__(self, name, size, default=-1):
        if size == 1:
            Field.__init__(self, name, default, "<B")
        elif size == 2:
            Field.__init__(self, name, default, "<H")
        elif size == 4:
            Field.__init__(self, name, default, "<I")
        elif size == 8:
            Field.__init__(self, name, default, "<Q")
        else:
            warning("This type is not handled")
            Field.__init__(self, name, default)

class P9Ntag(P9N):
    # all
    # distinct concurrent messages
    def __init__(self):
        P9N.__init__(self, "tag", 2)

class P9Nmode(P9N):
    # 112:Topen, 114:Tcreate
    OREAD     = 0   # open for read
    OWRITE    = 1   # write
    ORDWR     = 2   # read and write
    OEXEC     = 3   # execute, == read but check execute permission
    OTRUNC    = 16  # or'ed in (except for exec), truncate file first
    OCEXEC    = 32  # or'ed in, close on exec
    ORCLOSE   = 64  # or'ed in, remove on close
    ODIRECT   = 128 # or'ed in, direct access
    ONONBLOCK = 256 # or'ed in, non-blocking call
    def __init__(self):
        P9N.__init__(self, "mode", 1)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        s = ""
        if (x == self.OREAD    ): s += "|OREAD"
        if (x == self.OWRITE   ): s += "|OWRITE"
        if (x == self.ORDWR    ): s += "|ORDWR"
        if (x == self.OEXEC    ): s += "|OEXEC"
        if (x == self.OTRUNC   ): s += "|OTRUNC"
        if (x == self.OCEXEC   ): s += "|OCEXEC"
        if (x == self.ORCLOSE  ): s += "|ORCLOSE"
        if (x == self.ODIRECT  ): s += "|ODIRECT"
        if (x == self.ONONBLOCK): s += "|ONONBLOCK"
        if (x!=self.OREAD and x!=self.OWRITE and x!=self.ORDWR and x!=self.OEXEC and x!=self.OTRUNC and x!=self.OCEXEC and x!=self.ORCLOSE and x!=self.ODIRECT and x!=self.ONONBLOCK): s += "|OUNKNOWN"
        return s[1:]

class P9Noldtag(P9N):
    # 108:Tflush
    # force tag to be free
    def __init__(self):
        P9N.__init__(self, "oldtag", 2)

class P9Nperm(P9N):
    # 114:Tcreate
    DIR     = 0x80 # directories
    APPEND  = 0x40 # append only files
    EXCL    = 0x20 # exclusive use files
    MOUNT   = 0x10 # mounted channel
    AUTH    = 0x08 # authentication file
    TMP     = 0x04 # non-backed-up file
    SYMLINK = 0x02 # symbolic link
    FILE    = 0x00 # plain file
    def __init__(self):
        P9N.__init__(self, "perm", 4)
    def i2repr(self, pkt, mode):
        """Convert internal value to a nice representation"""
        s = ""
        if (P9qid.DIR     & (mode & 0xFF000000)>>3*8): s += 'DIR-'
        if (P9qid.APPEND  & (mode & 0xFF000000)>>3*8): s += 'APPEND-'
        if (P9qid.EXCL    & (mode & 0xFF000000)>>3*8): s += 'EXCL-'
        if (P9qid.MOUNT   & (mode & 0xFF000000)>>3*8): s += 'MOUNT-'
        if (P9qid.AUTH    & (mode & 0xFF000000)>>3*8): s += 'AUTH-'
        if (P9qid.TMP     & (mode & 0xFF000000)>>3*8): s += 'TMP-'
        if (P9qid.SYMLINK & (mode & 0xFF000000)>>3*8): s += 'SYMLINK-'
        #s += str(oct(mode & 0x0000FFFF))
        s += "%04o" % (mode & 0x0000FFFF)
        #s += '{0:4o}'.format(int((mode & 0x0000FFFF)))
        return s

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

class P9Noffset(P9N):
    # 116:Tread, 118:Twrite
    def __init__(self):
        P9N.__init__(self, "offset", 8)

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

class P9Ncount(P9N):
    # 116:Tread, 117:Rread, 118:Twrite, 119:Rwrite
    # size
    def __init__(self, length_of=None, count_of=None):
        P9N.__init__(self, "count", 4, 0)
        # TODO: move to parent
        self.length_of=length_of
        self.count_of=count_of
    def i2m(self, pkt, x):
        if x is None:
            if self.length_of is not None:
                fld,fval = pkt.getfield_and_val(self.length_of)
                x = fld.i2len(pkt, fval)
            if self.count_of is not None:
                fld,fval = pkt.getfield_and_val(self.count_of)
                x = fld.i2count(pkt, fval)
        return x

# === string[s]: s[2] + s bytes
class P9S(Field):
    def i2len(self, pkt, s):
        return len(s)
    def i2m(self, pkt, x):
        if x is None:
            x = ""
        elif type(x) is not str:
            x=str(x)
        return "" + struct.pack("<H", len(x)) + x
    def m2i(self, pkt, x):
        return x[2:2+struct.unpack("<H", x[:2])[0]]
    def getfield(self, pkt, s):
        x = self.m2i(pkt, s)
        return s[2+len(x):],x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)

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
class P9Scname(P9S):
    def __init__(self, default=""):
        P9S.__init__(self, "cname", default)

class P9qid(Field):
    """13-bytes qid"""
    DIR     = 0x80 # directories
    APPEND  = 0x40 # append only files
    EXCL    = 0x20 # exclusive use files
    MOUNT   = 0x10 # mounted channel
    AUTH    = 0x08 # authentication file
    TMP     = 0x04 # non-backed-up file
    SYMLINK = 0x02 # symbolic link
    FILE    = 0x00 # plain file

    def __init__(self, name):
        Field.__init__(self, name, None, "13s")
    def i2len(self, pkt, x):
        """Used in FieldLenField especially"""
        return 13
    def i2m(self, pkt, x):
        """Convert internal(class) representation to machine(then packed by fmt) value"""
        (type, vers, path) = x
        return struct.pack("<BIQ", type, vers, path)
    def m2i(self, pkt, x):
        """Convert unpacked(fmt, from machine value) to internal(class) representation"""
        if x == '': return None
        type = struct.unpack("<B", x[0:1])[0] # ord(x[0:1])
        vers = struct.unpack("<I", x[1:5])[0]
        path = struct.unpack("<Q", x[5:13])[0]
        return (type, vers, path)
    def getfield(self, pkt, s):
        x = self.m2i(pkt,s)
        return s[self.i2len(pkt, x):], x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def i2h(self, pkt, x):
        return x
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        (type, vers, path) = x
        # s = ":".join("{0:02x}".format(ord(c)) for c in self.i2m(pkt, x))
        s = '('
        if (P9qid.DIR     & type): s +=  'DIR'
        else:                      s +=  'FILE'
        if (P9qid.APPEND  & type): s += '|APPEND'
        if (P9qid.EXCL    & type): s += '|EXCL'
        if (P9qid.MOUNT   & type): s += '|MOUNT'
        if (P9qid.AUTH    & type): s += '|AUTH'
        if (P9qid.TMP     & type): s += '|TMP'
        if (P9qid.SYMLINK & type): s += '|SYMLINK'
        s += ',' + str(vers)
        s += ',' + str(path)
        s += ')'
        return s

# === list
class P9L(Field):
    islist = 1

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
    def self_build(self, field_pos_list=None):
        # why not executed
        print 123
        p=""
        for f in self.fields_desc:
            val = self.getfieldval(f.name)
            p = f.addfield(self, p, val)
        return p

class P9Lwname(P9L):
    def __init__(self, count_from):
        P9L.__init__(self, "wname", P9S("", ""), count_from=count_from)

class P9Lwqid(P9L):
    def __init__(self, count_from):
        P9L.__init__(self, "wqid", P9qid(""), count_from=count_from)

class P9Ldata(P9L):
    def __init__(self, count_from):
        P9L.__init__(self, "data", P9S("", ""), count_from=count_from)

class P9stat(Field):
    """compound stat[n]"""

    # size[2]:H      total byte count of the following data
    # type[2]:H      for kernel use
    # dev[4]:I       for kernel use
    # qid.type[1]:B  the type of the file (directory, etc.)
    # qid.vers[4]:I  version number for given path
    # qid.path[8]:Q  the file servers unique identification for the file
    # mode[4]:I      permissions and flags
    # atime[4]:I     last access time
    # mtime[4]:I     last modification time
    # length[8]:Q    length of file in bytes
    # name[ s ]:     file name; must be / if the file is the root directory of the server
    # uid[ s ]:      owner name
    # gid[ s ]:      group name
    # muid[ s ]:     name of the user who last modified the file

    def __init__(self, name):
        # stop bitching up with defaults, fmt, sz,
        # couse they are used only in get/addfield
        Field.__init__(self, name, None)
    def i2len(self, pkt, x):
        """Used in FieldLenField especially"""
        ((qtype, qvers, qpath), mode, atime, mtime, length, name, uid, gid, muid) = x
        return 41 + 2+len(name) + 2+len(uid) + 2+len(gid) + 2+len(muid)
    def i2m(self, pkt, x):
        """human-touple to byte-str"""
        ((qtype, qvers, qpath), mode, atime, mtime, length, name, uid, gid, muid) = x
        s  = struct.pack("<HHHI", self.i2len(pkt, x), self.i2len(pkt, x) - 2, 0, 0)
        s += struct.pack("<BIQ", qtype, qvers, qpath)
        s += struct.pack("<IIIQ", mode, atime, mtime, length)
        s += struct.pack("<H", len(name)) + str(name)
        s += struct.pack("<H", len(uid)) + str(uid)
        s += struct.pack("<H", len(gid)) + str(gid)
        s += struct.pack("<H", len(muid)) + str(muid)
        return s
    @staticmethod
    def gm2i(x):
        if x == '': return None
        try:
            n = 0
            size = struct.unpack("<H", x[n:n+2])[0]; n+=2
            type = struct.unpack("<H", x[n:n+2])[0]; n+=2
            dev  = struct.unpack("<I", x[n:n+4])[0]; n+=4
            qtype = struct.unpack("<B", x[n:n+1])[0]; n+=1
            qvers = struct.unpack("<I", x[n:n+4])[0]; n+=4
            qpath = struct.unpack("<Q", x[n:n+8])[0]; n+=8
            #(qtype, qvers, qpath) = P9qid("").m2i(None, x[8:21])
            mode = struct.unpack("<I", x[n:n+4])[0]; n+=4
            atime = struct.unpack("<I", x[n:n+4])[0]; n+=4
            mtime = struct.unpack("<I", x[n:n+4])[0]; n+=4
            length = struct.unpack("<Q", x[n:n+8])[0]; n+=8
            # name = P9S[41:43+struct.unpack("<H", x[41:43])[0]]
            name = P9S("","").m2i(None, x[n:]); n+=2+len(name)
            uid = P9S("","").m2i(None, x[n:]); n+=2+len(uid)
            gid = P9S("","").m2i(None, x[n:]); n+=2+len(gid)
            muid = P9S("","").m2i(None, x[n:]);
            return ((qtype, qvers, qpath), mode, atime, mtime, length, name, uid, gid, muid)
        except:
            return None
    def m2i(self, pkt, x):
        """Convert byte-str to human-touple"""
        if x == '': return None
        ssize = struct.unpack("<H", x[0:2])[0];
        return P9stat.gm2i(x[2:])
    def getfield(self, pkt, s):
        x = self.m2i(pkt,s)
        return s[2+self.i2len(pkt, x):], x
    def addfield(self, pkt, s, val):
        return s+self.i2m(pkt, val)
    def i2h(self, pkt, x):
        return x
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        ((qtype, qvers, qpath), mode, atime, mtime, length, name, uid, gid, muid) = x
        s = ""
        #s += ":".join("{0:02x}".format(ord(c)) for c in self.i2m(pkt, x))
        s += '('
        if (P9qid.DIR     & qtype): s +=  'DIR'
        else:                       s +=  'FILE'
        if (P9qid.APPEND  & qtype): s += '|APPEND'
        if (P9qid.EXCL    & qtype): s += '|EXCL'
        if (P9qid.MOUNT   & qtype): s += '|MOUNT'
        if (P9qid.AUTH    & qtype): s += '|AUTH'
        if (P9qid.TMP     & qtype): s += '|TMP'
        if (P9qid.SYMLINK & qtype): s += '|SYMLINK'
        s += ',' + str(qvers)
        s += ',' + str(qpath)
        s += ') '
        if (P9qid.DIR     & (mode & 0xFF000000)>>3*8): s += 'DIR-'
        if (P9qid.APPEND  & (mode & 0xFF000000)>>3*8): s += 'APPEND-'
        if (P9qid.EXCL    & (mode & 0xFF000000)>>3*8): s += 'EXCL-'
        if (P9qid.MOUNT   & (mode & 0xFF000000)>>3*8): s += 'MOUNT-'
        if (P9qid.AUTH    & (mode & 0xFF000000)>>3*8): s += 'AUTH-'
        if (P9qid.TMP     & (mode & 0xFF000000)>>3*8): s += 'TMP-'
        if (P9qid.SYMLINK & (mode & 0xFF000000)>>3*8): s += 'SYMLINK-'
        # s += str(oct(mode & 0x0000FFFF))
        s += "%04o" % (mode & 0x0000FFFF)
        s += ' "' + name
        s += '","' + uid
        s += '","' + gid
        s += '","' + muid
        s += '" (' + strftime("%Y.%m.%d-%H:%M:%S", gmtime(mtime))
        s += '),(' + strftime("%Y.%m.%d-%H:%M:%S", gmtime(atime))
        s += ')'
        return s

class P9Sstat(P9stat):
    def __init__(self):
        P9stat.__init__(self, "stat")

class P9Sdata(StrFixedLenField):
    def __init__(self):
        StrFixedLenField.__init__(self, "data", "", length_from=lambda pkt:pkt.count)
    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        s = ""
        s_ = P9stat.gm2i(x)

        if s_ is None:
            s = ';' + repr(x)

        while s_ is not None:
            s += ';' + P9stat("").i2repr(None, s_)
            x = x[P9stat("").i2len(None, s_):]
            s_ = P9stat.gm2i(x)

        return "[" + s[1:] + "]"

class P9(Packet):
    name = "P9"

    def __init__(self, _pkt="", post_transform=None, _internal=0, _underlayer=None, **fields):
        # post_transform = lambda pkt:self.build(pkt)
        Packet.__init__(self, _pkt, post_transform, _internal, _underlayer, **fields)

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
                 ConditionalField(P9qid("aqid"), lambda pkt:pkt.type in [103]),
                 # Rattach, Ropen, Rcreate
                 ConditionalField(P9qid("qid"), lambda pkt:pkt.type in [105,113,115]),
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
                 # Tcreate
                 ConditionalField(P9Scname(), lambda pkt:pkt.type in [114]),
                 ConditionalField(P9Nperm(), lambda pkt:pkt.type in [114]),
                 # Topen, Tcreate
                 ConditionalField(P9Nmode(), lambda pkt:pkt.type in [112,114]),
                 # Tread, Twrite
                 ConditionalField(P9Noffset(), lambda pkt:pkt.type in [116, 118]),
                 # Tread, Rwrite
                 ConditionalField(P9Ncount(), lambda pkt:pkt.type in [116, 119]),
                 # Rread
                 ConditionalField(P9Ncount(length_of="data"), lambda pkt:pkt.type in [117]),
                 ConditionalField(P9Sdata(), lambda pkt:pkt.type in [117]),
                 # Twrite
                 ConditionalField(P9Ncount(length_of="data"), lambda pkt:pkt.type in [118]),
                 ConditionalField(P9Sdata(), lambda pkt:pkt.type in [118]),
                ]
    def mysummary(self):
        s = self.sprintf("%2s,P9.tag% %P9.type%")
        if self.type in [100,101]:
            s += self.sprintf(" %P9.version%")
        if self.type in [104,110,112,114,116,118,120,122,124,126]:
            s += self.sprintf(" %P9.fid%:fid")
        if self.type in [102,104]:
            s += self.sprintf(" %P9.uname%")
        if self.type in [112,114]:
            s += self.sprintf(" %P9.mode%")
        if self.type in [116]:
            s += self.sprintf(" [%P9.offset%..%P9.offset%+%P9.count%]")
        if self.type in [117,118]:
            s += self.sprintf(" [%P9.count%]:%P9.data%")
        if self.type in [119]:
            s += self.sprintf(" [%P9.count%]")
        if self.type in [114]:
            s += self.sprintf(" %P9.cname%")
            s += self.sprintf(" %P9.perm%")
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
            s += self.sprintf(" %P9.newfid%:fidnew")
            #s += self.sprintf(" %P9.nwname%")
            s += self.sprintf(" %P9.wname%")
        if self.type in [111]:
            #s += self.sprintf(" %P9.nwqid%")
            s += self.sprintf(" %P9.wqid%")
        if self.type in [125,126]:
            s += self.sprintf(" %P9.stat%")

        if isinstance(self.underlayer, P9):
            return s,[P9]

        return s


bind_layers(TCP, P9, sport=5640)
bind_layers(TCP, P9, dport=5640)
bind_layers(P9, P9)

p=rdpcap('5640-1.pcap')
#p=p.filter(lambda x:x.haslayer(Raw))[:]
p=p.filter(lambda x:x.haslayer(P9))[:]
#print "\n".join(":".join("{0:02x}".format(ord(c)) for c in str(pkt[Raw])) for pkt in p)
print "\n".join(":".join("{0:02x}".format(ord(c)) for c in str(pkt[P9])) for pkt in p)

#p.nsummary()
