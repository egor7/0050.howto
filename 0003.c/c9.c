#include <string.h>
#include <stdint.h>
#include "c9.h"

#include <pthread.h>
#include "aux.h"
#include "trace.h"

enum
  {
    Svver = 1<<0,
  };

#define safestrlen(s) (s == NULL ? 0 : (uint32_t)strlen(s))
#define maxread(c) (c->msize-4-4-1-2)
#define maxwrite(c) maxread(c)

static void
w08(uint8_t **p, uint8_t x)
{
  (*p)[0] = x;
  *p += 1;
}

static void
w16(uint8_t **p, uint16_t x)
{
  (*p)[0] = x;
  (*p)[1] = x>>8;
  *p += 2;
}

static void
w32(uint8_t **p, uint32_t x)
{
  (*p)[0] = x;
  (*p)[1] = x>>8;
  (*p)[2] = x>>16;
  (*p)[3] = x>>24;
  *p += 4;
}

static void
w64(uint8_t **p, uint64_t x)
{
  (*p)[0] = x;
  (*p)[1] = x>>8;
  (*p)[2] = x>>16;
  (*p)[3] = x>>24;
  (*p)[4] = x>>32;
  (*p)[5] = x>>40;
  (*p)[6] = x>>48;
  (*p)[7] = x>>56;
  *p += 8;
}

static void
wcs(uint8_t **p, const char *s, int len)
{
  w16(p, len);
  if(s != NULL){
    memmove(*p, s, len);
    *p += len;
  }
}

static uint8_t
r08(uint8_t **p)
{
  *p += 1;
  return (*p)[-1];
}

static uint16_t
r16(uint8_t **p)
{
  *p += 2;
  return (uint16_t)(*p)[-2]<<0 | (uint16_t)(*p)[-1]<<8;
}

static uint32_t
r32(uint8_t **p)
{
  return r16(p) | (uint32_t)r16(p)<<16;
}

static uint64_t
r64(uint8_t **p)
{
  return r32(p) | (uint64_t)r32(p)<<32;
}

static C9error
newtag(C9ctx *c, C9ttype type, C9tag *tag)
{
  tbeg("newtag");
  C9aux *a = ((C9aux*)c->aux);
  pthread_mutex_lock(a->lock);

  uint32_t i;

  if(type == Tversion){
    *tag = 0xffff;
    pthread_mutex_unlock(a->lock);
    tend("newtag");
    return 0;
  }

  if(c->lowfreetag < C9maxtags){
    uint32_t d = c->lowfreetag / C9tagsbits, m = c->lowfreetag % C9tagsbits;
    if((c->tags[d] & 1<<m) != 0){
      c->tags[d] &= ~(1<<m);
      *tag = c->lowfreetag++;
      pthread_mutex_unlock(a->lock);
      tend("newtag");
      return 0;
    }
  }

  for(i = 0; i < (int)sizeof(c->tags)/sizeof(c->tags[0]); i++){
    uint32_t x, j;
		if((x = c->tags[i]) == 0)
		  continue;
		for(j = 0; j < C9tagsbits; j++){
		  if((x & (1<<j)) != 0){
		    c->tags[i] &= ~(1<<j);
		    *tag = i*C9tagsbits + j;
		    c->lowfreetag = *tag + 1;
            pthread_mutex_unlock(a->lock);
            tend("newtag");
		    return 0;
		  }
		}
  }

  c->error("newtag: no free tags");
  pthread_mutex_unlock(a->lock);
  terr("newtag");
  return C9Etag;
}

static int
freetag(C9ctx *c, C9tag tag)
{
  t2beg("freetag");
  C9aux *a = ((C9aux*)c->aux);
  pthread_mutex_lock(a->lock);

  t2log("tag = %d", tag);
  if(tag != 0xffff){
    uint32_t d = tag / C9tagsbits, m = tag % C9tagsbits;
    if(tag >= C9maxtags){
      c->error("freetag: invalid tag");
      pthread_mutex_unlock(a->lock);
      t2err("freetag");
      return -1;
    }
    if((c->tags[d] & 1<<m) != 0){
      c->error("freetag: double free");
      pthread_mutex_unlock(a->lock);
      t2err("freetag");
      return -1;
    }
		if(c->lowfreetag > tag)
		  c->lowfreetag = tag;
		c->tags[d] |= 1<<m;
  }
  pthread_mutex_unlock(a->lock);
  t2end("freetag");
  return 0;
}

static uint8_t *
T(C9ctx *c, uint32_t size, C9ttype type, C9tag *tag, C9error *err)
{
  tbeg("T");

  uint8_t *p = NULL;

  if(size > c->msize-4-1-2){
    c->error("T: invalid size");
    *err = C9Esize;
  }else if((*err = newtag(c, type, tag)) == 0){
    size += 4+1+2;
    if((p = c->begin(c, size)) == NULL){
      c->error("T: no buffer");
      freetag(c, *tag);
      *err = C9Ebuf;
    }else{
      *err = 0;
      w32(&p, size);
      w08(&p, type);
      w16(&p, *tag);
    }
  }

  tend("T");
  return p;
}

static uint8_t *
R(C9ctx *c, uint32_t size, C9rtype type, C9tag tag, C9error *err)
{
  tbeg("R");
  uint8_t *p = NULL;

  if(size > c->msize-4-1-2){
    c->error("R: invalid size");
    *err = C9Esize;
  }else{
    size += 4+1+2;
    if((p = c->begin(c, size)) == NULL){
      c->error("R: no buffer");
      *err = C9Ebuf;
    }else{
      *err = 0;
      w32(&p, size);
      w08(&p, type);
      w16(&p, tag);
    }
  }
  tend("R");
  return p;
}

C9error
c9parsedir(C9ctx *c, C9stat *stat, uint8_t **t, uint32_t *size)
{
  uint8_t *b;
  uint32_t cnt, sz;

	if(*size < 49 || (sz = r16(t)) < 47 || *size < 2+sz)
	  goto error;
	*size -= 2+sz;
	*t += 6; /* skip type(2) and dev(4) */
	stat->qid.type = r08(t);
	stat->qid.version = r32(t);
	stat->qid.path = r64(t);
	stat->mode = r32(t);
	stat->atime = r32(t);
	stat->mtime = r32(t);
	stat->size = r64(t);
	sz -= 39;
	if((cnt = r16(t)) > sz-2)
	  goto error;
	stat->name = (char*)*t; b = *t = *t+cnt; sz -= 2+cnt;
	if(sz < 2 || (cnt = r16(t)) > sz-2)
	  goto error;
	stat->uid = (char*)*t; *b = 0; b = *t = *t+cnt; sz -= 2+cnt;
	if(sz < 2 || (cnt = r16(t)) > sz-2)
	  goto error;
	stat->gid = (char*)*t; *b = 0; b = *t = *t+cnt; sz -= 2+cnt;
	if(sz < 2 || (cnt = r16(t)) > sz-2)
	  goto error;
	stat->muid = memmove(*t-1, *t, cnt); *b = stat->muid[cnt] = 0; *t = *t+cnt; sz -= 2+cnt;
	*t += sz;
	return 0;
error:
	c->error("c9parsedir: invalid size");
	return C9Epkt;
}

C9error
c9version(C9ctx *c, C9tag *tag, uint32_t msize)
{
  tbeg("c9version");
  uint8_t *b;
  C9error err;

  if(msize < C9minmsize){
    c->error("c9version: msize too small");
    terr("c9version");
    return C9Einit;
  }
  memset(c->tags, 0xff, sizeof(c->tags));
  memset(c->flush, 0xff, sizeof(c->flush));
  c->lowfreetag = 0;
  c->msize = msize;

  if((b = T(c, 4+2+6, Tversion, tag, &err)) != NULL){
    w32(&b, msize);
    wcs(&b, "9P2000", 6);
    err = c->end(c);
  }
  tend("c9version");
  return err;
}

C9error
c9auth(C9ctx *c, C9tag *tag, C9fid afid, const char *uname, const char *aname)
{
  tbeg("c9auth");
  uint8_t *b;
  uint32_t ulen = safestrlen(uname), alen = safestrlen(aname);
  C9error err;

  if(ulen > C9maxstr || alen > C9maxstr){
    c->error("c9auth: string too long");
    terr("c9auth");
    return C9Estr;
  }
  if((b = T(c, 4+2+ulen+2+alen, Tauth, tag, &err)) != NULL){
    w32(&b, afid);
    wcs(&b, uname, ulen);
    wcs(&b, aname, alen);
    err = c->end(c);
  }
  tend("c9auth");
  return err;
}

C9error
c9flush(C9ctx *c, C9tag *tag, C9tag oldtag)
{
  uint8_t *b;
  C9error err;
  int i;

  for(i = 0; i < C9maxflush && c->flush[i] != (uint32_t)~0; i++);
  if(i == C9maxflush){
    c->error("c9flush: no free flush slots");
    return C9Eflush;
  }
  if((b = T(c, 2, Tflush, tag, &err)) != NULL){
    w16(&b, oldtag);
    err = c->end(c);
		if(err == 0)
		  c->flush[i] = (uint32_t)oldtag<<16 | *tag;
  }
  return err;
}

C9error
c9attach(C9ctx *c, C9tag *tag, C9fid fid, C9fid afid, const char *uname, const char *aname)
{
  uint32_t ulen = safestrlen(uname), alen = safestrlen(aname);
  uint8_t *b;
  C9error err;

  if(ulen > C9maxstr || alen > C9maxstr){
    c->error("c9attach: string too long");
    return C9Estr;
  }
  if((b = T(c, 4+4+2+ulen+2+alen, Tattach, tag, &err)) != NULL){
    w32(&b, fid);
    w32(&b, afid);
    wcs(&b, uname, ulen);
    wcs(&b, aname, alen);
    err = c->end(c);
  }
  return err;
}

C9error
c9walk(C9ctx *c, C9tag *tag, C9fid fid, C9fid newfid, const char *path[])
{
  uint32_t i, j, sz;
  uint32_t len[C9maxpathel];
  uint8_t *b;
  C9error err;

  for(sz = i = 0; i < (int)sizeof(len)/sizeof(len[0]) && path[i] != NULL; i++){
    len[i] = safestrlen(path[i]);
    if(len[i] == 0 || len[i] > C9maxstr){
      c->error("c9walk: path element too long");
      return C9Epath;
    }
    sz += 2 + len[i];
  }
  if(path[i] != NULL || i == 0){
    c->error("c9walk: invalid elements !(0 < %d <= %d)", i, C9maxpathel);
    return C9Epath;
  }

  if((b = T(c, 4+4+2+sz, Twalk, tag, &err)) != NULL){
    w32(&b, fid);
    w32(&b, newfid);
    w16(&b, i);
    for(j = 0; j < i; j++)
      wcs(&b, path[j], len[j]);
    err = c->end(c);
  }
  return err;
}

C9error
c9open(C9ctx *c, C9tag *tag, C9fid fid, C9mode mode)
{
  uint8_t *b;
  C9error err;

  if((b = T(c, 4+1, Topen, tag, &err)) != NULL){
    w32(&b, fid);
    w08(&b, mode);
    err = c->end(c);
  }
  return err;
}

C9error
c9create(C9ctx *c, C9tag *tag, C9fid fid, const char *name, uint32_t perm, C9mode mode)
{
  uint32_t nlen = safestrlen(name);
  uint8_t *b;
  C9error err;

  if(nlen == 0 || nlen > C9maxstr){
    c->error("c9create: invalid name");
    return C9Epath;
  }
  if((b = T(c, 4+2+nlen+4+1, Tcreate, tag, &err)) != NULL){
    w32(&b, fid);
    wcs(&b, name, nlen);
    w32(&b, perm);
    w08(&b, mode);
    err = c->end(c);
  }
  return err;
}

C9error
c9read(C9ctx *c, C9tag *tag, C9fid fid, uint64_t offset, uint32_t count)
{
  uint8_t *b;
  C9error err;

  if((b = T(c, 4+8+4, Tread, tag, &err)) != NULL){
    w32(&b, fid);
    w64(&b, offset);
    w32(&b, count);
    err = c->end(c);
  }
  return err;
}

C9error
c9write(C9ctx *c, C9tag *tag, C9fid fid, uint64_t offset, const void *in, uint32_t count)
{
  uint8_t *b;
  C9error err;

  if((b = T(c, 4+8+4+count, Twrite, tag, &err)) != NULL){
    w32(&b, fid);
    w64(&b, offset);
    w32(&b, count);
    memmove(b, in, count);
    err = c->end(c);
  }
  return err;
}

C9error
c9wrstr(C9ctx *c, C9tag *tag, C9fid fid, const char *s)
{
  return c9write(c, tag, fid, 0, s, strlen(s));
}

C9error
c9clunk(C9ctx *c, C9tag *tag, C9fid fid)
{
  uint8_t *b;
  C9error err;

  if((b = T(c, 4, Tclunk, tag, &err)) != NULL){
    w32(&b, fid);
    err = c->end(c);
  }
  return err;
}

C9error
c9remove(C9ctx *c, C9tag *tag, C9fid fid)
{
  uint8_t *b;
  C9error err;

  if((b = T(c, 4, Tremove, tag, &err)) != NULL){
    w32(&b, fid);
    err = c->end(c);
  }
  return err;
}

C9error
c9stat(C9ctx *c, C9tag *tag, C9fid fid)
{
  uint8_t *b;
  C9error err;

  if((b = T(c, 4, Tstat, tag, &err)) != NULL){
    w32(&b, fid);
    err = c->end(c);
  }
  return err;
}

C9error
c9wstat(C9ctx *c, C9tag *tag, C9fid fid, const C9stat *s)
{
  uint32_t nlen = safestrlen(s->name), ulen = safestrlen(s->uid), glen = safestrlen(s->gid);
  uint32_t unusedsz = 2+4+13, statsz = unusedsz+4+4+4+8+2+nlen+2+ulen+2+glen+2;
  uint8_t *b;
  C9error err;

  if(nlen == 0 || nlen > C9maxstr){
    c->error("c9wstat: invalid name");
    return C9Epath;
  }
  if(ulen > C9maxstr || glen > C9maxstr){
    c->error("c9wstat: string too long");
    return C9Estr;
  }
  if((b = T(c, 4+2+2+statsz, Twstat, tag, &err)) != NULL){
    w32(&b, fid);
    w16(&b, statsz+2);
    w16(&b, statsz);
    memset(b, 0xff, unusedsz); /* leave type(2), dev(4) and qid(13) unchanged */
    b += unusedsz;
    w32(&b, s->mode);
    w32(&b, s->atime);
    w32(&b, s->mtime);
    w64(&b, s->size);
    wcs(&b, s->name, nlen);
    wcs(&b, s->uid, ulen);
    wcs(&b, s->gid, glen);
    wcs(&b, NULL, 0); /* muid unchanged */
    err = c->end(c);
  }
  return err;
}

C9error
c9proc(C9ctx *c)
{
  t2beg("c9proc");
  uint32_t i, sz, cnt, msize;
  uint8_t *b;
  int err;
  C9r r;

  err = -1;
  if((b = c->read(c, 4, &err)) == NULL){
		if(err != 0)
		  c->error("c9proc: short read");
		t2err("c9proc");
		return err == 0 ? 0 : C9Epkt;
  }

  t2log("read size");
  sz = r32(&b);
  if(sz < 7 || sz > c->msize){
    c->error("c9proc: invalid packet size !(7 <= %u <= %u)", sz, c->msize);
    t2err("c9proc");
    return C9Epkt;
  }
  sz -= 4;
  err = -1;
  if((b = c->read(c, sz, &err)) == NULL){
		if(err != 0)
		  c->error("c9proc: short read");
		t2err("c9proc");
		return err == 0 ? 0 : C9Epkt;
  }

  t2log("read type,tag");
  r.type = r08(&b);
  r.tag = r16(&b);
  if(r.type != Rversion){
    if(r.tag >= C9maxtags){
      c->error("c9proc: invalid tag 0x%x", r.tag);
      t2err("c9proc");
      return C9Epkt;
    }
    if(freetag(c, r.tag) != 0){
      t2err("c9proc");
      return C9Etag;
    }
  }
  sz -= 3;
  r.numqid = 0;

  t2log("r.type = %d", r.type);
  switch(r.type){
	case Rread:
		if(sz < 4 || (cnt = r32(&b)) > sz-4)
		  goto error;
		r.read.data = b;
		r.read.size = cnt;
		c->r(c, &r);
		break;

	case Rwrite:
		if(sz < 4 || (cnt = r32(&b)) > c->msize)
		  goto error;
		r.write.size = cnt;
		c->r(c, &r);
		break;

	case Rwalk:
		if(sz < 2+13 || (cnt = r16(&b))*13 > sz-2)
		  goto error;
		if(cnt > C9maxpathel){
		  c->error("c9proc: Rwalk !(%d <= %d)", cnt, C9maxpathel);
		  t2err("c9proc");
		  return C9Epath;
		}
		for(i = 0; i < cnt; i++){
		  r.qid[i].type = r08(&b);
		  r.qid[i].version = r32(&b);
		  r.qid[i].path = r64(&b);
		}
		r.numqid = cnt;
		c->r(c, &r);
		break;

	case Rstat:
	  b += 2; sz -= 2;
	  if((err = c9parsedir(c, &r.stat, &b, &sz)) != 0){
	    c->error("c9proc");
	    t2err("c9proc");
	    return err;
	  }
	  r.numqid = 1;
	  c->r(c, &r);
	  break;

	case Rflush:
	  for(i = 0; i < C9maxflush; i++){
	    if((c->flush[i] & 0xffff) == r.tag){
	      freetag(c, c->flush[i]>>16);
	      c->flush[i] = 0xffffffff;
	      break;
	    }
	  }
	case Rclunk:
	case Rremove:
	case Rwstat:
	  c->r(c, &r);
	  break;

	case Ropen:
	case Rcreate:
		if(sz < 17)
		  goto error;
		r.qid[0].type = r08(&b);
		r.qid[0].version = r32(&b);
		r.qid[0].path = r64(&b);
		r.iounit = r32(&b);
		r.numqid = 1;
		c->r(c, &r);
		break;

	case Rerror:
		if(sz < 2 || (cnt = r16(&b)) > sz-2)
		  goto error;
		r.error = memmove(b-1, b, cnt);
		r.error[cnt] = 0;
		c->r(c, &r);
		break;

	case Rauth:
	case Rattach:
		if(sz < 13)
		  goto error;
		r.qid[0].type = r08(&b);
		r.qid[0].version = r32(&b);
		r.qid[0].path = r64(&b);
		r.numqid = 1;
		c->r(c, &r);
		break;

	case Rversion:
		if(sz < 4+2 || (msize = r32(&b)) < C9minmsize || (cnt = r16(&b)) > sz-4-2)
		  goto error;
		if(cnt < 6 || memcmp(b, "9P2000", 6) != 0){
		  c->error("invalid version");
		  t2err("c9proc");
		  return C9Ever;
		}
		if(msize < c->msize)
		  c->msize = msize;
		c->r(c, &r);
		break;

	default:
	  goto error;
  }
  t2end("c9proc");
  return 0;
error:
  c->error("c9proc: invalid packet (type=%d)", r.type);
  t2err("c9proc");
  return C9Epkt;
}

C9error
s9version(C9ctx *c)
{
  tbeg("s9version");
  uint8_t *b;
  C9error err;

  if((b = R(c, 4+2+6, Rversion, 0xffff, &err)) != NULL){
    w32(&b, c->msize);
    wcs(&b, "9P2000", 6);
    err = c->end(c);
  };
  tend("s9version");
  return err;
}

C9error
s9auth(C9ctx *c, C9tag tag, const C9qid *aqid)
{
  tbeg("s9auth");
  uint8_t *b;
  C9error err;

  if((b = R(c, 13, Rauth, tag, &err)) != NULL){
    w08(&b, aqid->type);
    w32(&b, aqid->version);
    w64(&b, aqid->path);
    err = c->end(c);
  }
  tend("s9auth");
  return err;
}

C9error
s9error(C9ctx *c, C9tag tag, const char *ename)
{
  uint32_t len = safestrlen(ename);
  uint8_t *b;
  C9error err;

  if(len > C9maxstr){
    c->error("s9error: invalid ename");
    return C9Estr;
  }
  if((b = R(c, 2+len, Rerror, tag, &err)) != NULL){
    wcs(&b, ename, len);
    err = c->end(c);
  }
  return err;
}

C9error
s9attach(C9ctx *c, C9tag tag, const C9qid *qid)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 13, Rattach, tag, &err)) != NULL){
    w08(&b, qid->type);
    w32(&b, qid->version);
    w64(&b, qid->path);
    err = c->end(c);
  }
  return err;
}

C9error
s9flush(C9ctx *c, C9tag tag)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 0, Rflush, tag, &err)) != NULL)
    err = c->end(c);
  return err;
}

C9error
s9walk(C9ctx *c, C9tag tag, const C9qid *qids[])
{
  uint32_t i, n;
  uint8_t *b;
  C9error err;

  for(n = 0; n < C9maxpathel && qids[n] != NULL; n++);
  if(n > C9maxpathel){
    c->error("s9walk: invalid elements !(0 <= %d <= %d)", n, C9maxpathel);
    return C9Epath;
  }

  if((b = R(c, 2+n*13, Rwalk, tag, &err)) != NULL){
    w16(&b, n);
    for(i = 0; i < n; i++){
      w08(&b, qids[i]->type);
      w32(&b, qids[i]->version);
      w64(&b, qids[i]->path);
    }
    err = c->end(c);
  }
  return err;
}

C9error
s9open(C9ctx *c, C9tag tag, const C9qid *qid, uint32_t iounit)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 13+4, Ropen, tag, &err)) != NULL){
    w08(&b, qid->type);
    w32(&b, qid->version);
    w64(&b, qid->path);
    w32(&b, iounit);
    err = c->end(c);
  }
  return err;
}

C9error
s9create(C9ctx *c, C9tag tag, const C9qid *qid, uint32_t iounit)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 13+4, Rcreate, tag, &err)) != NULL){
    w08(&b, qid->type);
    w32(&b, qid->version);
    w64(&b, qid->path);
    w32(&b, iounit);
    err = c->end(c);
  }
  return err;
}

C9error
s9read(C9ctx *c, C9tag tag, const void *data, uint32_t size)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 4+size, Rread, tag, &err)) != NULL){
    w32(&b, size);
    memmove(b, data, size);
    err = c->end(c);
  }
  return err;
}

C9error
s9write(C9ctx *c, C9tag tag, uint32_t size)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 4, Rwrite, tag, &err)) != NULL){
    w32(&b, size);
    err = c->end(c);
  }
  return err;
}

C9error
s9readdir(C9ctx *c, C9tag tag, const C9stat *st[], int *num, uint64_t *offset, uint32_t size)
{
  uint8_t *b;
  const C9stat *s;
  uint32_t nlen, ulen, glen, mulen, m, n;
  C9error err;
  int i;

	if(size > c->msize-4-1-2)
	  size = c->msize-4-1-2;

	m = 0;
	for(i = 0; i < *num; i++){
	  s = st[i];
	  nlen = safestrlen(s->name);
	  ulen = safestrlen(s->uid);
	  glen = safestrlen(s->gid);
	  mulen = safestrlen(s->muid);

	  if(nlen == 0 || nlen > C9maxstr){
	    c->error("s9readdir: invalid name");
	    return C9Epath;
	  }
	  if(ulen > C9maxstr || glen > C9maxstr || mulen > C9maxstr){
	    c->error("s9readdir: string too long");
	    return C9Estr;
	  }

	  n = 2 + 2+4+13+4+4+4+8+2+nlen+2+ulen+2+glen+2+mulen;
		if(4+m+n > size)
		  break;
		m += n;
	}

	if((b = R(c, 4+m, Rread, tag, &err)) != NULL){
	  *num = i;
	  w32(&b, m);
	  for(i = 0; i < *num; i++){
	    s = st[i];
	    nlen = safestrlen(s->name);
	    ulen = safestrlen(s->uid);
	    glen = safestrlen(s->gid);
	    mulen = safestrlen(s->muid);
	    w16(&b, 2+4+13+4+4+4+8+2+nlen+2+ulen+2+glen+2+mulen);
	    w16(&b, 0xffff); /* type */
	    w32(&b, 0xffffffff); /* dev */
	    w08(&b, s->qid.type);
	    w32(&b, s->qid.version);
	    w64(&b, s->qid.path);
	    w32(&b, s->mode);
	    w32(&b, s->atime);
	    w32(&b, s->mtime);
	    w64(&b, s->size);
	    wcs(&b, s->name, nlen);
	    wcs(&b, s->uid, ulen);
	    wcs(&b, s->gid, glen);
	    wcs(&b, s->muid, mulen);
	  }
	  err = c->end(c);
		if(err == 0)
		  *offset += m;
	}
	return err;
}

C9error
s9clunk(C9ctx *c, C9tag tag)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 0, Rclunk, tag, &err)) != NULL)
    err = c->end(c);
  return err;
}

C9error
s9remove(C9ctx *c, C9tag tag)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 0, Rremove, tag, &err)) != NULL)
    err = c->end(c);
  return err;
}

C9error
s9stat(C9ctx *c, C9tag tag, const C9stat *s)
{
  uint32_t nlen = safestrlen(s->name), ulen = safestrlen(s->uid);
  uint32_t glen = safestrlen(s->gid), mulen = safestrlen(s->name);
  uint32_t statsz = 2+4+13+4+4+4+8+2+nlen+2+ulen+2+glen+2+mulen;
  uint8_t *b;
  C9error err;

  if(nlen == 0 || nlen > C9maxstr){
    c->error("s9stat: invalid name");
    return C9Epath;
  }
  if(ulen > C9maxstr || glen > C9maxstr || mulen > C9maxstr){
    c->error("s9stat: string too long");
    return C9Estr;
  }

  if((b = R(c, 2+2+statsz, Rstat, tag, &err)) != NULL){
    w16(&b, statsz+2);
    w16(&b, statsz);
    w16(&b, 0xffff); /* type */
    w32(&b, 0xffffffff); /* dev */
    w08(&b, s->qid.type);
    w32(&b, s->qid.version);
    w64(&b, s->qid.path);
    w32(&b, s->mode);
    w32(&b, s->atime);
    w32(&b, s->mtime);
    w64(&b, s->size);
    wcs(&b, s->name, nlen);
    wcs(&b, s->uid, ulen);
    wcs(&b, s->gid, glen);
    wcs(&b, s->muid, mulen);
    err = c->end(c);
  }
  return err;
}

C9error
s9wstat(C9ctx *c, C9tag tag)
{
  uint8_t *b;
  C9error err;

  if((b = R(c, 0, Rwstat, tag, &err)) != NULL)
    err = c->end(c);
  return err;
}

C9error
s9proc(C9ctx *c)
{
  tbeg("s9proc");
  uint32_t i, sz, cnt, n, msize;
  int readerr;
  uint8_t *b;
  C9error err;
  C9t t;

  tlog("s9proc1");
  readerr = -1;
  if((b = c->read(c, 4, &readerr)) == NULL){
        tlog("s9proc1.1");
		if(readerr != 0) {
          tlog("s9proc1.2");
		  c->error("s9proc: short read");
        }
        tlog("s9proc1.3");
        tend("s9proc");
		return readerr == 0 ? 0 : C9Epkt;
  }

  tlog("s9proc2");

  sz = r32(&b);
  if(sz < 7 || sz > c->msize){
    c->error("s9proc: invalid packet size !(7 <= %u <= %u)", sz, c->msize);
    tend("s9proc");
    return C9Epkt;
  }
  tlog("s9proc3");
  sz -= 4;
  readerr = -1;
  if((b = c->read(c, sz, &readerr)) == NULL){
        tlog("s9proc4");
		if(readerr != 0)
		  c->error("s9proc: short read");
        tend("s9proc");
		return readerr == 0 ? 0 : C9Epkt;
  }
  tlog("s9proc5");

  t.type = r08(&b);
  t.tag = r16(&b);
  sz -= 3;

  if((c->svflags & Svver) == 0 && t.type != Tversion){
    c->error("s9proc: expected Tversion, got %d", t.type);
    tend("s9proc");
    return C9Epkt;
  }

  switch(t.type){
	case Tread:
		if(sz < 4+8+4)
		  goto error;
		t.fid = r32(&b);
		t.read.offset = r64(&b);
		t.read.size = r32(&b);
		if(t.read.size > maxread(c))
		  t.read.size = maxread(c);
		c->t(c, &t);
		break;

	case Twrite:
		if(sz < 4+8+4)
		  goto error;
		t.fid = r32(&b);
		t.write.offset = r64(&b);
		if((t.write.size = r32(&b)) < sz-4-8-4)
		  goto error;
		if(t.write.size > maxwrite(c))
		  t.write.size = maxwrite(c);
		t.write.data = b;
		c->t(c, &t);
		break;

	case Tclunk:
	case Tstat:
	case Tremove:
		if(sz < 4)
		  goto error;
		t.fid = r32(&b);
		c->t(c, &t);
		break;

	case Twalk:
		if(sz < 4+4+2)
		  goto error;
		t.fid = r32(&b);
		t.walk.newfid = r32(&b);
		if((n = r16(&b)) > 16){
		  c->error("s9proc: Twalk !(%d <= 16)", n);
          tend("s9proc");
		  return C9Epath;
		}
		sz -= 4+4+2;
		if(n > 0){
		  for(i = 0; i < n; i++){
				if(sz < 2 || (cnt = r16(&b)) > sz-2)
				  goto error;
				if(cnt < 1){
				  c->error("s9proc: Twalk invalid element [%d]", i);
                  tend("s9proc");
				  return C9Epath;
				}
				b[-2] = 0;
				t.walk.wname[i] = (char*)b;
				b += cnt;
				sz -= 2 + cnt;
		  }
		  memmove(t.walk.wname[i-1]-1, t.walk.wname[i-1], (char*)b - t.walk.wname[i-1]);
		  t.walk.wname[i-1]--;
		  b[-1] = 0;
		}else
		  i = 0;
		t.walk.wname[i] = NULL;
		c->t(c, &t);
		break;

	case Topen:
		if(sz < 4+1)
		  goto error;
		t.fid = r32(&b);
		t.open.mode = r08(&b);
		c->t(c, &t);
		break;

	case Twstat:
		if(sz < 4+2)
		  goto error;
		t.fid = r32(&b);
		if((cnt = r16(&b)) > sz-4)
		  goto error;
		if((err = c9parsedir(c, &t.wstat, &b, &cnt)) != 0){
		  c->error("s9proc");
          tend("s9proc");
		  return err;
		}
		c->t(c, &t);
		break;

	case Tcreate:
		if(sz < 4+2+4+1)
		  goto error;
		t.fid = r32(&b);
		if((cnt = r16(&b)) < 1 || cnt > sz-4-2-4-1)
		  goto error;
		t.create.name = (char*)b;
		t.create.perm = r32(&b);
		t.create.mode = r08(&b);
		t.create.name[cnt] = 0;
		c->t(c, &t);
		break;

	case Tflush:
		if(sz < 2)
		  goto error;
		t.flush.oldtag = r16(&b);
		c->t(c, &t);
		break;

	case Tversion:
        tlog("Tversion1");
		if(sz < 4+2 || (msize = r32(&b)) < C9minmsize || (cnt = r16(&b)) > sz-4-2)
		  goto error;
		if(cnt < 6 || memcmp(b, "9P2000", 6) != 0){
		  if((b = R(c, 4+2+7, Rversion, 0xffff, &err)) != NULL){
		    w32(&b, 0);
		    wcs(&b, "unknown", 7);
		    err = c->end(c);
		    c->error("s9proc: invalid version");
		  }
          tend("s9proc");
		  return C9Ever;
		}
		if(msize < c->msize)
		  c->msize = msize;
		c->svflags |= Svver;
        tlog("Tversion9");
		c->t(c, &t);
		break;

	case Tattach:
		if(sz < 4+4+2+2)
		  goto error;
		t.fid = r32(&b);
		t.attach.afid = r32(&b);
		cnt = r16(&b);
		sz -= 4+4+2;
		if(cnt+2 > sz)
		  goto error;
		t.attach.uname = (char*)b;
		b += cnt;
		cnt = r16(&b);
		b[-2] = 0;
		sz -= cnt+2;
		if(cnt > sz)
		  goto error;
		memmove(b-1, b, cnt);
		t.attach.aname = (char*)b-1;
		t.attach.aname[cnt] = 0;
		c->t(c, &t);
		break;

	case Tauth:
		if(sz < 4+2+2)
		  goto error;
		t.auth.afid = r32(&b);
		cnt = r16(&b);
		sz -= 4+2;
		if(cnt+2 > sz)
		  goto error;
		t.auth.uname = (char*)b;
		b += cnt;
		cnt = r16(&b);
		b[-2] = 0;
		sz -= cnt+2;
		if(cnt > sz)
		  goto error;
		memmove(b-1, b, cnt);
		t.auth.aname = (char*)b-1;
		t.auth.aname[cnt] = 0;
		c->t(c, &t);
		break;

	default:
	  goto error;
  }
  tend("s9proc");
  return 0;
error:
  c->error("s9proc: invalid packet (type=%d)", t.type);
  tend("s9proc");
  return C9Epkt;
}
