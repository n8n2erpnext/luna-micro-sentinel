#!/usr/bin/env python3
import re
from urllib.parse import urlsplit
UUID=re.compile(r'^[0-9a-f]{8}-[0-9a-f-]{27,}$',re.I)
HEX=re.compile(r'^[0-9a-f]{16,}$',re.I)
NUM=re.compile(r'^\d{5,}$')
OPAQUE=re.compile(r'^[A-Za-z0-9_-]{24,}$')
def sanitize(raw):
 try:path=urlsplit(raw or '/').path or '/'
 except:path=(raw or '/').split('?',1)[0].split('#',1)[0]
 out=[]
 for seg in path.split('/'):
  if UUID.match(seg): seg='{uuid}'
  elif HEX.match(seg): seg='{hexid}'
  elif NUM.match(seg): seg='{numid}'
  elif OPAQUE.match(seg): seg='{opaque}'
  out.append(seg)
 return '/'.join(out) or '/'
