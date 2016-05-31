#!/usr/bin/env python3

import base64
import sys
from http.client import HTTPConnection
from os.path import basename
from urllib.parse import parse_qs, quote_plus, urlparse

if len(sys.argv) < 4:
  print('USAGE: {0}'.format(basename(sys.argv[0])))
  sys.exit(0)

service = quote_plus(sys.argv[1])
credential = sys.argv[2] + ':' + sys.argv[3]
basic = 'Basic ' + base64.b64encode(credential.encode('utf-8')).decode('utf-8')

conn = HTTPConnection('localhost', '8080')
conn.request('GET', '/login?service=' + service, headers={'Authorization': basic})
response = conn.getresponse()
if response.status != 302:
  print('Unexpected status: ', response.status, response.reason)
  sys.exit(0)
location = response.getheader('Location')
qs = parse_qs(urlparse(location).query)
ticket = qs['ticket'][0]
validate_url = '/serviceValidate?service={service}&ticket={ticket}'.format(
  service=service,
  ticket=qs['ticket'][0])
conn.request('GET', validate_url)
response = conn.getresponse()
body = response.read()
print(body)

