#!/usr/bin/env python3

import base64
import sys
import uuid
from datetime import datetime
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
conn.request('GET', '/login?TARGET=' + service, headers={'Authorization': basic})
response = conn.getresponse()
if response.status != 302:
    print('Unexpected status: ', response.status, response.reason)
    sys.exit(0)
location = response.getheader('Location')
qs = parse_qs(urlparse(location).query)
ticket = qs['SAMLart'][0]
validate_url = '/samlValidate?TARGET={service}'.format(service=service)
body = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
    <SOAP-ENV:Header/>
    <SOAP-ENV:Body>
        <samlp:Request IssueInstant="{now}"
            MajorVersion="1" MinorVersion="1"
            RequestID="{id}" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol">
            <samlp:AssertionArtifact>{ticket}</samlp:AssertionArtifact>
        </samlp:Request>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>""".format(now=datetime.now(), id=uuid.uuid4(), ticket=ticket).encode('utf-8')
headers = {
    'Content-Type': 'application/soap+xml',
    'Content-Length': len(body)
}
conn.request('POST', validate_url, body, headers)
response = conn.getresponse()
body = response.read()
print(body)

