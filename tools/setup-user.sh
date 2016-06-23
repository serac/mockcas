#!/usr/bin/env python3

import sys
import os

if len(sys.argv) < 4:
    print('''
USAGE: {0} <data-dir> <username> <uid> [<udc-id>]
data-dir - directory where user data will be stored
username - username for the user
uid      - unique id for the user
udc-id   - udc id for the user, default is '999<uid>'

Example: {0} data_dir john 12345
'''.format(os.path.basename(sys.argv[0])))
    sys.exit(0)

data_dir = sys.argv[1]
user = sys.argv[2]
uid = sys.argv[3]
if len(sys.argv) > 4:
  udc = sys.argv[4]
else:
  udc = "999{0}".format(uid)

if not os.path.exists(data_dir):
  os.makedirs(data_dir)

for dir in ['samlValidate', 'serviceValidate', 'validate']:
  subdir = "{0}/{1}".format(data_dir, dir)
  if not os.path.exists(subdir):
    os.makedirs(subdir)

with open("{0}/samlValidate/{1}".format(data_dir, user), 'w') as f:
  f.write('''<?xml version="1.0" encoding="utf-8" ?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header />
  <SOAP-ENV:Body>
    <Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol"
              IssueInstant="{now}"
              MajorVersion="1" MinorVersion="1" Recipient="{service}"
              ResponseID="{id}">
      <Status>
        <StatusCode Value="samlp:Success"/>
      </Status>
      <Assertion xmlns="urn:oasis:names:tc:SAML:1.0:assertion"
                 AssertionID="{id}"
                 IssueInstant="{now}" Issuer="mockcas" MajorVersion="1" MinorVersion="1">
        <AttributeStatement>
          <Subject>
            <NameIdentifier>''')
  f.write(user)
  f.write('''</NameIdentifier>
          </Subject>
          <Attribute AttributeName="uid" AttributeNamespace="http://www.ja-sig.org/products/cas/">
            <AttributeValue>''')
  f.write(uid)
  f.write('''</AttributeValue>
          </Attribute>
          <Attribute AttributeName="UDC_IDENTIFIER" AttributeNamespace="http://www.ja-sig.org/products/cas/">
            <AttributeValue>''')
  f.write(udc)
  f.write('''</AttributeValue>
          </Attribute>
        </AttributeStatement>
        <AuthenticationStatement AuthenticationInstant="{now}"
                                 AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password">
          <Subject>
            <NameIdentifier>''')
  f.write(user)
  f.write('''</NameIdentifier>
          </Subject>
        </AuthenticationStatement>
        <Conditions NotBefore="{before}" NotOnOrAfter="{after}">
          <AudienceRestrictionCondition>
            <Audience>{service}</Audience>
          </AudienceRestrictionCondition>
        </Conditions>
      </Assertion>
    </Response>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
''')

with open("{0}/serviceValidate/{1}".format(data_dir, user), 'w') as f:
  f.write('''<?xml version="1.0" encoding="UTF-8"?>
<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>{user}</cas:user>
    <cas:attributes>
      <cas:uid>{uid}</cas:uid>
      <cas:UDC_IDENTIFIER>{udc}</cas:UDC_IDENTIFIER>
    </cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>
'''.format(user=user, uid=uid, udc=udc))

with open("{0}/validate/{1}".format(data_dir, user), 'w') as f:
  f.write('''yes
{0}

'''.format(user))
