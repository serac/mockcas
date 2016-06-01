import os.path
import sys
import uuid
from base64 import b64decode
from datetime import datetime
from functools import lru_cache
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import xml.etree.ElementTree as ET

"""Number of entries in LRU cache that stores user data."""
CACHESIZE = 10000

"""Error response for CAS 1.0 protocol."""
CAS1_ERROR = "no\n\n"

"""Error response for CAS 2.0 protocol."""
CAS2_ERROR = """<cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
  <cas:authenticationFailure code="{error_code}">
      {detail_code}
  </cas:authenticationFailure>
</cas:serviceResponse>"""

"""Error response for SAML 1.1 protocol."""
SAML11_ERROR = """<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
  <SOAP-ENV:Header />
  <SOAP-ENV:Body>
    <Response xmlns="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion"
    xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" IssueInstant="{now}"
    MajorVersion="1" MinorVersion="1" Recipient="{service}"
    ResponseID="{id}">
      <Status>
        <StatusCode Value="samlp:RequestDenied" />
        <StatusMessage>{error_code}</StatusMessage>
        <StatusDetail>{detail_code}</StatusDetail>
      </Status>
    </Response>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"""

"""SAML 1.1 XML namespace mapping of prefix to URI."""
SAML11_NS_MAP = {
    'p': 'urn:oasis:names:tc:SAML:1.0:protocol',
    'env': 'http://schemas.xmlsoap.org/soap/envelope/'
}

"""Map of endpoint URI to error response."""
ERROR_MAP = {
    'validate': CAS1_ERROR,
    'serviceValidate': CAS2_ERROR,
    'samlValidate': SAML11_ERROR
}


class CASProtocolError(Exception):
    """CAS protocol error"""
    def __init__(self, error_code, detail_code):
        super(CASProtocolError, self).__init__(error_code + ': ' + detail_code)
        self.error_code = error_code
        self.detail_code = detail_code


class CASServer(HTTPServer):
    """Mock CAS server that implements the CAS protocol on address:port."""

    def __init__(self, server_address, secret, data_dir, handler_class):
        super(CASServer, self).__init__(server_address, handler_class)
        self.secret = secret
        self.data_dir = data_dir
        self._ticket_map = {}

    def serve_forever(self, poll_interval=0.5):
        """Starts the web server listening on address:port."""
        print("Starting CAS server on", self.server_address,
              "and serving content from", self.data_dir, file=sys.stderr)
        try:
            HTTPServer.serve_forever(self, poll_interval)
        except KeyboardInterrupt:
            print('Shutting down from interrupt signal')
            self.server_close()

    def generate_ticket(self, service, username):
        """Generate a CAS ticket for the given authenticated user."""
        ticket = 'ST-' + str(uuid.uuid4())
        self._ticket_map[ticket] = (service, username)
        return ticket

    def validate_ticket(self, ticket, service):
        """
        Validates the ticket by checking for existence and enforcing that the grantor matches the validator.
        Returns a CAS protocol response on success.
        Raises CASProtocolError on validation errors.
        """
        if ticket is None or service is None:
            raise CASProtocolError('INVALID_REQUEST', 'E_MISSING_PARAMETERS')
        try:
            result = self._ticket_map[ticket]
        except KeyError:
            raise CASProtocolError('INVALID_TICKET', 'E_TICKET_NOT_FOUND')
        del self._ticket_map[ticket]
        if result[0] != service:
            raise CASProtocolError('INVALID_SERVICE', 'E_SERVICE_MISMATCH')
        return result[1]

    @lru_cache(maxsize=CACHESIZE)
    def get_response(self, endpoint, username):
        """
        Reads the response data from the filesystem for the given endpoint-username pair.
        Raises CASProtocolError on IO errors.
        """
        try:
            with open(os.path.join(self.data_dir, endpoint, username), 'r') as f:
                return f.read()
        except FileNotFoundError:
            raise CASProtocolError('INTERNAL_ERROR', 'E_FILE_NOT_FOUND')
        except IOError:
            raise CASProtocolError('INTERNAL_ERROR', 'E_IO_ERROR')


class CASRequestHandler(BaseHTTPRequestHandler):
    """CAS HTTP request handler that implements CAS protocol URI handling."""

    def login(self):
        """
        Authenticates the user via HTTP Basic authentication.
        The password provided must match the static secret configured for the server.
        Produces a 302 response to trigger redirect to service with ticket on success.
        Produces a 403 Forbidden response on authentication failure.
        """
        service = self.query('service')
        is_saml = False
        if service is None:
            service = self.query('TARGET')
            if service is None:
                self.send_response(400, 'Bad request')
                return
            is_saml = True
        value = self.headers['Authorization'] or ''
        if not value.startswith('Basic '):
            self.send_error(403, 'Forbidden')
            return
        credentials = b64decode(value[6:]).decode('utf-8').split(':')
        if credentials[1] != self.server.secret:
            self.send_error(403, 'Forbidden')
            return
        ticket = self.server.generate_ticket(service, credentials[0])
        self.send_response(302, 'Found')
        if is_saml:
            self.send_header('Location', service + '?SAMLart=' + ticket)
        else:
            self.send_header('Location', service + '?ticket=' + ticket)
        self.end_headers()

    def validate(self):
        """Validates the ticket via the CAS 1.0 protocol."""
        ticket = self.query('ticket')
        service = self.query('service')
        try:
            username = self.server.validate_ticket(ticket, service)
            response = self.server.get_response(self.cas_uri, username)
        except CASProtocolError:
            response = ERROR_MAP[self.cas_uri]
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def serviceValidate(self):
        """Validates the ticket via the CAS 2.0 protocol."""
        ticket = self.query('ticket')
        service = self.query('service')
        try:
            username = self.server.validate_ticket(ticket, service)
            response = self.server.get_response(self.cas_uri, username)
        except CASProtocolError as e:
            response = ERROR_MAP[self.cas_uri]
            response = response.format(error_code=e.error_code, detail_code=e.detail_code)
        self.send_response(200)
        self.send_header('Content-Type', 'text/xml')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def samlValidate(self):
        """Validates the ticket via the "CAS-flavored" SAML 1.1 protocol."""
        service = self.query('TARGET')
        ticket = None
        length = self.headers['Content-Length']
        if length is None:
            length = 0
        else:
            length = int(length)
        body = self.rfile.read(length).decode('utf-8')
        root = ET.fromstring(body)
        assertions = root.findall('.//p:AssertionArtifact', SAML11_NS_MAP)
        if len(assertions) > 0:
            ticket = assertions[0].text
        format_params = {'id': uuid.uuid4(), 'now': datetime.now(), 'service': service}
        try:
            username = self.server.validate_ticket(ticket, service)
            response = self.server.get_response(self.cas_uri, username)
        except CASProtocolError as e:
            response = ERROR_MAP[self.cas_uri]
            format_params['error_code'] = e.error_code
            format_params['detail_code'] = e.detail_code
        response = response.format(**format_params)
        self.send_response(200)
        self.send_header('Content-Type', 'text/xml')
        self.send_header('Content-Length', len(response))
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

    def do_GET(self):
        """Handle GET requests by dispatching to a specific protocol URI handler by examining path."""
        self.protocol_version = 'HTTP/1.1'
        index = self.path.find('?')
        if index < 0:
            self.cas_uri = self.path[1:]
        else:
            self.cas_uri = self.path[1:index]
        if index > 1:
            self.querystring = parse_qs(self.path[index+1:])
        else:
            self.querystring = ''
        try:
            handler = getattr(self, self.cas_uri)
        except AttributeError:
            self.send_error(404, "Not Found")
        handler()

    def do_POST(self):
        """Handle POST requests by dispatching to a specific protocol URI handler by examining path."""
        self.do_GET()

    def query(self, key):
        """Gets the first value of the named querystring parameter or None if no such key is defined."""
        if key in self.querystring:
            values = self.querystring[key]
            if len(values) > 0:
                return values[0]
        return None

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Start the mock CAS server')
    parser.add_argument('--address', dest='address', type=str, default='0.0.0.0',
                        help='server bind address, 0.0.0.0 by default')
    parser.add_argument('--port', dest='port', type=int, default=8080,
                        help='server listen port, 8080 by default')
    parser.add_argument('secret', type=str,
                        help='static secret used to authenticate users')
    parser.add_argument('data_dir', type=str,
                        help='path to data directory')
    args = parser.parse_args(sys.argv[1:])
    server = CASServer((args.address, args.port), args.secret, args.data_dir, CASRequestHandler)
    server.serve_forever(1)
