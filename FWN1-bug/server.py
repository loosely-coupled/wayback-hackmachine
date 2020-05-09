""" 
This is an example of the FWN/1 protocol vulnerability discovered by Thomas Lopatic in Firewall-1.
Description of the vulnerability comes from the book "The art of software security assessments"
Note: This only aims to re-create the core vulnerability and does not resemble the actual protocol

The scaffolding code for the server is based off https://pymotw.com/3/http.server/
"""
import http.server
import socketserver
from http.server import BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib import parse
from random import randint
import hashlib
import json
import uuid

PORT = 8000

class FWN1RequestHandler(BaseHTTPRequestHandler):

    SECRET = str(randint(1000000000,9999999999))
    sessions = []

    def client_auth(self, auth_request):
         
        auth_json = json.loads(auth_request)
        
        user_hash = ""
        iv = ""
        try:
            iv = auth_json["iv"]
            user_hash = auth_json["hash"]
        except:
            return "failed to read 'iv' and 'hash' value"

        server_key = iv + FWN1RequestHandler.SECRET
        server_hash = hashlib.sha256(server_key.encode('utf-8')).hexdigest()
        
        if server_hash == user_hash:
            return "success"
        else:
            return "failed"

    def server_auth(self):

        r1 = randint(1000000000,9999999999) 
        key = str(r1) + FWN1RequestHandler.SECRET       
        return (str(r1), hashlib.sha256(key.encode('utf-8')).hexdigest())

    def store_session(self, sessionid):
        sessions.append[sessionid]


    def valid_session(self, sessionid):
        if sessionid in FWN1RequestHandler.sessions:
            return True
        
        return False


    def get_secret_text(self):
        return "A painful lesson in buiding authentication from scratch!!"

        
    def do_GET(self):
        print(FWN1RequestHandler.SECRET)
        
        proto_banner = """
  ______ _                        _ _       __ 
 |  ____(_)                      | | |     /_ |
 | |__   _ _ __ _____      ____ _| | |______| |
 |  __| | | '__/ _ \ \ /\ / / _` | | |______| |
 | |    | | | |  __/\ V  V | (_| | | |      | |
 |_|    |_|_|  \___| \_/\_/ \__,_|_|_|      |_|
                                            
[+] Welcome to the Firewall-1 admin panel
[+] available endpoints:
    * POST /serverauth
    * GET /clientauth
    * GET /getloot
[+] Mutual authentication status: enabled
[+] Use FWN1 protocol for authentication i.e sha256(<iv> + <pre-shared key>)
[+] Contact administrator for pre-shared key
"""
        if self.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(proto_banner.encode("utf-8"))

        if self.path.startswith("/serverauth"):
            res_json = {}
            iv, fhash = self.server_auth()
            res_json['iv'] = iv
            res_json['hash'] = fhash
            response = "{'iv':%s\r\nhash:%s" % (iv, fhash)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(res_json).encode('utf-8')) 

        elif self.path.startswith("/getloot"):
            cookies = SimpleCookie(self.headers.get('Cookie'))
            
            user_session = ""
            try:
                user_session = cookies["fwn1protocol"].value
            except:
                self.send_response(403)
                self.end_headers
                self.wfile.write("'fwn1protocol' cookie not found. Please authenticate\n".encode('utf-8'))
                return

            if self.valid_session(cookies["fwn1protocol"].value) == False:
                self.send_response(404)
                self.end_headers  
                self.wfile.write("invalid session. Please re-authenticate".encode('utf-8'))
                return

            if self.valid_session(user_session):
                self.send_response(200)
                self.end_headers
                self.wfile.write(self.get_secret_text().encode("utf-8"))
        
        else:
            self.send_response(404)
            self.end_headers      


    def do_POST(self):
        content_length = int(self.headers['Content-Length']) 
        post_data = self.rfile.read(content_length) 
        
        if self.path.startswith("/clientauth"):
            response = self.client_auth(post_data)
            
            if response == "success":
                user_session = str(uuid.uuid4())
                FWN1RequestHandler.sessions.append(user_session)

                self.send_response(200)
                cookie = http.cookies.SimpleCookie()
                cookie['fwn1protocol'] = user_session
                self.send_header("Set-Cookie", cookie.output(header='', sep=''))
                self.end_headers()

                self.wfile.write("successful authentication. Authorised to call /gettoken".encode('utf-8'))
            
            elif response == "failed":
                self.send_response(401)
                self.end_headers()

                self.wfile.write("authentication failed. Please try again".encode("utf-8"))

            else:

                self.send_response(500)
                self.end_headers()

                body = "Bad request: %s" % response
                self.wfile.write(body.encode('utf-8'))


if __name__ == '__main__':
    from http.server import HTTPServer
    server = HTTPServer(('localhost', 8080), FWN1RequestHandler)
    print('Starting server, use <Ctrl-C> to stop')
    server.serve_forever()