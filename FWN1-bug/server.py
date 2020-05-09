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

PORT = 8000

class FWN1RequestHandler(BaseHTTPRequestHandler):

    SECRET = str(randint(1000000000,9999999999))
    sessions = []

    def client_auth(self):
         # Generate random value

        # read secret

        # hash secret with random value

        pass


    def server_auth(self):

        r1 = randint(1000000000,9999999999) 
        key = str(r1) + FWN1RequestHandler.SECRET       
        return (r1, hashlib.sha256(key.encode('utf-8')).hexdigest())

    def store_session(self, sessionid):
        sessions.append[sessionid]


    def check_session(self, sessionid):
        if sessionid in FWN1RequestHandler.sessions:
            return True
        
        return False


    def get_secret_text(self):
        return "A painful lesson in buiding authentication from scratch!!"
    
    def do_GET(self):
        print(FWN1RequestHandler.SECRET)
        
        if self.path.startswith("/serverauth"):
            iv, fhash = self.server_auth()
            response = "iv:%s\r\nhash:%s" % (iv, fhash)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(response.encode('utf-8')) 
        
        elif self.path.startswith("/clientauth"):
            return self.client_auth()
        
        elif self.path.startswith("/gettoken"):
            cookies = SimpleCookie(self.headers.get('Cookie'))
            
            try:
                user_session = cookies["fwn1protocol"].value
            except:
                self.send_response(403)
                self.end_headers
                self.wfile.write("'fwn1protocol' cookie not found. Please authenticate\n".encode('utf-8'))
                return

            if self.check_session(cookies["fwn1protocol"].value) == False:
                self.send_response(404)
                self.end_headers  
                self.wfile.write("invalid session. Please re-authenticate".encode('utf-8'))
                
        else:
            self.send_response(404)
            self.end_headers      



if __name__ == '__main__':
    from http.server import HTTPServer
    server = HTTPServer(('localhost', 8080), FWN1RequestHandler)
    print('Starting server, use <Ctrl-C> to stop')
    server.serve_forever()