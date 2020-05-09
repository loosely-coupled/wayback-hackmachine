# based off:https://pymotw.com/3/http.server/
import http.server
import socketserver
from http.server import BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib import parse
from random import randint

PORT = 8000

class FWN1RequestHandler(BaseHTTPRequestHandler):

    SECRET = randint(1000000000,9999999999)
    sessions = []

    def client_auth(self):
         # Generate random value

        # read secret

        # hash secret with random value

        pass


    def server_auth(self):

        ## read random value

        ## read local secret

        ## hash secret  + random value

        ## compare hashes

        pass

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
            return self.server_auth()
        
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