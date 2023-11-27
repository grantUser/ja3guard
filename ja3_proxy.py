#!/usr/bin/env python
#-*- coding: utf-8 -*-

import socketserver
import ssl
import select
#from http.server import BaseHTTPRequestHandler
#from io import BytesIO

from ja3guard import *
from parse_http import *

"""
class HTTPRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.raw_request = request_text
        self.requestline = ""
        self.headers = {}
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.parse_request()

    @property
    def body(self) -> str:
        return self.raw_request.decode().split('\r\n\r\n', 1)[1]
"""

#
# Faire le handshake TLS
#
def start_tls(client_socket):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='combined.pem')

    return context.wrap_socket(client_socket, server_side=True)

sess = []

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global sess
        sess.append(self.request)
        ip,port = self.client_address

        # Lecture du TLS Client HELLO et génération du ja3
        ja3 = JA3Guard(self.request)

        # Si ja3.ja3 ne contient rien, la requete lu par JA3Guard n'est surement
        # pas un client HELLO
        if not ja3.ja3:
            print(f"#{len(sess)}\t{ip}:{port}\t[Invalid request]")
            self.request.close()
            return

        print(f"#{len(sess)}\t{ip}:{port}\t[{ja3.ja3.fingerprint}]")

        # Négocier la connexion TLS entre le client et le proxy
        ssl_socket = start_tls(self.request)

        # Connexion au serveur distant (flask)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect(('127.0.0.1', 8080))

        list_sockets = [ssl_socket, server_socket]

        while True:
            readable, _, _ = select.select(list_sockets, [], [])

            for sock in readable:

                # Quand des données sont disponible du coté client
                # (le client envoie une requête)
                if sock == ssl_socket:
                    data = ssl_socket.recv(8192)

                    if len(data) == 0:
                        print(f"#{len(sess)}\t{ip}:{port}\tConnexion closed by peer.")
                        server_socket.close()
                        return

#                    request_info = HTTPRequestHandler(cmd)

#                    headers = request_info.headers

                    try:
                        # Parser le HTTP
                        request_info = HTTPRequest(data)
                    except HTTPInvalidData as e:
                        print(e)
                        server_socket.close()
                        ssl_socket.close()
                        return

                    headers = request_info.headers

                    # Rajouter les headers custom pour JA3 et les informatios du
                    # client connecté au proxy
                    headers["X-Real-Ip"] = ip
                    headers["X-Real-Dst-Port"] = str(port)
                    headers["X-Ja3-Hash"] = ja3.ja3.fingerprint
                    headers["X-Ja3-Text"] = ja3.ja3.text

                    request_info.headers = headers

                    # envoyer la nouvelle requete HTTP au serveur
                    server_socket.send(str(request_info).encode())

                # Des données sont disponible coté serveur
                # (le serveur envoie une réponse
                elif sock == server_socket:
                    data = server_socket.recv(8192)

                    if len(data) == 0:
                        ssl_socket.close()
                        return

                    # Parser la réponse HTTP du serveur
                    response_info = HTTPResponse(data)

                    headers = response_info.headers

                    # Supprimer l'header Server de la réponse HTTP
                    del headers["Server"]

                    # Envoie au client la réponse HTTP modifié
                    ssl_socket.write(str(response_info).encode())

        ssl_socket.close()

class ThreadedTCPServer(socketserver.ThreadingMixIn,socketserver.TCPServer):
    pass

if __name__ == "__main__":
    port = 443
    svr = ThreadedTCPServer(("",port),TCPHandler)
    print("listen :%d"%port)
    svr.serve_forever()
