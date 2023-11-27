from ja3 import *
from TLSClientHello import *
import socket

class JA3Guard:
    def __init__(self, peer_socket: socket.socket):
        self.__hello: TLSClientHello = None
        self.__ja3 = None

        data = peer_socket.recv(4096, socket.MSG_PEEK)

        if data:
        #    try:
            self.__hello = TLSClientHello(data)
        #    except:
        #        return None

            handshake = self.__hello.handshake

            extensions_types = [x["type"] for x in handshake["extensions"]]

            self.__ja3 = JA3(handshake["version"],
                             handshake["cipher_suites"],
                             extensions_types,
                             handshake["supported_groups"],
                             handshake["ec_point_formats"])

    @property
    def ja3(self) -> JA3:
        return self.__ja3

    @property
    def tls_client_hello(self) -> TLSClientHello:
        return self.__hello
