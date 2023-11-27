import struct
import binascii
import numpy as np

class TLSClientHelloInvalid(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message

class TLSClientHello:
    @staticmethod
    def cipher_grease(extension: int):
        # if code is in range 0x0A0A, 0x1A1A, ..., 0xEAEA, 0xFAFA
        if (
            extension & 0x0f0f == 0x0a0a 
            and extension & 0xff == extension >> 8
            ):
            return True

        return False

    def __init__(self, data: bytes):
        def parse_extension(self, data: bytes):
            d_ext = struct.unpack('!HH', data[:4])

            ext_offset = 4

            ext_type = d_ext[0]
            ext_length = d_ext[1]
            ext_data = struct.unpack_from("%ds" % ext_length,
                                          data,
                                          offset=ext_offset)

            ext_data = ext_data[0]

            ext_offset += ext_length

            dic = {
                "type": ext_type,
                "length": ext_length,
                "data": ext_data
            }

            self.__handshake["extensions"].append(dic)

            # ec_point_formats
            if ext_type == 11:
                    data_offset = 0
                    ec_length = struct.unpack_from('!B',
                                                   ext_data,
                                                   offset=data_offset)

                    ec_length = ec_length[0]

                    data_offset += 1
                    ecpf = struct.unpack_from("!%dB" % int(ec_length),
                                              ext_data,
                                              offset=data_offset)

                    self.__handshake["ec_point_formats"] = ecpf

            # supported_groups
            elif ext_type == 10:
                data_offset = 0
                groups_length = struct.unpack_from('!H',
                                                   ext_data,
                                                   offset=data_offset)

                groups_length = groups_length[0]

                data_offset += 2

                groups = struct.unpack_from("!%dH" % int(groups_length/2),
                                            ext_data,
                                            offset=data_offset)

                self.__handshake["supported_groups"] = groups

            if len(data) - ext_length > 4:
                parse_extension(self, data[ext_offset:])

        hello_offset = 0
        self.__handshake = {}

        if len(data) < 44:
            raise TLSClientHelloInvalid(
                    "The size of data is less than the minimum"
                    "TLS client HELLO %d < 44" % len(data))

        d = struct.unpack('!BHHB3sH32sB', data[:44])
        hello_offset += 44 

        self.content_type = d[0]
        self.version = d[1]
        self.length = d[2]
        self.raw = data

        if self.content_type != 0x16 and self.version != 0x0301:
            raise TLSClientHelloInvalid("data is not an TLS client hello handshake")

        self.__handshake["type"] = d[3]
        self.__handshake["length"] = int.from_bytes(d[4], byteorder='big')
        self.__handshake["version"] = d[5]
        self.__handshake["random"] = binascii.hexlify(d[6]).decode('ascii')
        self.__handshake["session_id_length"] = d[7]
        self.__handshake["extensions"] = []

        d = struct.unpack_from("!%ds" % (self.__handshake["session_id_length"]),
                               data,
                               offset=hello_offset)

        self.__handshake["session_id"] = binascii.hexlify(d[0]).decode('ascii')

        hello_offset += self.__handshake["session_id_length"]

        d = struct.unpack_from('!H', data, offset=hello_offset)
        cipher_suites_length = d[0]
        cipher_array_len = int(cipher_suites_length / 2)

        self.__handshake["cipher_suites"] = np.zeros(cipher_array_len, dtype=int)

        hello_offset += 2

        cipher_suites = struct.unpack_from("!%ds" % cipher_suites_length,
                                           data,
                                           offset=hello_offset)

        cipher_suites = cipher_suites[0]

        hello_offset += cipher_suites_length 
        cipher_offset = 0

        x = 0
        for _ in range(0, cipher_array_len):
            cipher = struct.unpack_from('!H',
                                        cipher_suites,
                                        offset=cipher_offset)

            if not self.cipher_grease(cipher[0]):
                self.__handshake["cipher_suites"][x] = cipher[0]
                cipher_offset += 2
                x += 1

        d = struct.unpack_from('!B', data, offset=hello_offset)
        compression_methods_length = d[0]

        hello_offset += 1

        self.__handshake["compression_methods"] = struct.unpack_from(
                                            "%dB" % compression_methods_length,
                                            data,
                                            offset=hello_offset)

        hello_offset += compression_methods_length

        d = struct.unpack_from('!H', data, offset=hello_offset)

        extension_length = d[0]
        hello_offset += 2

        self.__handshake["ec_point_formats"] = [None]
        self.__handshake["supported_groups"] = [None]

        parse_extension(self, data[hello_offset:])

    @property
    def handshake(self) -> dict:
        return self.__handshake

if __name__ == "__main__":
    import socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 4444))
    server_socket.listen(1)

    client_socket, client_addr = server_socket.accept()

    data = client_socket.recv(4096)
    client_socket.close()
    server_socket.close()

    c = TLSClientHello(data)
    print(c.handshake)
