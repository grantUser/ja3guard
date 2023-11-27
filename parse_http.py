class HTTPInvalidData(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class HTTPHeaders(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __str__(self):
        strheader: str = ""

        for k,v in self.items():
            strheader += f"{k}: {v}\r\n"

        return strheader

class HTTPRequest:
    HTTP_METHODS = ["GET", "POST", "PUT", "CONNECT", "TRACE", "HEAD", "CREATE"]
    HTTP_VERSION = ["HTTP/0.9", "HTTP/1.0", "HTTP/1.1"]

    def __init__(self, raw: bytes):
        self.method: str = None
        self.path: str = None
        self.version: str = None
        self.headers: HTTPHeaders = HTTPHeaders()
        self.body: byte = None

        lines = raw.decode().split("\r\n")

        if len(lines) < 4:
            raise HTTPInvalidData("The request is too short.")

        req = lines[0].split(" ")

        if len(req) > 3:
            raise HTTPInvalidData("The request line is too long.")

        if not req[0] in HTTPRequest.HTTP_METHODS:
            raise HTTPInvalidData(f"{req[0]} is an invalid HTTP method.")

        if req[1][0] != '/':
            raise HTTPInvalidData("The path doesn't start with '/'.")

        if not req[2] in HTTPRequest.HTTP_VERSION:
            raise HTTPInvalidData(f"{req[0]} is an invalid HTTP version.")

        self.method = req[0]
        self.path = req[1]
        self.version = req[2]

        empty_index = 1

        for header in lines[1:]:
            if not header:
                break

            keyval = header.split(": ", 1)

            if len(keyval) < 2:
                raise HTTPInvalidData("Header is invalid.")

            key,val = keyval

            self.headers[key] = val
            empty_index += 1

        self.body = lines[empty_index+1]

    def __str__(self) -> str:
        return f'{self.method} {self.path} {self.version}\r\n{str(self.headers)}\r\n{self.body}'


class HTTPResponse:
    HTTP_VERSION = ["HTTP/0.9", "HTTP/1.0", "HTTP/1.1"]

    def __init__(self, raw: bytes):
        self.version: str = None
        self.code: str = None
        self.msg: str = None
        self.headers: HTTPHeaders = HTTPHeaders()
        self.body: byte = None

        lines = raw.decode().split("\r\n")

        if len(lines) < 4:
            raise HTTPInvalidData("The response is too short.")

        req = lines[0].split(" ")

        if len(req) > 3:
            raise HTTPInvalidData("The response line is too long.")

        if not req[0] in HTTPRequest.HTTP_VERSION:
            raise HTTPInvalidData(f"{req[0]} is an invalid HTTP version.")

        self.version = req[0]
        self.code = req[1]
        self.msg = req[2]

        empty_index = 1

        for header in lines[1:]:
            if not header:
                break

            keyval = header.split(": ", 1)

            if len(keyval) < 2:
                raise HTTPInvalidData("Header is invalid.")

            key,val = keyval

            self.headers[key] = val
            empty_index += 1

        self.body = lines[empty_index+1]

    def __str__(self) -> str:
        return f'{self.version} {self.code} {self.msg}\r\n{str(self.headers)}\r\n{self.body}'


if __name__ == "__main__":
    raw = """GET /test HTTP/1.1\r\nHost: hypertest\r\nUser-Agent: supertest\r\n\r\nbody"""
    raw = """HTTP/1.1 200 OK\r\nHost: hypertest\r\nUser-Agent: supertest\r\n\r\nbody"""

    h = HTTPResponse(raw.encode())
    h.headers["tttt"] = "toooot"
    h.headers["Host"] = "toooot"
    del h.headers["Host"]
    print(h)
