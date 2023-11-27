import hashlib

class JA3:
    def __init__(self, 
                 SSLVersion: int,
                 Cipher: list,
                 SSLExtension: list = None,
                 EllipticCurve: list = None,
                 EllipticCurvePointFormat: list = None
                 ):

        self.SSLVersion = SSLVersion
        self.Cipher = Cipher
        self.SSLExtension = SSLExtension
        self.EllipticCurve = EllipticCurve
        self.EllipticCurvePointFormat = EllipticCurvePointFormat

    @property
    def text(self) -> str:
        cipher = [str(x) for x in self.Cipher]
        extensions = []
        ec_list = []
        ec_point = []

        if len(self.SSLExtension) > 0:
            extensions = [str(x) for x in self.SSLExtension]

            if len(self.EllipticCurve) > 0:
                ec_list = [str(x) for x in self.EllipticCurve]

            if len(self.EllipticCurvePointFormat) > 0:
                ec_point = [str(x) for x in self.EllipticCurvePointFormat]

        data = "%d,%s,%s,%s,%s" % (
                    self.SSLVersion,
                    '-'.join(cipher),
                    '-'.join(extensions),
                    '-'.join(ec_list),
                    '-'.join(ec_point)
                )

        return data

    @property
    def fingerprint(self) -> str:
        digest = hashlib.md5()
        digest.update(self.text.encode())
        return digest.hexdigest()

    def __str__(self):
        return f"{self.fingerprint}: {self.text}"
