from pyasn1.codec.ber import decoder as der_decoder
from pyasn1.codec.ber import encoder as der_encoder

ocsp_bytes = open("ocsp_bytes", "rb").read()
cert_bytes = open("cert_bytes", "rb").read()

x, _ = der_decoder.decode(ocsp_bytes)
print(str(x))