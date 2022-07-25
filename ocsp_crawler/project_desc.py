# OCSP sizes for top 1 (??) million **
# OCSP responders for them
# Issuing certs
# Responder certs
# Delegated count **
from ocspchecker import get_ocsp_status

a = get_ocsp_status("google.com")
a = 1