
import os

ENV = os.getenv("BINARYIF_ENV", "dev")  # dev|stage|prod

# Simple rate limits (requests per minute)
AUTHORIZE_RPM = int(os.getenv("AUTHORIZE_RPM", "120"))
EXECUTE_RPM = int(os.getenv("EXECUTE_RPM", "120"))

# In prod, you should enforce TLS, auth, and network segmentation outside this MVP.
