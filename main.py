from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from cryptography.hazmat.primitives import serialization
import base64
import json
import jwt
import time

import db  



hostName = "localhost"   # tests/gradebot will hit http://localhost:8080
serverPort = 8080
ISSUER = "jwks-basic-server"
ALGORITHM = "RS256"


# -------------------------------
# Helper: base64url encode integer (for n,e in JWKS)
# -------------------------------
def int_to_base64(value: int) -> str:
    """
    Convert a nonnegative integer to Base64URL-encoded string without '=' padding.
    Used to produce 'n' and 'e' in JWKS.
    """
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')



def load_private_key_from_pem(pem_bytes: bytes):
    """
    Given PEM bytes loaded from SQLite, reconstruct a private key object to sign JWTs.
    """
    return serialization.load_pem_private_key(
        pem_bytes,
        password=None,
    )



def ensure_seed_keys(conn):
    """
    Make sure the database has:
      - one key that is still valid (expires >= now+3600)
      - one key that is already expired (expires <= now-3600)

    We only insert them if the table is empty. This guarantees:
      - /auth returns a valid (unexpired) token
      - /auth?expired=true returns an expired token
      - /.well-known/jwks.json can publish at least one unexpired public key
    """
    if db.count_keys(conn) > 0:
        return

    now = int(time.time())
    one_hour = 3600

    # Insert unexpired key (good key)
    good_pem, _good_obj = db.generate_rsa_keypair_pem()
    db.insert_key(conn, good_pem, now + one_hour)

    # Insert expired key (bad / old key)
    expired_pem, _expired_obj = db.generate_rsa_keypair_pem()
    db.insert_key(conn, expired_pem, now - one_hour)


# Create / open totally_not_my_privateKeys.db and seed if needed
conn = db.init_db()
ensure_seed_keys(conn)



class MyServer(BaseHTTPRequestHandler):
    #
    # Utility helpers for this class
    #

    def _read_json_body(self):
        """
        Safely read and parse JSON request body.
        If there's no body or it's invalid, return {}.
        """
        length = self.headers.get('Content-Length')
        if not length:
            return {}
        try:
            raw = self.rfile.read(int(length))
        except Exception:
            return {}
        try:
            return json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    def _parse_basic_auth(self):
        """
        Parse HTTP Basic Authorization header.
        Return (username, password) or (None, None).

        We're NOT doing real authentication in this project.
        The Gradebot will just send Basic auth and we should
        reflect that username in the JWT 'sub' claim.
        """
        auth = self.headers.get('Authorization')
        if not auth or not auth.startswith("Basic "):
            return (None, None)

        b64_part = auth.split(" ", 1)[1]
        try:
            decoded = base64.b64decode(b64_part).decode('utf-8')
            # expected "username:password"
            if ":" in decoded:
                u, p = decoded.split(":", 1)
                return (u, p)
        except Exception:
            pass

        return (None, None)

    #
    # Explicitly block methods we don't support
    #
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

    #
    # POST handler: /auth
    #
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            #
            # 1. Determine which username to embed in the token
            #
            body_json = self._read_json_body()
            body_user = body_json.get("username")
            basic_user, basic_pass = self._parse_basic_auth()

            # Priority: JSON username > Basic auth username > fallback
            username = body_user or basic_user or "demo-user"

            #
            # 2. Pick which private key to use based on "expired" query parameter
            #
            use_expired = 'expired' in params
            if use_expired:
                row = db.get_expired_key(conn)
            else:
                row = db.get_unexpired_key(conn)

            if row is None:
                # If we somehow have no suitable key, that's a server problem
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"No suitable key in database")
                return

            db_kid    = row["kid"]   # integer PRIMARY KEY AUTOINCREMENT from SQLite
            pem_bytes = row["key"]   # PEM-encoded private key (bytes)
            exp_epoch = row["exp"]   # this key's expiration timestamp

            #
            # 3. Reconstruct the signing key object from PEM
            #
            priv_obj = load_private_key_from_pem(pem_bytes)

            #
            # 4. Build the JWT claims
            #
            now_epoch = int(time.time())
            token_payload = {
                "iss": ISSUER,
                "iat": now_epoch,
                "exp": exp_epoch,      # expiration is whatever we stored in DB
                "sub": username,
                "scope": "demo"
            }

            #
            # 5. JWT header has the kid so verifiers know which public key to use
            #
            headers = {
                "kid": str(db_kid),    # make sure it's a string
                "typ": "JWT",
                "alg": ALGORITHM
            }

            #
            # 6. Sign the JWT using RS256
            #
            token = jwt.encode(
                token_payload,
                priv_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ),
                algorithm=ALGORITHM,
                headers=headers
            )

            #
            # 7. Send the token back as the response body
            #
            self.send_response(200)
            self.send_header("Content-Type", "application/jwt")
            self.end_headers()
            self.wfile.write(token.encode("utf-8"))
            return

        
        self.send_response(405)
        self.end_headers()

    
    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path in ("/.well-known/jwks.json", "/jwks"):
            # 1. Pull all unexpired keys from the database
            rows = db.get_all_unexpired_keys(conn)

            jwk_keys = []
            for row in rows:
                db_kid    = row["kid"]    # numeric kid from DB
                pem_bytes = row["key"]

                # Reconstruct the private key so we can derive the public numbers
                priv_obj = load_private_key_from_pem(pem_bytes)
                pub_nums = priv_obj.public_key().public_numbers()

                jwk_keys.append({
                    "alg": ALGORITHM,
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(db_kid),  # kid must match what we put in JWT headers
                    "n": int_to_base64(pub_nums.n),
                    "e": int_to_base64(pub_nums.e),
                })

            body = json.dumps({"keys": jwk_keys})

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode("utf-8"))
            return

        # Any other GET path is not allowed
        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Serving on http://{hostName}:{serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        webServer.server_close()
