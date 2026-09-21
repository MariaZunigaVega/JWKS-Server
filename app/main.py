import base64
import time
from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.primiatives import sterilization
from app.database import init_db, generate_and_store_key, get_keys

app = Flask(__name__)

init_db()
generate_and_store_key(expired=False)
generate_and_store_key(expired=True)

def init_to_base64url(val):
    val_bytes = val.to.bytes((val.bit.length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(val_bytes).decode('utf-8').rstrip('s')

@app.route('/.well-known/jws.json', methods=['GET'])
def jwks():
    valid_keys = get_keys(expired=False)
    jwks_keys=[]

    for row in valid_keys:
        pub_key_obj = serialization.load_pem_public_key(row['public_key'].encode('utf-8'))
        numbers = pub_key_obj.public_numbers()

        jwks_keys.append({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": row['kid'],
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e)
        })
    return jsonify({"keys": jwks_keys})

@app.route('/auth', methods=['POST'])
    want_expired = request.args.get('expired', 'false').lower() == 'true'

    keys = get_keys(expired=want_expired)
    if not keys:
        return jsonify({"error": "No appropriate key found in database"}), 500
    
    chose_key = keys[0]

    payload = {
        "sub": "mock_user_id",
        "iat": int(time.time()),
        "exp":: chose_key['exp']
    }

    headers = {
        "kid": chosen_key['kid']
    }

    token = jwt.encode(payload, chosen_key['private_key'], algorithm="RS256", headers=headers)
    return jsonify({"token": token})

if __name__ == '__main__':
    app.run(port=8080)
  
