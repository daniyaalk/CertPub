from flask import Flask, Response
from flask_httpauth import HTTPBasicAuth
import json
import os

app = Flask(__name__)
auth = HTTPBasicAuth()

@app.route('/')
def home():

    return "No certificate name found in request"

@auth.verify_password
def verify_password(username, password):

    credentials = open("credentials.json")
    keypairs = json.load(credentials)

    if username in keypairs:
        return keypairs[username]==password
    else:
        return False

@auth.error_handler
def auth_error():

    return Response(response='{"status": 401, "error": "Unauthorized"}', content_type="application/json", status=401)


@app.route('/<certname>')
@auth.login_required
def certificate_info(certname):

    if not os.path.exists("certificates.json"):
        return Response(response='{"status": 501, "error": "certificates.json not found"}', content_type="application/json", status=501)

    f = open("certificates.json")
    data = json.load(f)

    if certname not in data['certificates']:
        return Response(response='{"status": 404, "error": "certificate not found"}', content_type="application/json", status=404)

    if auth.username() not in data["certificates"][certname]["access"]:
        return Response(response='{"status": 401, "error": "Unauthorized for this user"}', content_type="application/json", status=401)

    certificate = {

        "cert_name": certname,
        "certificate": data["certificates"][certname]["certificate"],
        "private_key": data["certificates"][certname]["private_key"]

    }

    resp = {"status": 200, "response": certificate}
    return Response(response=json.dumps(resp), content_type="application/json", status=200)

@app.route('/<certname>/certificate')
@auth.login_required
def certificate(certname):

    if not os.path.exists("certificates.json"):
        return Response(response='{"status": 501, "error": "certificates.json not found"}', content_type="application/json", status=501)

    f = open("certificates.json")
    data = json.load(f)

    if certname not in data['certificates']:
        return Response(response='{"status": 404, "error": "certificate not found"}', content_type="application/json", status=404)

    if auth.username() not in data["certificates"][certname]["access"]:
        return Response(response='{"status": 401, "error": "Unauthorized for this user"}', content_type="application/json", status=401)

    return Response(response=data["certificates"][certname]["certificate"], content_type="application/x-pem-file", status=200)

@app.route('/<certname>/private_key')
@auth.login_required
def private_key(certname):

    if not os.path.exists("certificates.json"):
        return Response(response='{"status": 501, "error": "certificates.json not found"}', content_type="application/json", status=501)

    f = open("certificates.json")
    data = json.load(f)

    if certname not in data['certificates']:
        return Response(response='{"status": 404, "error": "certificate not found"}', content_type="application/json", status=404)

    if auth.username() not in data["certificates"][certname]["access"]:
        return Response(response='{"status": 401, "error": "Unauthorized for this user"}', content_type="application/json", status=401)

    return Response(response=data["certificates"][certname]["private_key"], content_type="application/x-pem-file", status=200)


if __name__ == "__main__":
    app.run(debug=True)
