from flask import Flask
from flask import request
from flask import make_response

app = Flask(__name__)

@app.before_request
def before_req():
    ja3hash = request.headers.get("X-Ja3-Hash", False)

    if ja3hash == "375c6162a492dfbf2795909110ce8424":
        return "JA3 BLOCKED"

@app.route('/')
def hello_world():
    resp = make_response(dict(request.headers))
    print(dict(resp.headers))
    return resp

if __name__ == '__main__':

    app.run(port=8080)
