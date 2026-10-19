import flask


httpchallenge_server = flask.Flask(__name__)



authorizations = {}



@httpchallenge_server.route('/.well-known/acme-challenge/<string:token>')
def http_challenge(token):
    if token in authorizations:
        return flask.Response(authorizations[token], mimetype="application/octet-stream")
    else:
        flask.abort(404)


def register_http_challenge(token, authorization):
    authorizations[token] = authorization






