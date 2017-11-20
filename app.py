import flask
import requests
from flask_openid import OpenID
from openid.extension import Extension as OpenIDExtension
from pymacaroons import Macaroon


class MacaroonRequest(OpenIDExtension):
    ns_uri = 'http://ns.login.ubuntu.com/2016/openid-macaroon'
    ns_alias = 'macaroon'

    def __init__(self, caveat_id):
        self.caveat_id = caveat_id

    def getExtensionArgs(self):
        """
        Return the arguments to add to the OpenID request query
        """

        return {
            'caveat_id': self.caveat_id
        }


class MacaroonResponse(OpenIDExtension):
    ns_uri = 'http://ns.login.ubuntu.com/2016/openid-macaroon'
    ns_alias = 'macaroon'

    def getExtensionArgs(self):
        """
        Return the arguments to add to the OpenID request query
        """

        return {
            'discharge': self.discharge
        }

    def fromSuccessResponse(cls, success_response, signed_only=True):
        self = cls()
        if signed_only:
            args = success_response.getSignedNS(self.ns_uri)
        else:
            args = success_response.message.getArgs(self.ns_uri)

        if not args:
            return None

        self.discharge = args['discharge']

        return self

    fromSuccessResponse = classmethod(fromSuccessResponse)


app = flask.Flask(__name__)
app.config.update(
    SECRET_KEY="This is a super secret key!",
    DEBUG=True
)
UBUNTU_SSO_URL = "https://login.ubuntu.com"

oid = OpenID(
    app,
    safe_roots=[],
    extension_responses=[MacaroonResponse]
)


def get_authorization_header(root, discharge):
    """
    Bind root and discharge macaroons and return the authorization header.
    """

    bound = Macaroon.deserialize(root).prepare_for_request(
        Macaroon.deserialize(discharge))

    return 'Macaroon root={}, discharge={}'.format(root, bound.serialize())


@app.route('/')
def homepage():
    return flask.render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    response = requests.request(
        url='https://dashboard.snapcraft.io/dev/api/acl/',
        method='POST',
        json={'permissions': ['package_access']},
        headers={
            'Accept': 'application/json, application/hal+json',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
        }
    )
    root = response.json()['macaroon']

    caveat, = [
        c for c in Macaroon.deserialize(root).third_party_caveats()
        if c.location == 'login.ubuntu.com'
    ]

    openid_macaroon = MacaroonRequest(caveat_id=caveat.caveat_id)

    flask.session['macaroon_root'] = root

    return oid.try_login(
        UBUNTU_SSO_URL,
        ask_for=['email', 'nickname'],
        ask_for_optional=['fullname'],
        extensions=[openid_macaroon]
    )


@oid.after_login
def create_or_login(resp):
    flask.session['openid'] = resp.identity_url

    flask.session['macaroon_discharge'] = resp.extensions['macaroon'].discharge

    authorization = get_authorization_header(
        flask.session['macaroon_root'],
        flask.session['macaroon_discharge']
    )
    headers = {
        'X-Ubuntu-Series': '16',
        'X-Ubuntu-Architecture': 'amd64',
        'Authorization': authorization
    }
    url = (
        'https://api.snapcraft.io/api/v1/snaps/details'
        '/documentation-builder?revision=3'
    )

    response = requests.request(url=url, method='GET', headers=headers)
    response.raise_for_status()

    print('HTTP/1.1 {} {}'.format(response.status_code, response.reason))

    return "<h1>documentation-builder v3</h1><p>{}</p>".format(
        str(response.json())
    )


@app.route('/logout')
def logout():
    flask.session.pop('openid', None)
    return flask.redirect(oid.get_next_url())


if __name__ == '__main__':
    app.run()
