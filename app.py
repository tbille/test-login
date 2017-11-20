import flask
import requests
from macaroon import MacaroonRequest
from macaroon import MacaroonResponse
from flask_openid import OpenID
from pymacaroons import Macaroon

app = flask.Flask(__name__)
app.config.update(
    SECRET_KEY="This is a super secret key!",
    DEBUG=True
)

UBUNTU_SSO_URL = "https://login.ubuntu.com"
SCA_BASE_URL = "https://dashboard.snapcraft.io/dev/api/"

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
        Macaroon.deserialize(discharge)
    )

    return 'Macaroon root={}, discharge={}'.format(root, bound.serialize())


def is_connected():
    return (
        'openid' in flask.session or
        'macaroon_discharge' in flask.session or
        'macaroon_root' in flask.session
    )


def redirect_to_login():
    return flask.redirect(
        'login?next=' +
        flask.request.url_rule.rule
    )


@app.route('/')
def homepage():
    context = {}
    if is_connected():
        context['connected'] = True

    return flask.render_template('index.html', **context)


@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    if is_connected():
        return flask.redirect(oid.get_next_url())

    response = requests.request(
        url=SCA_BASE_URL + '/acl/',
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
def after_login(resp):
    flask.session['openid'] = resp.identity_url
    flask.session['macaroon_discharge'] = resp.extensions['macaroon'].discharge

    return flask.redirect(oid.get_next_url())


@app.route('/app-detail')
def get_app_detail():
    if not is_connected():
        return redirect_to_login()

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
    if is_connected():
        flask.session.pop('macaroon_root', None)
        flask.session.pop('macaroon_discharge', None)
        flask.session.pop('openid', None)

    return flask.redirect('/')


if __name__ == '__main__':
    app.run()
