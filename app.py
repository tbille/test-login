import flask
import requests
import authentication
from macaroon import MacaroonRequest, MacaroonResponse
from flask_openid import OpenID

app = flask.Flask(__name__)
app.config.update(
    SECRET_KEY="This is a super secret key!",
    DEBUG=True
)

oid = OpenID(
    app,
    safe_roots=[],
    extension_responses=[MacaroonResponse]
)


def redirect_to_login():
    return flask.redirect(''.join([
        'login?next=',
        flask.request.url_rule.rule,
    ]))


@app.route('/')
def homepage():
    context = {}
    if authentication.is_authenticated(flask.session):
        context['connected'] = True

    return flask.render_template('index.html', **context)


@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    if authentication.is_authenticated(flask.session):
        return flask.redirect(oid.get_next_url())

    root = authentication.request_macaroon()
    openid_macaroon = MacaroonRequest(
        caveat_id=authentication.get_caveat_id(root)
    )
    flask.session['macaroon_root'] = root

    return oid.try_login(
        'https://login.ubuntu.com',
        ask_for=['email', 'nickname'],
        ask_for_optional=['fullname'],
        extensions=[openid_macaroon]
    )


@oid.after_login
def after_login(resp):
    flask.session['openid'] = resp.identity_url
    flask.session['macaroon_discharge'] = resp.extensions['macaroon'].discharge
    return flask.redirect('/account')


@app.route('/account')
def get_account():
    if not authentication.is_authenticated(flask.session):
        return redirect_to_login()

    authorization = authentication.get_authorization_header(
        flask.session['macaroon_root'],
        flask.session['macaroon_discharge']
    )

    headers = {
        'X-Ubuntu-Series': '16',
        'X-Ubuntu-Architecture': 'amd64',
        'Authorization': authorization
    }

    url = 'https://dashboard.snapcraft.io/dev/api/account'
    response = requests.request(url=url, method='GET', headers=headers)

    verified_response = authentication.verify_response(
        response,
        flask.session,
        url,
        '/account',
        '/login'
    )

    if verified_response is not None:
        if verify_response['redirect'] is None:
            return response.raise_for_status
        else:
            return flask.redirect(
                validate_response.redirect
            )

    print('HTTP/1.1 {} {}'.format(response.status_code, response.reason))

    return "<h1>Developer Account</h1><p>{}</p>".format(
        str(response.json())
    )


@app.route('/logout')
def logout():
    if authentication.is_authenticated(flask.session):
        authentication.empty_session(flask.session)
    return flask.redirect('/')


if __name__ == '__main__':
    app.run()
