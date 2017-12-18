import requests
from pymacaroons import Macaroon


def get_authorization_header(root, discharge):
    """
    Bind root and discharge macaroons and return the authorization header.
    """

    bound = Macaroon.deserialize(root).prepare_for_request(
        Macaroon.deserialize(discharge)
    )

    return 'Macaroon root={}, discharge={}'.format(root, bound.serialize())


def is_authenticated(session):
    return (
        'openid' in session and
        'macaroon_discharge' in session and
        'macaroon_root' in session
    )


def empty_session(session):
    session.pop('macaroon_root', None)
    session.pop('macaroon_discharge', None)
    session.pop('openid', None)


def get_caveat_id(root):
    caveat, = [
        c for c in Macaroon.deserialize(root).third_party_caveats()
        if c.location == 'login.ubuntu.com'
    ]

    return caveat.caveat_id


def request_macaroon():
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

    return response.json()['macaroon']


def verify_macaroon(root, discharge, url):
    """
        Submit a request to verify a macaroon used for authorization.
        Returns the response.
    """
    authorization = get_authorization_header(root, discharge)
    response = requests.request(
        url='https://dashboard.snapcraft.io/dev/api/acl/verify/',
        method='POST',
        json={
            'auth_data': {
                'authorization': authorization,
                'http_uri': url,
                'http_method': 'GET'
            }
        },
        headers={
            'Accept': 'application/json, application/hal+json',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
        }
    )

    return response.json()


def get_refreshed_discharge(discharge):
    """
        Get a refresh macaroon if the macaroon is not valid anymore.
        Returns the new discharge macaroon.
    """
    url = (
        'https://login.ubuntu.com'
        '/api/v2/tokens/refresh'
    )
    response = requests.request(
        url=url,
        method='POST',
        json={'discharge_macaroon': discharge},
        headers={
            'Accept': 'application/json, application/hal+json',
            'Content-Type': 'application/json',
            'Cache-Control': 'no-cache',
        }
    )

    return response.json()['discharge_macaroon']
