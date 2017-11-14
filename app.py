import flask
from flask_openid import OpenID
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

app = flask.Flask(__name__)
app.config.update(
    DATABASE_URI = 'sqlite:///flask-openid.db',
    SECRET_KEY = 'This is a super secret key!',
    DEBUG = True
)
UBUNTU_SSO_URL = "https://login.ubuntu.com"

oid = OpenID(app, safe_roots=[])

# setup sqlalchemy
engine = create_engine(app.config['DATABASE_URI'])
db_session = scoped_session(
    sessionmaker(
        autocommit=False,
        autoflush=True,
        bind=engine
    )
)
Base = declarative_base()
Base.query = db_session.query_property()

def init_db():
    Base.metadata.create_all(bind=engine)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(String(60))
    email = Column(String(200))
    openid = Column(String(200))

    def __init__(self, name, email, openid):
        self.name = name
        self.email = email
        self.openid = openid


@app.before_request
def lookup_current_user():
    flask.g.user = None
    if 'openid' in flask.session:
        openid = flask.session['openid']
        flask.g.user = User.query.filter_by(openid=openid).first()


@app.after_request
def after_request(response):
    db_session.remove()
    return response


@app.route('/')
def homepage():
    context = {}
    if flask.g.user is not None:
        context['connected'] = True
    return flask.render_template('index.html', **context)


@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    if flask.g.user is not None:
        return flask.redirect(oid.get_next_url())

    return oid.try_login(
        UBUNTU_SSO_URL,
        ask_for=['email', 'nickname'],
        ask_for_optional=['fullname'],
    )


@oid.after_login
def create_or_login(resp):
    flask.session['openid'] = resp.identity_url
    user = User.query.filter_by(openid=resp.identity_url).first()

    if user is not None:
        flask.g.user = user
    else:
        db_session.add(
            User(
                resp.fullname,
                resp.email,
                flask.session['openid']
            )
        )
        db_session.commit()

    return flask.redirect(oid.get_next_url())


@app.route('/logged')
def logged():
    if flask.g.user is None:
        return flask.redirect('/login')
    return flask.render_template('logged.html')


@app.route('/logout')
def logout():
    flask.session.pop('openid', None)
    return flask.redirect(oid.get_next_url())


if __name__ == '__main__':
    init_db()
    app.run()
