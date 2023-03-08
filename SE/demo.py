import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request
from flask import send_file,render_template
from flask import Flask, redirect, url_for, session, request, jsonify
from flask import url_for
from authlib.integrations.flask_client import OAuth
from flask_oauthlib.client import OAuth,OAuthException
from flask import session
from flask_dance.contrib.twitter import make_twitter_blueprint, twitter
from pip._vendor import cachecontrol
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests


#for google
myapp = Flask("Application")
myapp.secret_key = "google.com"
oauth = OAuth(myapp)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
g_id = "681357783167-q8s40t0h3l7gqoippft658opejg7n1ft.apps.googleusercontent.com"
credentials_files = os.path.join(pathlib.Path(__file__).parent, "credentials.json.json")   

f = Flow.from_client_secrets_file(
    client_secrets_file=credentials_files,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://localhost:5000//callback"
)

#for github
myapp.config['git_id'] = "6badc317aa9be87a001f"
myapp.config['git_secret'] = "a16a9ecffbe377125910d16f9f3c461cc152c0dd"

#for facebook
F_ID = '3195740460739063'
F_SECRET = '01022c0c888d7d83511bce906a2323e0'

#for linkedin
linkedin = oauth.remote_app(
    'linkedin',
    consumer_key='77td29z882tr6d',
    consumer_secret='YSCCRyn7VVjkG5m1',
    request_token_params={
        'scope': 'r_basicprofile',
        'state': 'RandomString',
    },
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
    authorize_url='https://www.linkedin.com/uas/oauth2/authorization',
)


#github
from authlib.integrations.flask_client import OAuth
o = OAuth(myapp)

git = o.register (
  name = 'git',
    client_id = myapp.config["git_id"],
    client_secret = myapp.config["git_secret"],
    access_token_url = 'https://github.com/login/oauth/access_token',
    access_token_params = None,
    authorize_url = 'https://github.com/login/oauth/authorize',
    authorize_params = None,
    api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope': 'user:email'},
)

#facebook
from flask_oauthlib.client import OAuth,OAuthException
o = OAuth(myapp)
facebook = o.remote_app(
    'facebook',
    consumer_key=F_ID,
    consumer_secret=F_SECRET,
    request_token_params={'scope': 'email'},
    base_url='https://graph.facebook.com',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    access_token_method='GET',
    authorize_url='https://www.facebook.com/dialog/oauth'
)



def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401)  # Authorization required
        else:
            return function()

    return wrapper



from authlib.integrations.flask_client import OAuth
oauth = OAuth(myapp)

# Github login route
@myapp.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_url = url_for('github_authorize', _external=True)
    return render_template('home.html')


#linkedin login route
@myapp.route('/login/linkedin')
def login_linkedin():
    return render_template('home.html') 

@myapp.route('/login/linkedin/authorized')
def linkedin_authorized():
    resp = linkedin.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['linkedin_token'] = (resp['access_token'], '')
    me = linkedin.get('people/~')
    return jsonify(me.data)

@linkedin.tokengetter
def get_linkedin_oauth_token():
    return session.get('linkedin_token')


def change_linkedin_query(uri, headers, body):
    auth = headers.pop('Authorization')
    # headers['x-li-format'] = 'json'
    if auth:
        auth = auth.replace('Bearer', '').strip()
        if '?' in uri:
            uri += '&oauth2_access_token=' + auth
        else:
            uri += '?oauth2_access_token=' + auth
    return uri, headers, body

linkedin.pre_request = change_linkedin_query


@myapp.route('/login/github/authorize')
def github_authorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user').json()
    print(f"\n{resp}\n")
    return "You are successfully signed in using github <br/> <a href='/download'>download</a> <br> <a href='/logout'><button>Logout</button></a>"


@myapp.route("/login")
def login():
    authorization_url, state = f.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@myapp.route("/callback")
def callback():
    f.fetch_token(authorization_response=request.url)

    '''if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!'''

    credentialss = f.credentials
    r_session = requests.session()
    cach_session = cachecontrol.CacheControl(r_session)
    token_req = google.auth.transport.requests.Request(session=cach_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentialss._id_token,
        request=token_req,
        audience=g_id
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/page")

#facebook login 
@myapp.route('/login/facebook')
def facebook_login():
    callback = url_for(
        'f_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True
    )
    return facebook.authorize(callback=callback)


@myapp.route('/login/facebook/authorized')
def f_authorized():
    resp = facebook.authorized_response()
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    if isinstance(resp, OAuthException):
        return 'Access denied: %s' % resp.message

    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    return 'Logged in as id=%s name=%s redirect=%s <a href="/download">download</a> <br> <a href="/logout">logout</a>' % \
        (me.data['id'], me.data['name'], request.args.get('next'))
        
@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')
'''

'''
@myapp.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@myapp.route("/download")
def download_file():
    p = "happy.png"
    return send_file(p,as_attachment=True)
    


@myapp.route("/")
def index():
    
    return "<h1>! ASSIGNMENT IV!</h1><br> <a href='/login'><button>GOOGLE</button></a> <br><br> <a href='/login/github''><button>GITHUB</button></a> <br><br> <a href='/login/linkedin'><button>LINKEDIN</button></a> <br><br> <a href='login/facebook'><button>FACEBOOK</button></a><br><br>"

@myapp.route("/page")
@login_is_required
def page():
    return render_template('home.html')

if __name__ == "__main__":
    myapp.run(debug=True)
    myapp.run(host='0.0.0.0', port = 5000)

