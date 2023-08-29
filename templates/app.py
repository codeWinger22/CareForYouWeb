import json
import os
import sqlite3
from flask_sqlalchemy import SQLAlchemy

#set up the environment variable 
#this environment variable need to be set in order to run it over http 
#as we are running this currently on localhost
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'   #without https

from flask import Flask,redirect,request,url_for,render_template
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user)

#this flask login package is important for user session management instead of creating it manually we are using the predefined library


from oauthlib.oauth2 import WebApplicationClient
#WebapplicationClient because we are building it on the client side
import requests
#from db import init_db_command
from user import User


#now we will import the environment variables 
#GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID',None)
#GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET',None)
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_CLIENT_ID = "652381501875-vav5i893k6atvuj80vei5j0u77cfid5v.apps.googleusercontent.com"


GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")
#this discovery url is basically the one from where your app will fetch google account from


app = Flask(__name__, static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///basicinformation.sqlite3'
app.config['SECRET_KEY'] = "secret key"
db = SQLAlchemy(app)

#either you can set a secret key in environment variable or just generate a 24char secret key


login_manager = LoginManager()
login_manager.init_app(app)
#this is not required until the external db.py file is working

def init_db_command():
    connection = sqlite3.connect('database.db')
    with open('schema.sql') as f:
        connection.executescript(f.read())

    cur = connection.cursor()
    connection.commit()
    connection.close()


#initialize a handler
@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content",403

#try:
    init_db_command()
    

#except sqlite3.OperationalError:
#    pass

client = WebApplicationClient(GOOGLE_CLIENT_ID)
#initialize helper
@login_manager.user_loader
def load_user(user_id):
    flag = 0
    user = User.get(user_id,flag)
    print(user,"from main helper")
    if not user:
        return None
    return user
    



    #return User.get(user_id,flag)

@app.route('/connection')
def connection():
    return render_template('admin_doctor.html')


@app.route('/')
def index():
    return "<h1>This project will be updated within 24 hours and you will be redirected to the original site soon. Sorry for the inconvenience</h1>"

	
    #print("reached in index api")
    #print(current_user)
    #if(current_user.is_authenticated):
      #  print("from final ")
        #print(current_user.name)
        #print(current_user.email)
        #return ("<h1> YOU ARE LOGGED IN </h1>"
               # "<div> <p> Google Profile </p>"
               # '<img src = "{}" alt = "Google Profile Pic" ></img></div>'
               # '<a class "button" href = "/logout">Logout</a>'.format(current_user.name,current_user.email,current_user.profile_pic))
    #else:
      #  print("not authenticated")
       # return render_template('index.html')
       # return '<a class = "button" href = "/loginAdmin"> Google Admin Login </a>  <br><br> <a class = "button" href = "/loginDoctor"> #Google Login </a>' 






@app.route('/adminapprovedoctor')
def adminapprovedoctor():
    return render_template('admin_approve_doctor.html')


@app.route('/adminviewdoctor')
def adminviewdoctor():
    return render_template('admin_view_doctor.html')


@app.route('/adminindex')
def adminindex():
    if(current_user.is_authenticated):
        print("from final ")
        print(current_user.name)
        print(current_user.email)

        return ("<h1> YOU ARE LOGGED IN AS ADMIN</h1>"
                "<div> <p> Google Profile </p>"
                '<img src = "{}" alt = "Google Profile Pic" ></img></div>'
                '<a class "button" href = "/logout">Logout</a>'.format(current_user.name,current_user.email,current_user.profile_pic))
    else:
        print("not authenticated")
        return render_template('index.html')

@app.route('/doctorindex')
def doctorindex():
    if(current_user.is_authenticated):
        print("from final ")
        print(current_user.name)
        print(current_user.email)
        return ("<h1> YOU ARE LOGGED IN AS DOCTOR</h1>"
                "<div> <p> Google Profile </p>"
                '<img src = "{}" alt = "Google Profile Pic" ></img></div>'
                '<a class "button" href = "/logout">Logout</a>'.format(current_user.name,current_user.email,current_user.profile_pic))
    else:
        print("not authenticated")
        return render_template('index.html')
    

@app.route('/patientindex')
def patientindex():
    if(current_user.is_authenticated):
        print("from final ")
        print(current_user.name)
        print(current_user.email)
        return ("<h1> YOU ARE LOGGED IN AS PATIENT</h1>"
                "<div> <p> Google Profile </p>"
                '<img src = "{}" alt = "Google Profile Pic" ></img></div>'
                '<a class "button" href = "/logout">Logout</a>'.format(current_user.name,current_user.email,current_user.profile_pic))
    else:
        print("not authenticated")
        return render_template('index.html')


@app.route('/logout')
@login_required
def logout():
    
    if(logout_user()):
        
        print("logged out")
        current_user.authenticated = False

    return redirect(url_for('index'))
    
    #return '<a class = "button" href = "/login"> Google Login </a>' 


@app.route('/login<flag>')
def login(flag):
    
    print("this is login flag ")
    print(flag)
  
    if(flag == '1'):
        google_provider_cgf =  get_google_provider_cfg()
        authorization_endpoint = google_provider_cgf['authorization_endpoint']
        request_uri  = client.prepare_request_uri(authorization_endpoint,redirect_uri="http://localhost:5000/login/callbackAdmin",scope = ['openid','email','profile'])
        print("completed login process",request_uri)
    elif(flag == '2'):
        google_provider_cgf =  get_google_provider_cfg()
        authorization_endpoint = google_provider_cgf['authorization_endpoint']
        request_uri  = client.prepare_request_uri(authorization_endpoint,redirect_uri="http://localhost:5000/login/callbackDoctor",scope = ['openid','email','profile'])
        print("completed login process",request_uri)

    elif(flag == '3'):
        google_provider_cgf =  get_google_provider_cfg()
        authorization_endpoint = google_provider_cgf['authorization_endpoint']
        request_uri  = client.prepare_request_uri(authorization_endpoint,redirect_uri="http://localhost:5000/login/callbackPatient",scope = ['openid','email','profile'])
        print("completed login process",request_uri)
        

    return redirect(request_uri)
  
    

    #configuration url 
    #redirect url = http://localhost:5000/login/callbackAdmin
    #client = WebApplicationClient(GOOGLE_CLIENT_ID_ADMIN)
   

@app.route('/login/callbackAdmin')
def callbackAdmin():
    print("reached in callbackAdmin")
    flag = 1
    
    code = request.args.get('code')
    #authorization code 
    #now with this we can get the authorization
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint  = google_provider_cfg['token_endpoint']

    #prepare token url 
    token_url , headers , body = client.prepare_token_request(token_endpoint,authorization_response=request.url,redirect_url="http://localhost:5000/login/callbackAdmin",code = code)
    token_response = requests.post(token_url,headers=headers,data = body,auth=(GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri,headers=headers,data = body)
    print(userinfo_response.json())
    if(userinfo_response.json().get('email_verified')):
        unique_id = userinfo_response.json()['sub']
        user_email = userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        username = userinfo_response.json()['given_name']
        print("before inserting into db callback function")
    else:
        return "User email not available or not verified by google",400
    #now we need to insert this user inside our sqlite db

    user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
    print(unique_id)

    returnfunction = User.get(unique_id,flag)
    print(returnfunction)
    if( returnfunction != None):
        print("user already exists")
    else:

        User.create(unique_id,username,user_email,picture,flag)



    #start the session
    if(login_user(user)):
        print("user logged in")
        print("completed callback admin process ")
        current_user.autheticated = True
    else:
        print("user not logged in")



    #and redirect to the homepage
    return redirect(url_for('adminindex')) #def index which is created previously




@app.route('/login/callbackDoctor')
def callbackDoctor():
    print("reached in callbackDoctor")
    flag = 2
    
    code = request.args.get('code')
    #authorization code 
    #now with this we can get the authorization
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint  = google_provider_cfg['token_endpoint']

    #prepare token url 
    token_url , headers , body = client.prepare_token_request(token_endpoint,authorization_response=request.url,redirect_url="http://localhost:5000/login/callbackDoctor",code = code)
    token_response = requests.post(token_url,headers=headers,data = body,auth=(GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri,headers=headers,data = body)
    print(userinfo_response.json())
    if(userinfo_response.json().get('email_verified')):
        unique_id = userinfo_response.json()['sub']
        user_email = userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        username = userinfo_response.json()['given_name']
        print("before inserting into db callback function")
    else:
        return "User email not available or not verified by google",400
    #now we need to insert this user inside our sqlite db

    user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
    print(unique_id)
    
    returnfunction = User.get(unique_id,flag)
    print(returnfunction)
    if( returnfunction != None):
        print("user already exists")
    else:
        
        User.create(unique_id,username,user_email,picture,flag)
        return redirect('')


    #start the session
    if(login_user(user)):
        print("user logged in")
        print("completed callback doctor process ")
        current_user.autheticated = True
    else:
        print("user not logged in")



    #and redirect to the homepage
    return redirect(url_for('doctorindex')) #def index which is created previously





@app.route('/login/callbackPatient')
def callbackPatient():
    print("reached in callbackPatient")
    flag = 3
    
    code = request.args.get('code')
    #authorization code 
    #now with this we can get the authorization
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint  = google_provider_cfg['token_endpoint']

    #prepare token url 
    token_url , headers , body = client.prepare_token_request(token_endpoint,authorization_response=request.url,redirect_url="http://localhost:5000/login/callbackPatient",code = code)
    token_response = requests.post(token_url,headers=headers,data = body,auth=(GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri,headers=headers,data = body)
    print(userinfo_response.json())
    if(userinfo_response.json().get('email_verified')):
        unique_id = userinfo_response.json()['sub']
        user_email = userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        username = userinfo_response.json()['given_name']
        print("before inserting into db callback function")
    else:
        return "User email not available or not verified by google",400
    #now we need to insert this user inside our sqlite db

    user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
    print(unique_id)
    
    returnfunction = User.get(unique_id,flag)
    print(returnfunction)
    if( returnfunction != None):
        print("user already exists")
    else:
        
        User.create(unique_id,username,user_email,picture,flag)


    #start the session
    if(login_user(user)):
        print("user logged in")
        print("completed callback patient process ")
        current_user.autheticated = True
    else:
        print("user not logged in")



    #and redirect to the homepage
    return redirect(url_for('patientindex')) #def index which is created previously










   #-----------------------------------------------------------------------




#original login and callback
""" @app.route('/loginoriginal')
def login():
    #configuration url 
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
    google_provider_cgf =  get_google_provider_cfg()
    authorization_endpoint = google_provider_cgf['authorization_endpoint']
    request_uri  = client.prepare_request_uri(authorization_endpoint,redirect_uri="http://localhost:5000/login/callback",scope = ['openid','email','profile'])
    print("this is request uri")
    print(request_uri)
    return redirect(request_uri)

@app.route('/login/callbackoriginal')
def callback():
    client = WebApplicationClient(GOOGLE_CLIENT_ID)
    code = request.args.get('code')
    #authorization code 
    #now with this we can get the authorization
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint  = google_provider_cfg['token_endpoint']

    #prepare token url 
    token_url , headers , body = client.prepare_token_request(token_endpoint,authorization_response=request.url,redirect_url="http://localhost:5000/login/callback",code = code)
    token_response = requests.post(token_url,headers=headers,data = body,auth=(GOOGLE_CLIENT_ID,GOOGLE_CLIENT_SECRET))
    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg['userinfo_endpoint']
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri,headers=headers,data = body)
    print(userinfo_response.json())
    if(userinfo_response.json().get('email_verified')):
        unique_id = userinfo_response.json()['sub']
        user_email = userinfo_response.json()['email']
        picture = userinfo_response.json()['picture']
        username = userinfo_response.json()['given_name']
        print("before inserting into db callback function")
    else:
        return "User email not available or not verified by google",400
    #now we need to insert this user inside our sqlite db

    user = User(id= unique_id,name = username, email = user_email,profile_pic=picture)
    print(unique_id)
    returnfunction = User.get(unique_id)
    print(returnfunction)
    if( returnfunction != None):
        print("user already exists")
    else:
        User.create(unique_id,username,user_email, picture)


    #start the session
    if(login_user(user)):
        print("user logged in")
    else:
        print("user not logged in")



    #and redirect to the homepage
    return redirect(url_for('index')) #def index which is created previously
    """

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


if __name__ == '__main__':
    app.run(debug=True)
