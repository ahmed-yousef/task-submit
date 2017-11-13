from flask import Flask,redirect,request,url_for,session,render_template,send_from_directory
from werkzeug import secure_filename
import google.oauth2.credentials
import google_auth_oauthlib.flow
from google.cloud import datastore
import datetime
import os
import json
import requests

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'#remove when deploying app engine
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'assignment-submit.json'#required for datastore API

dir_path = os.path.dirname(os.path.realpath(__file__))#work directory path
credential_dir = os.path.join(dir_path, '.configs')#credentials or configs it doesnot matter
if not os.path.exists(credential_dir):
        os.makedirs(credential_dir)
credential_path = os.path.join(credential_dir,'drive-auth.json')

#print(credential_path)#credintal path got from auth operation callback()

access_from_refresh='' #here we save auth token from refresh
client_saved=''
creds_saved=''
def check_auth():
        print("we are checking auth")
        creds_found=load_files()
        if creds_found:
                valid="https://www.googleapis.com/oauth2/v1/tokeninfo?access_token="+creds_saved['token']
                check=requests.get(valid)
                print(check.status_code,"/n /n",check.text)
                if not check.status_code==200:
                        print("creds_found ",creds_found)
                        auth="https://www.googleapis.com/oauth2/v4/token"
                        header={'Content-Type':'application/x-www-form-urlencoded'}
                        payload={'client_id':client_saved['web']['client_id'],\
                          'client_secret':client_saved['web']['client_secret'],\
                          'refresh_token':creds_saved['refresh_token'],\
                          'grant_type':'refresh_token'}
                        req=requests.post(auth,headers=header,data=payload)
                        if req.status_code == 200:
                                mid=json.loads(req.text)
                                global access_from_refresh
                                access_from_refresh=mid['access_token']
                                jsonFile = open(credential_path, "r")
                                data = json.load(jsonFile)
                                jsonFile.close()
                                data["token"] = mid['access_token']
                                jsonFile = open(credential_path, "w+")
                                jsonFile.write(json.dumps(data))
                                jsonFile.close()
                                return True
                else:
                        access_from_refresh=creds_saved['token']
                        return True
        print("no auth found")
        return False

def create_client(project_id):
    return datastore.Client(project_id)

def add_user(client, reg_id,drive_id,name,email):
    key = client.key('User',int(reg_id))
    task = datastore.Entity(key, exclude_from_indexes=['retry_times','drive_folder_id'])
    task.update({
        'reg_id':int(reg_id),
        'created': datetime.datetime.utcnow(),
        'email':email,
        'drive_folder_id': drive_id,
        'retry_times': 1,
        'name':name
    })
    client.put(task)
    return task.key

def add_retry(client, reg_id,drive_id,name,email):
    with client.transaction():
        key = client.key('User', int(reg_id))
        task = client.get(key)

        if not task:
            print('User {} does not exist.'.format(reg_id))
            print(add_user(client,reg_id,drive_id,name,email))
            return "User Created"
        else:    
            task['retry_times'] += 1 
            client.put(task)
            return True
    return False

def update_user(client, reg_id,prop=None,val=None):
    with client.transaction():
        key = client.key('User', int(reg_id))
        user = client.get(key)
        if not user:
            print('User "{}" does not exist.'.format(reg_id))
            return False
        else:    
            user[str(prop)]= val
            client.put(user)
            return True
    return False

def check_user(client,reg_id):
    with client.transaction():
        key = client.key('User', int(reg_id))
        user = client.get(key)
        if not user:
            print('User "{}" does not exist.'.format(reg_id))
            return False
        else:    
            return True
        
def get_creds(client):
    query = client.query(kind="admin")
    fetch=list(query.fetch())
    user=fetch[0]['user']
    password=fetch[0]['pass']
    cred=[user,password]
    return cred

def get_prop(client,prop,user):#i use this for admin log in
    query = client.query(kind=str(user))
    fetch=list(query.fetch())
    try:
      prop=fetch[0][prop]
    except:
        print('Can not find that property "{}".'.format(prop))
        pass
    return prop

def get_props(client,criteria,val):
    query = client.query(kind='User')
    query.add_filter(criteria, '=', val)
    fetch=list(query.fetch())
    try:
        prop=fetch[0]
    except:
        print('Can not find that property .')
        return False
    return dict(prop)
        
def update_admin(client, admin_id, prop, val):
    with client.transaction():
        key = client.key('admin', admin_id)
        admin = client.get(key)

        if not admin:
            raise ValueError(
                'Key {} does not exist.'.format(admin_id))
        admin[prop] = val
        client.put(admin)

def load_files():
###load clien_secret.json and drive-pyton.json if found
        try:
          with open(credential_path) as data1:
                global creds_saved
                creds_saved = json.load(data1)
                creds_found=True
        except FileNotFoundError:
                creds_found=False
                print(creds_found)
        with open('client_secret.json') as data2:
                global client_saved
                client_saved = json.load(data2)
        return creds_found
###     

       
app=Flask(__name__)
upload = dir_path+"\\uploads"
app.config['UPLOAD_FOLDER'] = upload
app.secret_key = 'hello_darkness_my_old_friend'

@app.route('/fonts/<filename>')
def fonts(filename):
    return send_from_directory('static/fonts', filename)

@app.route('/auth')
def auth():
    if 'username' in session:
      username = session['username']
      flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file('client_secret.json',\
      scopes=['https://www.googleapis.com/auth/drive'])
      flow.redirect_uri = 'http://127.0.0.1:8080/callback'
      authorization_url, state = flow.authorization_url(access_type='offline',include_granted_scopes='true',approval_prompt='force')
      return redirect(authorization_url)
    else:
         return "You are not logged in <br><a href = '/admin'></b>" + \
      "click here to log in</b></a>"

@app.route('/admin',methods=['GET', 'POST'])
def log():
    #check user and pass
    if request.method == 'POST':
        user = request.form['user']
        password=request.form['pass']
        client=create_client("assignment-submit")
        creds=get_creds(client)
        last_login=get_prop(client,'last_login','admin')
        if creds[0]==user and creds[1]==password:
            session['username'] = user
            session['last_login'] = last_login
            update_admin(client,'admin','last_login',datetime.datetime.utcnow())
            return redirect(url_for('logged'))
        else:
            error="Please enter vaild user name and password"
            return render_template('admin.html',error=error)
    message="Ready"
    return render_template('admin.html',error=message)

@app.route('/update',methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        if 'username' in session:
           old = request.form['old']
           user = request.form['user']
           password=request.form['pass']
           client=create_client("assignment-submit")
           creds=get_creds(client)
           if creds[1]==old:
               update_admin(client,'admin','user',user)
               update_admin(client,'admin','pass',password)
               update_admin(client,'admin','last_update',datetime.datetime.utcnow())
               return 'success'
           else:
               return 'failure'
        else:
            return 'fail'

@app.route('/logged')
def logged():
    if 'username' in session:
      username = session['username']
      last_login = session['last_login']
      if check_auth():
          message="You are Authorized"
          print("check auth in logged ",message)
          print("auth_token:",access_from_refresh)
          return render_template('logged.html',user_name=username,message=message,last_login=last_login,access=access_from_refresh)
      else:
          message="Auth is Required click AUTH CLOUD"
          print("check auth in logged ",message)
          return render_template('logged.html',user_name=username,message=message,last_login=last_login,access=0)
    return "You are not logged in <br><a href = '/admin'></b>" + \
      "click here to log in</b></a>"

@app.route('/callback')
def callback():
    #set folder of auth_token and save refresh_token
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file('client_secret.json',
    scopes=['https://www.googleapis.com/auth/drive'])
    flow.redirect_uri = url_for('callback', _external=True)
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    cred =json.dumps( {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes},separators=(',',':'))
    f = open(credential_path, 'w')
    f.write(cred)
    f.close()
    ##create folder using drive api and save it s` name in credential_dir as file with drive folder name in it(drive_folder.txt)
    print(check_auth())
    print(check_drive_folder(drive_folder(1)))
    if not check_drive_folder(drive_folder(1)):    
        req=create_folder('Assignment Submit')
        print(req.text)
        if req.status_code == 200:
            drive_id=json.loads(req.text)
            if drive_id['mimeType']=='application/vnd.google-apps.folder':
               drive_folder(drive_id["id"],'new')
            else:
                    print("Error no folder created")
    return redirect(url_for('logged'))

def drive_folder(drive_folder_id=0,state='old'):
        folder_path=credential_dir+"\\drive_folder.txt"
        if not os.path.exists(folder_path):
                os.path.join(credential_dir,"drive_folder.txt")
        if  state == 'new':
                f = open(folder_path, 'w')
                f.write(drive_folder_id)
                f.close
                print("success")
        if drive_folder_id == 1:#return folder id
                try:
                    f = open(folder_path)
                    data=f.read()
                    f.close
                    return data
                except:
                       return False
        if drive_folder_id == 2:#if i want drive folder path
                return folder_path
        if drive_folder_id == 0:#return folder exist or not
                return os.path.exists(folder_path)

def create_folder(name,parentid=None):
    url='https://www.googleapis.com/drive/v3/files'
    header={'Authorization':'Bearer {}'.format(access_from_refresh),'Content-Type': 'application/json'}
    metadata={"mimeType": 'application/vnd.google-apps.folder',
  "name": name}
    if parentid:
            metadata['parents']=[parentid]
    req=requests.post(url,headers=header,data=json.dumps(metadata))
    return req

def check_drive_folder(folderid):
        if folderid:
                url='https://www.googleapis.com/drive/v3/files/'+str(folderid)
                header={'Authorization':'Bearer {}'.format(access_from_refresh),'Accept': 'application/json'}
                req=requests.get(url,headers=header)
                if req.status_code == 200:
                        return True
        return False

def check_folder_name(folder_name):
        url="https://www.googleapis.com/drive/v3/files"
        header={'Authorization':'Bearer {}'.format(access_from_refresh),'Accept': 'application/json'}
        parameters={'q':"name = '{}' and '".format(folder_name)+drive_folder(1)+"' in parents"}    
        req=requests.get(url,headers=header,params=parameters)
        data=json.loads(req.text)
        print(data)
        if not len(data['files'])==0:
                if data['files'][0]['name'] == str(folder_name):
                        return data['files'][0]['id']
        return False

def upload_file(path,name,size,mime,parentid):
        print('we are uploading ',)
        url='https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart'
        meta={'name':name,"parents": [parentid],"mimeType": mime}
        header={'Authorization': 'Bearer {}'.format(access_from_refresh),
                 #'Content-Type': 'multipart/related',
                 'Content-Length':str(size)
                }
        file = {'json':(None,json.dumps(meta),'application/json'),'file':open(path, 'rb')}
        req=requests.post(url,headers=header,files=file)
        print("request file upload multipart",req.text)
        print(req.headers)
        if req.status_code==200:
                return True
        return False
          

@app.route('/clear')
def clear_credentials():
    if 'username' in session:
      if os.path.exists(credential_path):
        os.remove(credential_path)
      return redirect(url_for('logged'))
    return "You are not logged in <br><a href = '/admin'></b>" + \
      "click here to log in</b></a>"

@app.route('/logout')
def logout():
    if 'username' in session:
       session.pop('username', None)
       return redirect(url_for('log'))
    return "You are not logged in <br><a href = '/admin'></b>" + \
      "click here to log in</b></a>"

@app.route('/logout_fb')
def log_out():
    if 'user_name' in session:
       session.pop('user_name', None)
       return redirect(url_for('index'))
    return "You are not logged in <br><a href = '/admin'></b>" + \
      "click here to log in</b></a>"

@app.route('/',defaults={'m':3})
@app.route('/<int:m>')
def index(m):
        messages=['You have Logged Facebook, You can upload.',
                  'I require email permission please click Log To Facebook',
                  'Error happened you cancelled log in',
                  'please enter reg id and chose files']
        if 'user_name' in session:
            return render_template('index.html',err=messages[0],user_fb=session['user_name'])
        elif m==1:
            return render_template('index.html',err=messages[1],user_fb="User")
        elif m==2:
            return render_template('index.html',err=messages[2],user_fb="User")
        else:
            return render_template('index.html',err=messages[3],user_fb="First Time, click Log to facebook please.")
        
def allowed_file(filename):
    ALLOWED_EXTENSIONS = set(['txt', 'doc', 'docx'])
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/submit',methods=['GET','POST'])
def submit():
   if request.method =='GET':
        message='please enter reg id and chose files'
        return render_template('response.html',error=message,files=None,notifys=None) 
   if request.method =='POST' and 'user_email' in session:
        reg_id= request.form['reg_id']
        if not (int(reg_id) >=4001 and int(reg_id) <=4549):#setting ranges for register values
                if not (int(reg_id)>=5001 and int(reg_id) <=5088):
                        if not (int(reg_id)>=71001 and int(reg_id)<=71017):
                                if not (int(reg_id)>=71101 and int(reg_id)<=71103):
                                    message='Wrong Register Id Please Review register'
                                    return render_template('response.html',error=message)
        files =request.files.getlist("file[]")
        name=session['user_name']
        email=session['user_email']
        client=create_client("assignment-submit")
        user_exist=check_user(client, reg_id)
        print("user exist ",user_exist)
        check_email=get_props(client,'email',email)
        print(check_email)
        if not user_exist and not check_email:
                print("add user",add_retry(client, reg_id,"not uploaded yet",name,email))
        else:
              if check_email:
                if not check_email['reg_id'] == int(reg_id):
                        true_id=check_email['reg_id']
                        message='this facebook account used another register id '+str(true_id)
                        return render_template('response.html',error=message)
              else:
                   message='this register id used by another facebook account'
                   return render_template('response.html',error=message) 
        if 'file[]' not in request.files:
            message='No file chosen'
            return render_template('response.html',error=message)
        print(files)
        if files[0].filename == '':
            message='No selected file'
            return render_template('response.html',error=message)
        user_props=get_props(client,'reg_id',int(reg_id))
        print(user_props['reg_id'],user_props['email'],"\n")
        print(reg_id,email,"\n")
        if not int(reg_id) == int(user_props['reg_id']) and not str(email) == str(user_props['email']):
                message="Every facebook account have one register id"
                return render_template('response.html',error=message)
        
        print(len(files))
        directory=upload+"\\"+reg_id
        files_test=[]
        not_accepted_fils=['file refused: ']
        accepted=['file accepted: ']
        files_saved=['file saved: ']
        notification=['duplicate save, change file named: ']
        for file in files:#test
            files_test.append(file and allowed_file(file.filename))
            if file and allowed_file(file.filename):
                accepted.append(file.filename)
            else:
                not_accepted_fils.append(file.filename)    
        if not False in files_test:
           try:
            os.mkdir(directory)
           except FileExistsError:
                pass
           check_auth()
           print("Folder is",check_folder_name(reg_id))
           if not check_folder_name(reg_id):#check if folder name exisit on cloud
                   user_drive_folder=create_folder(reg_id,drive_folder(1))
                   data=json.loads(user_drive_folder.text)
                   drive_id=data['id']
                   print("Create folder",data['id'])#here we should create folder with regid on cloud
                   client = create_client("assignment-submit")
                   print("update user",update_user(client, reg_id,'drive_folder_id',drive_id))
           else:
                   pass
                   #drive_sub_folder=check_folder_name(reg_id)#here if folder found we retain the id
                   #print(drive_sub_folder)
           for file in files:#actual save of files
            print('file name is',file.filename)
            if file and allowed_file(file.filename):#we should notify user of not saving same name files
                filename_cloud = str(reg_id)+"-"+secure_filename(file.filename).replace(" ","_")
                filename=secure_filename(file.filename).replace(" ","_")
                filedir = directory+"\\"+filename
                
                if not os.path.exists(filedir):
                  print('file saved ',filename) 
                  file.save(os.path.join(directory,filename))
                  files_saved.append(filename)
                  file_size=os.path.getsize(filedir)
                  check_auth()
                  print('upload status ',upload_file(filedir,filename_cloud,file_size,file.mimetype,check_folder_name(reg_id)))#here we save file to the folder created or found on cloud 
                else:
                  notification.append(filename)
           if len(notification)> 1:
                if len(files_saved)==0:
                  message='Submit error'
                  print(message)
                else:
                     message='Submit partial success'
                     print(message)
                return render_template('response.html',error=message,files=files_saved,notifys=notification)
           message='Submit success'
           print(message)
           return render_template('response.html',error=message,files=files_saved)
        message='NOt allowed file/files please upload .doc or .docs'
        print(message)
        return render_template('response.html',error=message,files=not_accepted_fils)
   else:
        message='please log to facebook'
        print(message)
        return render_template('response.html',error=message,files=None,notifys=None)
        

@app.route('/face')
def face_auth():
    url='https://www.facebook.com/v2.11/dialog/oauth?client_id=144059996221344&redirect_uri=http://127.0.0.1:8080/facecallback&auth_type=rerequest&scope=email'
    return redirect(url)

@app.route('/facecallback')
def face_call():
    auth_resp=dict(request.args)
    if not 'error' in auth_resp:
        print('code is: ',auth_resp['code'],"/n")
        url='https://graph.facebook.com/v2.11/oauth/access_token'
        params={'client_id':'144059996221344',
       'redirect_uri':'http://127.0.0.1:8080/facecallback',
       'client_secret':'a73d172ea4132d6c5f5b9a93a6a4866d',
       'code':auth_resp['code']}
        req=requests.get(url,params=params)
        data=json.loads(req.text)
        print('access token ',data["access_token"],' time ',data["expires_in"],'/n')
        url='https://graph.facebook.com/v2.11/me?fields=name,email&access_token='+data["access_token"]
        req=requests.get(url)
        data1=json.loads(req.text)
        print(data1)
        if 'email' in data1:
            user_fb=data1['name']
            email_fb=data1['email']
            session['user_name'] = user_fb
            session['user_email'] = email_fb
            return redirect(url_for('index',m=0))
        return redirect(url_for('index',m=1))
    else:
        return redirect(url_for('index',m=2))

if __name__=='__main__':
    app.run()
