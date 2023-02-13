import json
import os
import requests
from sys import stderr
from flask import Flask, request, jsonify
import random
import string
from ast import Pass
import paramiko
from paramiko import SSHClient
app = Flask(__name__)

# api_key = os.environ.get("API_KEY", "")
zep_url = "http://10.207.26.22:9995/"
zep_host = "10.207.26.22"
zep_username = "apps"
zep_pass = "apps247"
# if api_key == "":
#     print("api key is required", file=stderr)

# api_base_url = "https://api.stagingv3.microgen.id/query/api/v1/" + api_key

@app.route('/')
def hello_geek():
    return '<h1>Hello from Flask</h2>'


def login():
    url = "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/auth/login"
    email = "admin@sapujagad.id"
    password = "123123"
    form_data = {'email': email,'password': password}
    z = requests.post(url,json=form_data,verify=False)
    return z.json()['token']

def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

@app.post("/api/addrole")
def createuser():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    request_data = request.get_json()
    nilai = int(request_data['total'])
    bearer_token = login()
    urlget= "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/ZeppelinUser/count"
    z = requests.get(urlget,headers={"Authorization": "Bearer %s" %bearer_token},verify=False)
    count=z.json()['count']
    url = "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/ZeppelinUser"
    if count > nilai or count == nilai:
        totalrole = 0
    else:
        totalrole = nilai - count 
    for i in range(0, totalrole):
        i = requests.post(url,headers={"Authorization": "Bearer %s" %bearer_token},json={"username":get_random_string(8),"password":get_random_string(9),"role":get_random_string(10)},verify=False)
    return jsonify({"msg": "succes"}), 200

def create_folder(email):
    hostname = '10.207.26.22'
    port = 8080
    username = "apps"
    password = "apps247"    
    command = "hadoop fs -mkdir /usersapujagad/%s && hdfs dfs -chmod 777 /usersapujagad/%s" % (email, email)
    client = SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, password=password)
    # command = "ls \"
    stdin, stdout, stderr = client.exec_command(command)

    z=str(stdout.read())
    # print(z)
    return z

def getuserzeppelinmicrogen(bearer_token):
    bearer_token = bearer_token
    print(bearer_token)
    urlget= "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/ZeppelinUser"
    z = requests.get(urlget,headers={"Authorization": "Bearer %s" %bearer_token},verify=False)
    x = json.dumps(z.json())
    a_list = json.loads(x)
    filtered_list = [
        dictionary for dictionary in a_list
        if len(dictionary['Users']) == 0 and len(dictionary['UserGroup']) == 0
    ]
    return(filtered_list[0]['_id'])

@app.post("/api/register")
def registeruser():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
    request_data = request.get_json()
    firstName = request_data['firstName']
    lastName = request_data['lastName']
    email = request_data['email']
    password = request_data['password']
    bearer_token = str(request_data['token'])
    usergroup = request_data['UserGroup']
    zeppelinuser = str(getuserzeppelinmicrogen(bearer_token))
    try :
        jsonr = {"firstName":firstName,"lastName":lastName,"email":email,"password":password,"isEmailVerified":True,'role':['authenticated'],'zeppelinUser':[zeppelinuser],'UserGroup':usergroup}
        url = "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/Users"
        z = requests.post(url,headers={"Authorization": "Bearer %s" %bearer_token},json=jsonr,verify=False)
        create_folder(email)
        if str(z) == "<Response [400]>":
            return z.json(),400
        else:
            return z.json(),200
    except requests.exceptions.RequestException as e:
        Pass
        
listusers = []
def listuser():
    try:
        bearer_token = login()
        url = "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/ZeppelinUser"
        z = requests.get(url,headers={"Authorization": "Bearer %s" %bearer_token},verify=False)
        a = z.json()
        n = len(a)
        for i in range(0, n):
            listusers.append(a[i]['username']+" = "+a[i]['password']+','+a[i]['role']+'\n')
        return a
    except Exception as e:
        print(e)
        return 'error'
listroles = [] 
def listrole():
    try:
        bearer_token = login()
        url = "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/ZeppelinUser"
        z = requests.get(url,headers={"Authorization": "Bearer %s" %bearer_token},verify=False)
        a = z.json()
        n = len(a)
        
        for i in range(0, n):
            listroles.append(a[i]['role']+" = *\n")
        return a
    except Exception as e:
        print(e)
        return 'error'
    
@app.post("/api/createalluser")
def createalluser():
    try:
        listuser()
        listrole()
        lists = {}
        lists["user"] = ''.join(listusers)
        lists["roles"] = ''.join(listroles)
        listusers.clear()
        listroles.clear()
        url = 'http://10.10.65.1:8080/api/v1/clusters/sapujagad'
        username = 'sapujagad'
        password = 'kayangan'
        zzz = [{"Clusters":{"desired_config":[{"type":"zeppelin-shiro-ini","properties":{"shiro_ini_content":"\n[users]\n# List of users with their password allowed to access Zeppelin.\n# To use a different strategy (LDAP / Database / ...) check the shiro doc at http://shiro.apache.org/configuration.html#Configuration-INISections\n"+lists["user"]+"\n\n\n# Sample LDAP configuration, for user Authentication, currently tested for single Realm\n[main]\n### A sample for configuring Active Directory Realm\n#activeDirectoryRealm = org.apache.zeppelin.realm.ActiveDirectoryGroupRealm\n#activeDirectoryRealm.systemUsername = userNameA\n\n#use either systemPassword or hadoopSecurityCredentialPath, more details in http://zeppelin.apache.org/docs/latest/security/shiroauthentication.html\n#activeDirectoryRealm.systemPassword = passwordA\n#activeDirectoryRealm.hadoopSecurityCredentialPath = jceks://file/user/zeppelin/zeppelin.jceks\n#activeDirectoryRealm.searchBase = CN=Users,DC=SOME_GROUP,DC=COMPANY,DC=COM\n#activeDirectoryRealm.url = ldap://ldap.test.com:389\n#activeDirectoryRealm.groupRolesMap = \"CN=admin,OU=groups,DC=SOME_GROUP,DC=COMPANY,DC=COM\":\"admin\",\"CN=finance,OU=groups,DC=SOME_GROUP,DC=COMPANY,DC=COM\":\"finance\",\"CN=hr,OU=groups,DC=SOME_GROUP,DC=COMPANY,DC=COM\":\"hr\"\n#activeDirectoryRealm.authorizationCachingEnabled = false\n\n### A sample for configuring LDAP Directory Realm\n#ldapRealm = org.apache.zeppelin.realm.LdapGroupRealm\n## search base for ldap groups (only relevant for LdapGroupRealm):\n#ldapRealm.contextFactory.environment[ldap.searchBase] = dc=COMPANY,dc=COM\n#ldapRealm.contextFactory.url = ldap://ldap.test.com:389\n#ldapRealm.userDnTemplate = uid={0},ou=Users,dc=COMPANY,dc=COM\n#ldapRealm.contextFactory.authenticationMechanism = SIMPLE\n\n### A sample PAM configuration\n#pamRealm=org.apache.zeppelin.realm.PamRealm\n#pamRealm.service=sshd\n\n## To be commented out when not using [user] block / paintext\n#passwordMatcher = org.apache.shiro.authc.credential.PasswordMatcher\n#iniRealm.credentialsMatcher = $passwordMatcher\n\nsessionManager = org.apache.shiro.web.session.mgt.DefaultWebSessionManager\n### If caching of user is required then uncomment below lines\ncacheManager = org.apache.shiro.cache.MemoryConstrainedCacheManager\nsecurityManager.cacheManager = $cacheManager\n\ncookie = org.apache.shiro.web.servlet.SimpleCookie\ncookie.name = JSESSIONID\n#Uncomment the line below when running Zeppelin-Server in HTTPS mode\n#cookie.secure = true\ncookie.httpOnly = true\nsessionManager.sessionIdCookie = $cookie\n\nsecurityManager.sessionManager = $sessionManager\n# 86,400,000 milliseconds = 24 hour\nsecurityManager.sessionManager.globalSessionTimeout = 86400000\nshiro.loginUrl = /api/login\n\n[roles]\n"+lists["roles"]+"\n\n[urls]\n# This section is used for url-based security.\n# You can secure interpreter, configuration and credential information by urls. Comment or uncomment the below urls that you want to hide.\n# anon means the access is anonymous.\n# authc means Form based Auth Security\n# To enfore security, comment the line below and uncomment the next one\n/api/version = anon\n#/api/interpreter/** = authc, roles[admin]\n#/api/configurations/** = authc, roles[admin]\n#/api/credential/** = authc, roles[admin]\n#/** = anon\n/** = authc"},"service_config_version_note":""}]}}]
        response = requests.put(url, auth=(username, password),data = json.dumps(zzz),verify=False)
        return response.json()
    except requests.exceptions.RequestException as e:
        Pass
        
def loginzeppelin(username1,password1):
    hostname = zep_host
    port = 9995
    username = zep_username 
    password = zep_pass
    
    command = "curl -i --data 'userName=%s&password=%s' -X POST %s/api/login" % (str(username1) , str(password1), str(zep_url))
    
    client = SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname, username=username, password=password)
    stdin, stdout, stderr = client.exec_command(command)
    z=stdout.read()

    x = str(z)
    nu = x.find('Content-Type: application/json')
    g = int(nu)-162
    u = int(g)+47
    s = x[g:u]
    my_dict = {}
    my_dict['Set-Cookie']= s
    return my_dict['Set-Cookie']

listid = []
def listusernotebook(username,password):
    y = loginzeppelin(username,password)
    x = y.split("=")
    url = zep_url+'/api/notebook'
    cookies = {str(x[0]): str(x[1])}
    r = requests.get(url, cookies=cookies,verify=False)
    a = r.json()['body']
    n = len(a)
    for i in range(0, n):
        listid.append(a[i]['id'])
    return y

def deletenotebook(username, password):
    y = listusernotebook(username, password)
    x = y.split("=")
    cookies = {str(x[0]): str(x[1])}
    a = len(listid)
    for i in range(0, a):
        url = zep_url+'/api/notebook/'+listid[i]+''
        r = requests.delete(url, cookies=cookies,verify=False)
    return "succes"


@app.delete("/api/delete/<id>")
def deleteallnotebookbyid(id):
    bearer_token = login()
    url = "https://database-query.v3.microgen.sm.co.id/api/v1/446ed6be-d3df-42dd-ace4-8693ccf0c647/ZeppelinUser/"+str(id)+""
    z = requests.get(url,headers={"Authorization": "Bearer %s" %bearer_token},verify=False)
    
    deletenotebook(str(z.json()['username']),str(z.json()['password']))
    return z.json()

if __name__ == "__main__":
    app.run(debug=True)
