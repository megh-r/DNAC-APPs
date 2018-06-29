#packages to be imported for the reliability report
import sys
import telnetlib
import time
import requests, base64, json, sys
import numpy as np
import pandas as pd


'''

ENTER YOUR DNAC INSTANCE CREDENTIALS BELOW


'''

username = 'username' # enter the username of the DNAC instance here
password = 'password' # enter the password of the DNAC instance here
ipAddress = 'ip address' # enter the ip address of the DNAC instance here
authCredentials = username+':'+password
b64Val = base64.b64encode(authCredentials.encode('UTF-8')).decode('utf-8')

try:
    r=requests.get('https://'+ ipAddress +'/api/system/v1/auth/login', headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json"}, verify=False)
    r.raise_for_status()
except requests.exceptions.Timeout as errt:
    print "Timeout Error:",errt
    sys.exit(1)
except requests.exceptions.ConnectionError as errc:
    print "Error Connecting:",errc
    sys.exit(1)
except requests.exceptions.HTTPError as errh:
    print "Http Error:",errh
    sys.exit(1)
except requests.exceptions.RequestException as err:
    print "Oops: Something Else",err
    sys.exit(1)

a=r.headers['Set-Cookie'].split(";")
b=a[0].split("=")
c=b[1]
cookie = {'X-JWT-ACCESS-TOKEN':c}

#initializing dataframes
df=pd.DataFrame()
df1=pd.DataFrame()
df2=pd.DataFrame()
a=['ACCESS','DISTRIBUTION']
try:
    r= requests.get('https://'+ ipAddress +'/api/v1/network-device',cookies=cookie,verify=False)
    r.raise_for_status()
except requests.exceptions.Timeout as errt:
    print "Timeout Error:",errt
    sys.exit(1)
except requests.exceptions.ConnectionError as errc:
    print "Error Connecting:",errc
    sys.exit(1)
except requests.exceptions.HTTPError as errh:
    print "Http Error:",errh
    sys.exit(1)
except requests.exceptions.RequestException as err:
    print "Oops: Something Else",err
    sys.exit(1)

#for more information about the request you can uncomment the following     
'''
print "Status code:"+ str(r.status_code)  
print "Encoding :" + str(r.encoding)
print "Content type:" + str(r.headers["Content-Type"]) 
'''
obj = json.loads(r.text)
for dic in obj['response']:
    for key,val in sorted(dic.items()):
        if key == 'role':
            role= val 
        if key == 'managementIpAddress':
            ip= val
        if key == 'series':
            series=val
    df = df.append({'Ip_address':ip, 'Role':role, 'Series':series}, ignore_index=True)


searchfor = ['witch', 'outer']
df = df[df.Series.str.contains('|'.join(searchfor))]
df=df.drop('Series', axis=1)

access=df[df['Role'] =='ACCESS']
access.reset_index(drop=True, inplace=True)
br=df[df['Role'] == 'BORDER ROUTER']
br.reset_index(drop=True, inplace=True )

col=['Border\Access']
for i in range(0,access.shape[0]):
    col.append(access.loc[i]['Ip_address'])
dff=br.copy(deep=True)
dff=br.drop('Role', axis=1)
dff.columns=['Border\Access']

for i in range(0,access.shape[0]):
    grade=[]
    tn = telnetlib.Telnet(access.loc[i]['Ip_address'])
    
    TELNET_PROMPT=">"
    ENABLE_PROMPT="#"
    TIMEOUT=5
    
    tn.write("\n")
    auth=pd.read_csv("auth.csv")
    acc=[]
    acc=auth.loc[auth['ip']==access.loc[i]['Ip_address']]
    un= str(acc.iloc[0]['un']) 
    pw= str(acc.iloc[0]['pw'])
    enpw =str(acc.iloc[0]['enpw'])

    tn.read_until("Username: ",2)
    tn.write(un + "\r\n")
    tn.read_until("Password: ",2)
    tn.write(pw + "\r\n")
    if enpw !='no':
        tn.read_until(TELNET_PROMPT, TIMEOUT)
        tn.write("enable" + "\r\n")
        tn.read_until("Password: ",5)
        tn.write(enpw+"\r\n")
    t= tn.read_until("failed",5)    
    try:
        t.index("% Authentication failed")
        for j in range(0,br.shape[0]):
            grade.append('ae,0')
    except:
        tn.read_until(ENABLE_PROMPT, TIMEOUT)
        tn.write("term len 0" + "\r\n")
        tn.read_until(ENABLE_PROMPT, TIMEOUT)

        for j in range(0,br.shape[0]):
            avgrtt=0
            successPercent=0
            tn.write("ping "+str(br.loc[j]['Ip_address'])+"\r\n")
            

            t=tn.read_until(ENABLE_PROMPT, 20)
            ten=t.split(" ")
            

            index_element = ten.index('ping')
            index_element = ten.index('percent')
            successPercent=ten[index_element-1]
            if successPercent !='0':
                index_element = ten.index('=')
            
                tt=ten[index_element+1].split('/')[1]
                avgrtt=tt
            
            else: 
                avgrtt='nr'
            grade.append(avgrtt+','+successPercent)
           

        tn.sock.close()



    dff[access.loc[i]['Ip_address']]=grade
        

dfff=dff.copy(deep=True)
dfff=dfff.set_index('Border\Access')
dfff.to_csv('border_access.csv')