import requests, base64, json, sys
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)#GET request with error handling 
#Enter your DNAC credentials here
username = 'username'
password = 'password'
ip = 'ipaddress'
b64Val = base64.b64encode((username+':'+password).encode('UTF-8')).decode('utf-8')
try:
    r=requests.get('https://'+ip+'/api/system/v1/auth/login', headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json"}, verify=False)
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

tg='https://'+ip+'/api/v1/host'
            
try:
    r= requests.get(tg,cookies=cookie,verify=False)
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
objh = json.loads(r.text)
print objh
with open('hosts.json', 'w') as outfile:
    json.dump(objh['response'], outfile)
outfile.close()
train = pd.DataFrame(objh['response'])
train.to_csv('hosts.csv')
del train

