from django.shortcuts import render
import requests, base64, json, sys, time, collections, ast
import pandas as pd
from django.shortcuts import render, render_to_response, redirect
from django.template import RequestContext
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
import urllib3
from xml.dom import minidom
from apscheduler.schedulers.background import BackgroundScheduler

sched = BackgroundScheduler()
sched.start()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ise_un = 'Username of the ise instance (ersadmin)'
ise_pw = 'Password of the ise instance (ersadmin)'
ise_ip = 'Ip address of the ise instance'
dnac_un = 'Username of the dnac instance'
dnac_pw = 'Password of the ise instance'
dnac_ip = 'Ip address of the dnac instance'


def start_priority(user,start,end):

    # authenticate to make API calls to DNAC
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://'+dnac_ip+'/api/system/v1/auth/login',
                         headers={"Authorization": "Basic %s" % b64Val, "Content-Type": "application/json"},
                         verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    a = r.headers['Set-Cookie'].split(";")
    b = a[0].split("=")
    c = b[1]
    cookie = {'X-JWT-ACCESS-TOKEN': c}
    print "strated the cron job for authentication at " + start.split(':')[0] + ":" + start.split(':')[1]
    # check if there is auth rule for SAP_user
    url = "https://"+ise_ip+":9060/ers/config/authorizationrule/name/SAP_User"
    try:
        b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
        r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                       'Content-Type': "application/json", }, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print ""
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    if not r.text:
            # getting Vlan ID
        tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/Segment?name=100_69_0_0-ABCD"
        print tg
        try:
            r = requests.get(tg, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        vlanId = str(objh['response'][0]['vlanId'])
        print vlanId

        # creating the auth rule for SAP_user
        data = '{"AuthorizationRule": {"id": "SAP_User","name": "SAP_User","rank": 0,"enabled": true,"condition":' \
               ' {"conditionType": "AttributeCondition","isNot": false,"operand": "EQUALS","attributeName": "User-Name",' \
               '"value": "' + user.split('|')[0] + '","dictionaryName": "Radius"},"permissions": {"standardList": ' \
                '["vlan_' + vlanId + '"],"securityGroupList": ["SGT_SAPUser"] } } }'

        url = "https://"+ise_ip+":9060/ers/config/authorizationrule"
        print data
        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
        '''
        #Get the host server and host mac for coa
        tg = 'https://'+ise_ip+'/admin/API/mnt/Session/UserName/'+user.split("|")[0]
    
        b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
        headers = {'Authorization': 'Basic %s' % b64Val, }
        try:
            r = requests.get(tg, headers=headers, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
    
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        doc = minidom.parseString(r.text)
        mac = doc.getElementsByTagName('calling_station_id')[0].firstChild.nodeValue
        server = doc.getElementsByTagName('acs_server')[0].firstChild.nodeValue
    
    
        #COA 
        tg = 'https://'+ise_ip+'/admin/API/mnt/CoA/Reauth/' + server + '/' + mac + '/1'
    
        b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
        headers = {'Authorization': 'Basic %s' % b64Val, }
    
        try:
            r = requests.get(tg, headers=headers, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
    
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
    
        '''


def end_priority(user,start,end):

    # authenticate to make API calls to DNAC
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://'+dnac_ip+'/api/system/v1/auth/login',
                         headers={"Authorization": "Basic %s" % b64Val, "Content-Type": "application/json"},
                         verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    a = r.headers['Set-Cookie'].split(";")
    b = a[0].split("=")
    c = b[1]
    cookie = {'X-JWT-ACCESS-TOKEN': c}
    print "stated the cron job for authentication at " + end.split(':')[0] + ":" + end.split(':')[1]
    # check if there is auth rule for SAP_user
    url = "https://"+ise_ip+":9060/ers/config/authorizationrule/name/SAP_User"
    try:
        b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
        r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                       'Content-Type': "application/json", }, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print ""
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    if r.text:
        objh = json.loads(r.text)
        auth_id = objh['AuthorizationRule']['id']
        print auth_id
        # delete auth rule
        url = "https://"+ise_ip+":9060/ers/config/authorizationrule/" + auth_id
        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.delete(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                              'Content-Type': "application/json", }, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print ""
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
    '''
    #Get the host server and host mac for coa
    tg = 'https://'+ise_ip+'/admin/API/mnt/Session/UserName/'+user.split("|")[0]

    b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val, }
    try:
        r = requests.get(tg, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:

        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    doc = minidom.parseString(r.text)
    mac = doc.getElementsByTagName('calling_station_id')[0].firstChild.nodeValue
    server = doc.getElementsByTagName('acs_server')[0].firstChild.nodeValue


    #COA 
    tg = 'https://'+ise_ip+'/admin/API/mnt/CoA/Reauth/' + server + '/' + mac + '/1'

    b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val, }

    try:
        r = requests.get(tg, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:

        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    '''


def index(request):
    # check if SGT there and if not create
    url = "https://"+ise_ip+":9060/ers/config/sgt/name/SGT_SAP"

    try:
        b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
        r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                       'Content-Type': "application/json", }, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        # If not found create it

        # creating the sgt for SAP
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "SGT_SAP",    "description" : "SAP_SGT for priority of' \
               ' traffic",    "value" : -1  } }'
        print data

        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)

        # creating the sgt for ABCD
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "ABCD_IT",    "description" : "SGT for IT group in OU ABCD"' \
               ',    "value" : -1  } }'
        print data

        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)

        # creating the sgt for ENT
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "SGT_ENT",    "description" : "SGT for Enterprise ' \
               'Functionalities",    "value" : -1  } }'
        print data

        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        # creating the sgt for Social Media
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "SGT_SM",    "description" : "SGT for Social Media' \
               ' Functionalities",    "value" : -1  } }'
        print data

        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    # authenticate to make API calls to DNAC
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://'+dnac_ip+'/api/system/v1/auth/login',
                         headers={"Authorization": "Basic %s" % b64Val, "Content-Type": "application/json"},
                         verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    a = r.headers['Set-Cookie'].split(";")
    b = a[0].split("=")
    c = b[1]
    cookie = {'X-JWT-ACCESS-TOKEN': c}
    # check if VN there and if scalable group associated to it
    tg = 'https://'+dnac_ip+'/api/v2/data/customer-facing-service/virtualnetworkcontext?name=ABCD'
    print "checking the vn"
    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    objh = json.loads(r.text)
    if objh['response']:
        print "The VN is there"
    else:
        # getting the details for the DNS and DHCP servers
        tg = "https://"+dnac_ip+"/api/v1/commonsetting/global/-1"

        try:
            r = requests.get(tg, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        for obj in objh["response"]:
            if obj["key"] == "dns.server":
                dns_server = obj["value"][0]["primaryIpAddress"]
                print dns_server
            if obj["key"] == "dhcp.server":
                dhcp_server = obj["value"][0]
                print dhcp_server

        # check the scalable group
        tg = 'https://'+dnac_ip+'/api/v2/data/customer-facing-service/scalablegroup?name=ABCD_IT'
        try:
            r = requests.get(tg, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        if objh['response']:
            objh = json.loads(r.text)
            stringsg = str(objh["response"][0]["id"])
            # create a vn
            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/virtualnetworkcontext/"
            headers = {'Content-Type': 'application/json', }
            data = '[{"name":"ABCD","virtualNetworkContextType":"ISOLATED","scalableGroup": ' \
                   '[{"idRef":"' + stringsg + '"}]}]'
            print data
            try:
                r = requests.post(tg, data=data, headers=headers, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            ipam = pd.read_csv("ipam_file.csv")

            info = ipam.loc[ipam["project_name"] == 'ABCD'].to_string(header=False, index=False,
                                                                     index_names=False).split('  ')
            print info
            # print "the infomation is Project name: " + str(info[0]) + " Ip address: " + str(info[1]) + str(
            #   info[2]) + " Gateways: " + str(info[3])

            # create the ip pool
            ip_name = "ip_ABCD"
            # print ip_name

            tg = "https://"+dnac_ip+"/api/v2/ippool"
            headers = {'Content-Type': 'application/json', }
            data = '{"ipPoolName":"' + ip_name + '","ipPoolCidr":"' + str(info[1]) + str(
                info[2]) + '","gateways":["' + str(
                info[3]) + '"],"dhcpServerIps":["' + dhcp_server + '"],"dnsServerIps":["' + dns_server + '"]' \
                                                                                            ',"overlapping":false}'
            try:
                r = requests.post(tg, data=data, headers=headers, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            time.sleep(40)

            # associating vn to ip pool (getting the information)
            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/VirtualNetwork?name=ABCD-FABRIC1"

            try:
                r = requests.get(tg, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            # print objh
            project = objh["response"][0]
            project_id = str(project["id"])
            instanceId = str(project["instanceId"])
            authEntityId = str(project["authEntityId"])
            deployPending = str(project["deployPending"])
            instanceVersion = str(project["instanceVersion"])
            deployed = str(json.dumps(project["deployed"]))
            isSeeded = str(json.dumps(project["isSeeded"]))
            isStale = str(json.dumps(project["isStale"]))
            name = str(project["name"])
            namespace = str(project["namespace"])
            provisioningState = str(project["provisioningState"])
            resourceVersion = str(project["resourceVersion"])
            project_type = str(project["type"])
            CCI = str(project["cfsChangeInfo"])
            isDefault = str(json.dumps(project["isDefault"]))
            isInfra = str(json.dumps(project["isInfra"]))
            l3Instance = str(project["l3Instance"])
            displayName = str(project["displayName"])
            authEntityClass = str(project["authEntityClass"])
            virtualNetworkContextId = str(project["virtualNetworkContextId"])
            # print project_id + instanceId + authEntityId +deployPending
            # print instanceVersion+deployed+isSeeded+isStale
            # print name + namespace + provisioningState+resourceVersion
            # print project_type+CCI+isDefault+isInfra+l3Instance+virtualNetworkContextId

            if not CCI:
                cfsChangeInfo = ''
            else:
                cfsChangeInfo = " ".join(CCI)

            # getting the ip id
            tg = "https://"+dnac_ip+"/api/v2/ippool?ipPoolName=" + ip_name
            try:
                r = requests.get(tg, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)

            ipPoolId = objh["response"][0]["id"]
            ip = objh["response"][0]["ipPoolCidr"].split('/')[0]
            # print ip
            ip_name = ip.replace('.', '_')
            # print ip_name
            # associating the ip pool to the VN
            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/VirtualNetwork"
            headers = {'Content-Type': 'application/json', }
            data = '[{"fabricOverride": [],"segment": [{"type": "Segment","name": "' + ip_name + '-ABCD",' \
                    '"trafficType": "DATA","ipPoolId": "' + ipPoolId + '","isFloodAndLearn": true,' \
                    '"isApProvisioning": false,"isDefaultEnterprise": false,"connectivityDomain": {"idRef":' \
                    ' "' + namespace + '"} }],"id": "' + project_id + '","name": "' + name + '","type": "' +\
                   project_type + '","isDefault": ' + isDefault + ',"isInfra": ' + isInfra + ',"l3Instance": '\
                   + l3Instance + ',"namespace": "' + namespace + '","instanceId": ' + instanceId + ',"authEntityId":' \
                    ' ' + authEntityId + ',"displayName": "' + displayName + '","authEntityClass": ' + authEntityClass\
                   + ',"deployPending": "' + deployPending + '","instanceVersion": ' + instanceVersion + ',"deployed":' \
                    ' ' + deployed + ',"isStale": ' + isStale + ',"provisioningState": "' + provisioningState + '",' \
                    '"cfsChangeInfo": ' + cfsChangeInfo + ',"virtualNetworkContextId": "' + virtualNetworkContextId +\
                   '","resourceVersion": ' + resourceVersion + '}]'
            try:
                r = requests.put(tg, data=data, headers=headers, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)

            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            headers = {'Authorization': 'Basic %s' % b64Val,
                       'Accept': "application/json",
                       'Content-Type': "application/json", }
            time.sleep(10)
            # getting Vlan ID
            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/Segment?name=" + ip_name + "-ABCD"
            print tg
            try:
                r = requests.get(tg, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            vlanId = str(objh['response'][0]['vlanId'])
            print vlanId

            # create new authorization profile

            url = 'https://'+ise_ip+':9060/ers/config/authorizationprofile/'
            data = '{"AuthorizationProfile": {"id": "id","name": "vlan_' + vlanId + '","description":' \
                ' "vlan for ABCD","accessType": "ACCESS_ACCEPT","authzProfileType": "SWITCH",' \
                '"vlan": {"nameID": "' + vlanId + '","tagID": 1},"trackMovement": false,"serviceTemplate":' \
                ' false,"easywiredSessionCandidate": false,"voiceDomainPermission": false,"neat": false,' \
                                                  '"webAuth": false}}'
            print data
            try:
                r = requests.post(url, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)

            # creating authorization rule for all
            url = "https://"+ise_ip+":9060/ers/config/authorizationrule"
            data = '{"AuthorizationRule": {"id": "ABCD_IT","name": "ABCD_IT","rank": 0,"enabled": true,' \
                   '"condition": {"conditionType": "AttributeCondition","isNot": false,"operand": "EQUALS",' \
                   '"attributeName": "ExternalGroups","value": "ciscotest.com/ABCD/ABCD_IT","dictionaryName":' \
                   ' "DNAC"},"permissions": {"standardList": ["vlan_' + vlanId + '"],"securityGroupList": ' \
                    '["ABCD_IT"] } } }'
            print data
            try:
                r = requests.post(url, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            # associate Ip to all the three SGTs
            #associate Ip for ENT
            #first get the SGT id of the ENT
            url = "https://"+ise_ip+":9060/ers/config/sgt/name/SGT_ENT"

            try:
                b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
                r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                               'Content-Type': "application/json", }, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            print objh
            sgt_id_ent = objh['Sgt']['id']
            #creating the mapping
            url = "https://"+ise_ip+":9060/ers/config/sgmapping"
            data = '{"SGMapping" : {"name" : "100.21.0.1/32","sgt" : "'+sgt_id_ent+'", "deployTo" : "1",' \
                    '"deployType" : "ALL","hostIp" : "100.21.0.1/32"} }'
            print data
            try:
                r = requests.post(url, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            # first get the SGT id of the SM
            url = "https://"+ise_ip+":9060/ers/config/sgt/name/SGT_SM"

            try:
                b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
                r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                               'Content-Type': "application/json", }, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            sgt_id_sm = objh['Sgt']['id']
            # creating the mapping
            url = "https://"+ise_ip+":9060/ers/config/sgmapping"
            data = '{"SGMapping" : {"name" : "100.21.0.2/32","sgt" : "' + sgt_id_sm + '", "deployTo" : "1",' \
                    '"deployType" : "ALL","hostIp" : "100.21.0.2/32"} }'
            print data
            try:
                r = requests.post(url, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)

            # first get the SGT id of the SAP
            url = "https://"+ise_ip+":9060/ers/config/sgt/name/SGT_SAP"

            try:
                b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
                r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                               'Content-Type': "application/json", }, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            sgt_id_sap = objh['Sgt']['id']
            # creating the mapping
            url = "https://"+ise_ip+":9060/ers/config/sgmapping"
            data = '{"SGMapping" : {"name" : "100.21.0.3/32","sgt" : "' + sgt_id_sap + '", "deployTo" : "1",' \
                    '"deployType" : "ALL","hostIp" : "100.21.0.3/32"} }'
            print data
            try:
                r = requests.post(url, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)

            # first get the SG id of the ABCD_IT
            url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=ABCD_IT"

            try:
                r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            sg_id_abcd = objh['response'][0]['id']

            # first get the SG id of the ENt
            url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_ENT"

            try:
                r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            sg_id_ent = objh['response'][0]['id']

            # first get the SG id of the sap
            url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_SAP"

            try:
                r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            sg_id_sap = objh['response'][0]['id']

            # first get the SG id of the SM
            url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_SM"

            try:
                r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:
                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
            objh = json.loads(r.text)
            sg_id_sm = objh['response'][0]['id']

            #create the contract for all in ABCD
            denyId='e36d49de-3004-41a0-a53b-a3959de71513'
            policyScope='2827e5bf-d291-3d54-aeda-3e21b29a9d5d'
            permitId= 'c80326bb-6649-45f4-9e47-5ac6724e03c6'

            #the policy administration for abcd_it to ent and sm permit


            url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/policy/access/"
            headers = {'Content-Type': 'application/json', }
            data = '[{"name":"ABCD_IT_Permit","description":"the groups that ABCD_IT is permited to access",' \
                   '"priority":65535,"contract":{"idRef":"'+permitId+'"},"producer":{"scalableGroup":' \
                    '[{"idRef":"'+sg_id_ent+'"},{"idRef":"'+sg_id_sm+'"}]},"consumer":{"scalableGroup":' \
                    '[{"idRef":"'+sg_id_abcd+'"}]},"isEnabled":true,"policyScope":"'+policyScope+'"}]'
            print data
            try:
                r = requests.post(url, cookies=cookie, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)

            #the policy administration for abcd_it to sap (deny)
            url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/policy/access/"
            data = '[{"name":"ABCD_IT_Deny","description":"the groups that ABCD_IT is denied access to","priority":' \
                   '65535,"contract":{"idRef":"'+denyId+'"},"producer":{"scalableGroup":[{"idRef":"'+sg_id_sap+'"}]}' \
                    ',"consumer":{"scalableGroup":[{"idRef":"'+sg_id_abcd+'"}]},"isEnabled":true,"policyScope":"'\
                   +policyScope+'"}]'
            print data
            try:
                r = requests.post(url, cookies=cookie, headers=headers, data=data, verify=False)
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print "Timeout Error:", errt
                sys.exit(1)
            except requests.exceptions.ConnectionError as errc:
                print "Error Connecting:", errc
                sys.exit(1)
            except requests.exceptions.HTTPError as errh:

                print "Http Error:", errh
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print "Oops: Something Else", err
                sys.exit(1)
    '''
    
    #Get the users and pass to the front end

    tg = 'https://'+ise_ip+'/admin/API/mnt/Session/ActiveList'

    b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val, }
    try:
        r = requests.get(tg, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:

        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    doc = minidom.parseString(r.text)
    activeList = doc.getElementsByTagName('activeList')
    #print activeList
    itemlist = activeList[0].getAttribute('noOfActiveSession')
    #print itemlist
    '''
    users=['jackie|ACBD_IT']
    '''
    hosts = []
    for activeSession in activeList:
        eachhost = {}
        eachhost['mac'] = str(activeSession.attributes['calling_station_id'].value)
        eachhost['server'] = str(activeSession.attributes['server'].value)
        hosts.append(eachhost)
    print hosts
    #get the username of the user
    for host in hosts:
        tg = 'https://'+ise_ip+'/admin/API/mnt/Session/MACAddress/0A:0B:0C:0D:0E:0F'
    
        b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
        headers = {'Authorization': 'Basic %s' % b64Val, }
        try:
            r = requests.get(tg, headers=headers, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
    
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        doc = minidom.parseString(r.text)
        username = doc.getElementsByTagName('user_name')[0].firstChild.nodeValue
        print username
        group = activeList[0].getAttribute('identity_group')[0].firstChild.nodeValue
        print group
        users.append(username + '|' + group)
    '''
    return render(request, 'index.html',{'users': users})


def permit(request):
    abc = sched.get_jobs()
    for job in abc:
        sched.remove_job(job.id)
    response_data = {}
    application = request.GET.get('application',None)
    print application
    user = request.GET.get('user',None)
    print user
    trigger = request.GET.get('trigger',None)
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://'+dnac_ip+'/api/system/v1/auth/login',
                         headers={"Authorization": "Basic %s" % b64Val, "Content-Type": "application/json"},
                         verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    a = r.headers['Set-Cookie'].split(";")
    b = a[0].split("=")
    c = b[1]
    cookie = {'X-JWT-ACCESS-TOKEN': c}
    # check if sgt is already there otherwise create
    url = "https://"+ise_ip+":9060/ers/config/sgt/name/SGT_SAPUser"
    try:
        b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
        r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                       'Content-Type': "application/json", }, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        # creating the sgt for SAP_user
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "SGT_SAPUser",    "description" : "SAP user sgt for priority ' \
               'of traffic",    "value" : -1  } }'
        print data
        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)

        # Creating the Policy admin
        # first get the SG id of the ENt
        url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_ENT"

        try:
            r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        sg_id_ent = objh['response'][0]['id']

        # first get the SG id of the sap
        url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_SAP"

        try:
            r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        sg_id_sap = objh['response'][0]['id']

        # first get the SG id of the SM
        url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_SM"

        try:
            r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        sg_id_sm = objh['response'][0]['id']
        # first get the SG id of the SAPUser
        url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=SGT_SAPUser"

        try:
            r = requests.get(url, headers={'Content-Type': "application/json", }, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        sg_id_sapuser = objh['response'][0]['id']

        # create the contract for all in ABCD
        denyId = 'e36d49de-3004-41a0-a53b-a3959de71513'
        policyScope = '2827e5bf-d291-3d54-aeda-3e21b29a9d5d'
        permitId = 'c80326bb-6649-45f4-9e47-5ac6724e03c6'

        # the policy administration for sap user to sap (permit)
        url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/policy/access/"
        data = '[{"name":"ABCD_IT_Permit","description":"the groups that Sap user is permitted access to",' \
               '"priority":65535,"contract":{"idRef":"' + permitId + '"},"producer":{"scalableGroup":' \
                '[{"idRef":"' + sg_id_sap + '"},{"idRef":"' + sg_id_ent + '"}' \
                ']},"consumer":{"scalableGroup":[{"idRef":"' + sg_id_sapuser + '"}]},' \
                '"isEnabled":true,"policyScope":"' + policyScope + '"}]'
        headers = {'Content-Type': 'application/json', }
        print data
        try:
            r = requests.post(url, cookies=cookie, headers=headers, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)

        # the policy administration for sap_user to ent and sm deny

        url = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/policy/access/"
        headers = {'Content-Type': 'application/json', }
        data = '[{"name":"SAP_User_Deny","description":"the groups that SAP_User is denied access to","priority"' \
               ':65535,"contract":{"idRef":"' + denyId + '"},"producer":{"scalableGroup":[{"idRef":"' + sg_id_sm +\
               '"}]},"consumer":{"scalableGroup":[{"idRef":"' + sg_id_sapuser + '"}]},' \
                                               '"isEnabled":true,"policyScope":"' + policyScope + '"}]'
        print data
        try:
            r = requests.post(url, cookies=cookie, headers=headers, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    if json.loads(trigger)['name'] == 'time':
        print "reached time"
        start = json.loads(trigger)['start']
        print start
        end = json.loads(trigger)['end']
        print type(end)
        print end.split(':')[0]
        sched.add_job(start_priority, 'cron', [user, start, end], day_of_week='*', hour=start.split(':')[0],
                      minute=start.split(':')[1], id='time_trigger_start')
        sched.add_job(end_priority,'cron', [user, start, end], day_of_week='*', hour=end.split(':')[0],
                      minute=end.split(':')[1], id='time_trigger_end')
    else:
        print "Email Trigger"
        # getting Vlan ID
        tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/Segment?name=100_69_0_0-ABCD"
        print tg
        try:
            r = requests.get(tg, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        objh = json.loads(r.text)
        vlanId = str(objh['response'][0]['vlanId'])
        print vlanId

        # creating the auth rule for SAP_user
        data = '{"AuthorizationRule": {"id": "SAP_User","name": "SAP_User","rank": 0,"enabled": true,"condition":' \
               ' {"conditionType": "AttributeCondition","isNot": false,"operand": "EQUALS","attributeName": "User-Name",' \
               '"value": "' + user.split('|')[0] + '","dictionaryName": "Radius"},"permissions": {"standardList": ' \
                                                   '["vlan_' + vlanId + '"],"securityGroupList": ["SGT_SAPUser"] } } }'

        url = "https://"+ise_ip+":9060/ers/config/authorizationrule"
        print data
        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                            'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        '''
        #Get the host server and host mac for coa
        tg = 'https://'+ise_ip+'/admin/API/mnt/Session/UserName/'+user.split("|")[0]

        b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
        headers = {'Authorization': 'Basic %s' % b64Val, }
        try:
            r = requests.get(tg, headers=headers, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
        doc = minidom.parseString(r.text)
        mac = doc.getElementsByTagName('calling_station_id')[0].firstChild.nodeValue
        server = doc.getElementsByTagName('acs_server')[0].firstChild.nodeValue


        #COA 
        tg = 'https://'+ise_ip+'/admin/API/mnt/CoA/Reauth/' + server + '/' + mac + '/1'

        b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
        headers = {'Authorization': 'Basic %s' % b64Val, }

        try:
            r = requests.get(tg, headers=headers, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:

            print "Http Error:", errh
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)

        '''

    # project=json.loads(project)
    # print application + user + trigger
    response_data['msg'] = "Dynamic priority has been given to user "+user.split("|")[0] + " of group "+ user.split("|")[1] + " for SAP"
    return HttpResponse(json.dumps(response_data), content_type="application/json")


def revoke(request):
    abc = sched.get_jobs()
    for job in abc:
        sched.remove_job(job.id)
    response_data = {}
    application = request.GET.get('application',None)
    print application
    user = request.GET.get('user',None)
    print user
    trigger = request.GET.get('trigger',None)

    # check if there is auth rule for SAP_user
    url = "https://"+ise_ip+":9060/ers/config/authorizationrule/name/SAP_User"
    try:
        b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
        r = requests.get(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                        'Content-Type': "application/json", }, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        print ""
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    if r.text:
        objh=json.loads(r.text)
        auth_id= objh['AuthorizationRule']['id']
        print auth_id
        #delete auth rule
        url = "https://"+ise_ip+":9060/ers/config/authorizationrule/"+auth_id
        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.delete(url, headers={'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json",
                                           'Content-Type': "application/json", }, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print "Timeout Error:", errt
            sys.exit(1)
        except requests.exceptions.ConnectionError as errc:
            print "Error Connecting:", errc
            sys.exit(1)
        except requests.exceptions.HTTPError as errh:
            print ""
        except requests.exceptions.RequestException as err:
            print "Oops: Something Else", err
            sys.exit(1)
    '''
    #Get the host server and host mac for coa
    tg = 'https://'+ise_ip+'/admin/API/mnt/Session/UserName/'+user.split("|")[0]

    b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val, }
    try:
        r = requests.get(tg, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:

        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)
    doc = minidom.parseString(r.text)
    mac = doc.getElementsByTagName('calling_station_id')[0].firstChild.nodeValue
    server = doc.getElementsByTagName('acs_server')[0].firstChild.nodeValue


    #COA 
    tg = 'https://'+ise_ip+'/admin/API/mnt/CoA/Reauth/' + server + '/' + mac + '/1'

    b64Val = base64.b64encode('admin:Dnae@2018'.encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val, }

    try:
        r = requests.get(tg, headers=headers, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print "Timeout Error:", errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        print "Error Connecting:", errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:

        print "Http Error:", errh
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print "Oops: Something Else", err
        sys.exit(1)

    '''

    # project=json.loads(project)
    # print application + user + trigger
    response_data['msg'] = "Dynamic priority has been revoked for user "+user.split("|")[0] + " of group " + user.split("|")[1] + " for SAP"
    return HttpResponse(json.dumps(response_data), content_type="application/json")