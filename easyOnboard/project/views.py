# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.shortcuts import render, render_to_response, redirect
from django.template import RequestContext
from django.contrib.auth import authenticate, login
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render
from django.http import JsonResponse
import requests, base64, json, sys, time, collections, ast
import pandas as pd
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

error_data = ""
ise_un = 'Username of the ise instance (ersadmin)'
ise_pw = 'Password of the ise instance (ersadmin)'
ise_ip = 'Ip address of the ise instance'
dnac_un = 'Username of the dnac instance'
dnac_pw = 'Password of the ise instance'
dnac_ip = 'Ip address of the dnac instance'
ad_domain = 'Domain of the Active Directory being used'

def index(request):

    b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val,
               'Accept': "application/json",
               'Content-Type': "application/json", }

    url = "https://"+ise_ip+":9060/ers/config/activedirectory"
    try:
        r = requests.get(url, headers=headers, verify=False)
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
    ide = objh['SearchResult']['resources'][0]['id']

    url = "https://" + ise_ip + ":9060/ers/config/activedirectory/" + ide + "/getGroupsByDomain"
    data = '{  "OperationAdditionalData" : {    "additionalData" : [ {      "name" : "domain",      "value" : "'+ad_domain+'"    } ]  } }'
    try:
        r = requests.put(url, headers=headers, data=data, verify=False)
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
    ou = []
    allprojects = []
    for group in objh['ERSActiveDirectoryGroups']['groups']:
        projectinfo = {}
        projectName = group['name'].split('/')[1]
        #print projectName
        usertype = group['name'].split('/')[2]
        #print usertype
        ou.append(group['name'].split('/')[1])
        user={}
        if any(project.get('projectName', None) == projectName for project in allprojects):
            for project in allprojects:
                if project['projectName'] == projectName:
                    user['name'] = usertype
                    user['full_name'] = group['name']
                    project['userType'].append(user)
        else:
            projectinfo['projectName'] = projectName
            user['name'] = usertype
            user['full_name'] = group['name']
            projectinfo['userType'] = [user]
            allprojects.append(projectinfo)
    ou = list(set(ou))

    # adding only the projects that have Org in their name
    activeProjects = []
    for project in allprojects:
        if "Org" in project['projectName']:
            activeProjects.append(project)
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
    #this is where we check if there is a main big project that has OUs in it
    for project in activeProjects:
        #check if sg is present
        print project
        print "Project Name is " +project['projectName']
        sgg= project['userType']
        print sgg
        print "sgg[0] is "
        print sgg[0]
        sggt = sgg[0]['name']
        print sggt
        abc = project['userType'][0]['name']
        print abc
        tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=" + str(sggt)
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
        if objh['response']:
            sgId= objh['response'][0]['id']
            # get vn in which SG is present
            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/virtualnetworkcontext"
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
            for vn in objh['response']:
                if str(sgId) in str(vn) and str(vn['name']) != 'DEFAULT_VN':
                    projMulOU = vn['name']
                    if projMulOU != project['projectName']:
                        proji={}
                        if any(proj.get('projectName', None) == projMulOU for proj in activeProjects):
                            for proj in activeProjects:
                                if proj['projectName'] == projMulOU:
                                    proj['userType'].extend(project['userType'])
                                    proj['VN'].append(project['projectName'])
                        else:
                            proji['projectName'] = projMulOU
                            proji['userType'] = project['userType']
                            proji['VN']=[project['projectName']]
                            activeProjects.append(proji)
                        project['inVN'] = True



    for project in activeProjects:
        if 'inVN' not in project:

            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/virtualnetworkcontext?name=" + str(project['projectName'])
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
            # print objh['response']
            if objh['response']:
                print project['projectName']
                for group in project['userType']:
                    # getting sgt value
                    print group
                    url = "https://"+ise_ip+":9060/ers/config/sgt/name/" + str(group['name'])
                    try:
                        r = requests.get(url, headers=headers, verify=False)
                        r.raise_for_status()
                    except requests.exceptions.Timeout as errt:
                        print "Timeout Error:", errt
                        sys.exit(1)
                    except requests.exceptions.ConnectionError as errc:
                        print "Error Connecting:", errc
                        sys.exit(1)
                    except requests.exceptions.HTTPError as errh:
                        print " "
                    except requests.exceptions.RequestException as err:
                        print "Oops: Something Else", err
                        sys.exit(1)

                    if r.text:
                        objh = json.loads(r.text)
                        sgt_value = objh['Sgt']['value']
                        group.update({"sgt_value": sgt_value})



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

                tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/Segment?name=.*" + str(project['projectName'])
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
                # print objh['response']
                if objh['response']:
                    ipPoolId = objh["response"][0]["ipPoolId"]
                    vlanId = str(objh['response'][0]['vlanId'])

                    # getting corresponding Ip and mask
                    tg = "https://"+dnac_ip+"/api/v2/ippool?id=" + ipPoolId
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

                ipPoolCidr = objh["response"][0]["ipPoolCidr"]
                project.update({"ipPool": ipPoolCidr})
                project.update({"associated": True})
                project.update({"vlanId": vlanId})
                #activeProjects= json.dumps(activeProjects)
                #print activeProjects

                #fh = open("post_command.txt", "w")
                #fh.write(str(activeProjects))
                #fh.close()
                print activeProjects
    return render(request, 'projectList.html', {'allprojects': activeProjects})


def validate_username(request):
    username = request.GET.get('username', None)
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://+dnac_ip+/api/system/v1/auth/login',
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

    tg = 'https://+dnac_ip+/api/v2/data/customer-facing-service/virtualnetworkcontext'

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
    allprojects = objh['response']
    project_name=[]
    for project in allprojects:
        project_name.append(project['name'])
    if username in project_name:
        taken = True
    else:
        taken = False
    data = {
        'is_taken': taken
    }
    return JsonResponse(data)


def associateProject(request):
    response_data = {}
    project = request.GET.get('project',None)
    #project=json.loads(project)
    projectcurr = eval(project)
    print projectcurr
    #print type(project)
    #print project["projectName"]
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://+dnac_ip+/api/system/v1/auth/login',
                         headers={"Authorization": "Basic %s" % b64Val, "Content-Type": "application/json"},
                         verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in the authorization for the DNAC'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),
                                content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in the authorization for the DNAC'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),
                                content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in the authorization for the DNAC'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),
                                content_type='application/json')

        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in the authorization for the DNAC'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),
                                content_type='application/json')
        return response

    a = r.headers['Set-Cookie'].split(";")
    b = a[0].split("=")
    c = b[1]
    cookie = {'X-JWT-ACCESS-TOKEN': c}

    # getting the details for the DNS and DHCP servers
    tg = "https://+dnac_ip+/api/v1/commonsetting/global/-1"

    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()

    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in getting the details for the DNS and DHCP servers'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in getting the details for the DNS and DHCP servers'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in getting the details for the DNS and DHCP servers'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in getting the details for the DNS and DHCP servers'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    objh = json.loads(r.text)
    for obj in objh["response"]:
        if obj["key"] == "dns.server":
            dns_server = obj["value"][0]["primaryIpAddress"]
            print dns_server
        if obj["key"] == "dhcp.server":
            dhcp_server = obj["value"][0]
            print dhcp_server


    # get the scalable groups
    scalableGroup = []
    for group in projectcurr['userType']:

        # creating the sgt
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "' + str(group['name']) + '",    "description" : "' + str(
            group['name']) + ' group for ' + str(projectcurr['projectName']) + '",    "value" : -1  } }'
        print data

        try:
            b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
            r = requests.post(url, headers={'Authorization': 'Basic %s' % b64Val,'Accept': "application/json",'Content-Type': "application/json", }, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            err = 'An timeout error occured in creating the sgt for group.'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.ConnectionError as errc:
            err = 'An Connection error occured in creating the sgt for group.'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.HTTPError as errh:
            err = 'An Http error occured in creating the sgt for group.'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.RequestException as err:
            err = 'An unexpected error occured in creating the sgt for group '
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response

        time.sleep(3)




        # getting the scalable groups
        scalg = {}

        tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/scalablegroup?name=" + group["name"]

        print tg
        try:
            r = requests.get(tg, cookies=cookie, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            err = 'An timeout error occured in getting the scalable groups for group '
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.ConnectionError as errc:
            err = 'An Connection error occured in getting the scalable groups for group '
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.HTTPError as errh:
            err = 'An Http error occured in getting the scalable groups for group '
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.RequestException as err:
            err = 'An unexpected error occured in in getting the scalable groups for group '
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        objh = json.loads(r.text)
        #print(objh["response"])
        #print str(objh["response"][0])
        scalg[str("idRef")] = str(objh["response"][0]["id"])
        scalableGroup.append(scalg)
    stringsg = str(scalableGroup)
    stringsg = stringsg.replace("'", '"')

    # creating the VN or project in this case
    # user_input = "IT"
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/virtualnetworkcontext/"
    headers = {'Content-Type': 'application/json', }
    headers = {'Content-Type': 'application/json', }
    data = '[{"name":"' + projectcurr[
        'projectName'] + '","virtualNetworkContextType":"ISOLATED","scalableGroup": ' + stringsg + '}]'
    print data
    try:
        r = requests.post(tg, data=data, headers=headers, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in creating the Virtual Network for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in creating the Virtual Network for the OU '
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in creating the Virtual Network for for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in in creating the Virtual Network for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response

    # objh = json.loads(r.text)
    # print objh

    # get values from IPAM file
    ipam = pd.read_csv("ipam_file.csv")
    inf = ipam.loc[ipam["project_name"] == projectcurr['projectName']]
    print inf
    info = ipam.loc[ipam["project_name"] == projectcurr['projectName']].to_string(header=False,
                                                                                  index=False,
                                                                                  index_names=False).split('  ')
    print info
    #if inf.empty:
    #    err = 'The Ip details are not present in the IPAM file.'
    #    response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}), content_type='application/json')
    #    return response

    #print "the infomation is Project name: " + str(info[0]) + " Ip address: " + str(info[1]) + str(
     #   info[2]) + " Gateways: " + str(info[3])

    # create the ip pool

    ip_name = "ip_" + projectcurr['projectName']
    # print ip_name

    tg = "https://+dnac_ip+/api/v2/ippool"
    headers = {'Content-Type': 'application/json', }
    data = '{"ipPoolName":"' + ip_name + '","ipPoolCidr":"' + str(info[1]) + str(info[2]) + '","gateways":["' + str(
        info[
            3]) + '"],"dhcpServerIps":["' + dhcp_server + '"],"dnsServerIps":["' + dns_server + '"],"overlapping":false}'
    try:
        r = requests.post(tg, data=data, headers=headers, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in creating the Ip pool for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in creating the Ip pool for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in creating the Ip pool for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in creating the Ip pool for the OU'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    print json.loads(r.text)
    time.sleep(60)

    # associating vn to ip pool (getting the information)
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/VirtualNetwork?name=" + str(projectcurr[
        'projectName']) + "-FABRIC1"

    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    objh = json.loads(r.text)
    print objh
    if not objh['response']:
        print "it did not reach here"
        err = 'The vn could not be associated to the IP pool'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}), content_type='application/json')
        return response
    else:
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

        if not CCI:
            cfsChangeInfo = ''
        else:
            cfsChangeInfo = " ".join(CCI)

    # getting the ip id
    tg = "https://+dnac_ip+/api/v2/ippool?ipPoolName=" + ip_name
    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in getting the details of the IP Pool'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in getting the details of the IP Pool'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in getting the details of the IP Pool'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in getting the details of the IP Pool'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    objh = json.loads(r.text)

    ipPoolId = objh["response"][0]["id"]
    ip = objh["response"][0]["ipPoolCidr"].split('/')[0]
    # print ip
    ip_name = ip.replace('.', '_')
    # print ip_name
    #associating the ip pool to the VN
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/VirtualNetwork"
    headers = {'Content-Type': 'application/json', }
    data = '[{"fabricOverride": [],"segment": [{"type": "Segment","name": "' + ip_name + '-' + projectcurr[
        'projectName'] + '","trafficType": "DATA","ipPoolId": "' + ipPoolId + '","isFloodAndLearn": true,"isApProvisioning": false,"isDefaultEnterprise": false,"connectivityDomain": {"idRef": "' + namespace + '"} }],"id": "' + project_id + '","name": "' + name + '","type": "' + project_type + '","isDefault": ' + isDefault + ',"isInfra": ' + isInfra + ',"l3Instance": ' + l3Instance + ',"namespace": "' + namespace + '","instanceId": ' + instanceId + ',"authEntityId": ' + authEntityId + ',"displayName": "' + displayName + '","authEntityClass": ' + authEntityClass + ',"deployPending": "' + deployPending + '","instanceVersion": ' + instanceVersion + ',"deployed": ' + deployed + ',"isStale": ' + isStale + ',"provisioningState": "' + provisioningState + '","cfsChangeInfo": ' + cfsChangeInfo + ',"virtualNetworkContextId": "' + virtualNetworkContextId + '","resourceVersion": ' + resourceVersion + '}]'
    try:
        r = requests.put(tg, data=data, headers=headers, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in associating the Ip pool to the VN'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val,
               'Accept': "application/json",
               'Content-Type': "application/json", }
    time.sleep(10)
    #getting Vlan ID
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/Segment?name=" + ip_name + "-" + projectcurr[
        'projectName']
    print tg
    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in geting the vlan Id.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in geting the vlan Id.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in geting the vlan Id.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in geting the vlan Id.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    objh = json.loads(r.text)
    vlanId = str(objh['response'][0]['vlanId'])
    print vlanId

    # create new authorization profile

    url = 'https://'+ise_ip+':9060/ers/config/authorizationprofile/'
    data = '{"AuthorizationProfile": {"id": "id","name": "vlan_' + vlanId + '","description": "vlan for ' + projectcurr[
        "projectName"] + '","accessType": "ACCESS_ACCEPT","authzProfileType": "SWITCH","vlan": {"nameID": "' + vlanId + '","tagID": 1},"trackMovement": false,"serviceTemplate": false,"easywiredSessionCandidate": false,"voiceDomainPermission": false,"neat": false,"webAuth": false}}'
    print data
    try:
        r = requests.post(url, headers=headers, data=data, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in creating the authorization profile'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in creating the authorization profile.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in creating the authorization profile.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in creating the authorization profile.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    for group in projectcurr['userType']:


        # creating authorization rule for all
        url = "https://"+ise_ip+":9060/ers/config/authorizationrule"
        data = '{"AuthorizationRule": {"id": "' + group['name'] + '","name": "' + group[
            'name'] + '","rank": 0,"enabled": true,"condition": {"conditionType": "AttributeCondition",' \
                      '"isNot": false,"operand": "EQUALS","attributeName": "ExternalGroups","value": "' + \
               group['full_name'] + '","dictionaryName": "DNAC"},"permissions": {"standardList": ["vlan_' \
               + vlanId + '"],"securityGroupList": ["' + group['name'] + '"] } } }'
        print data
        try:
            r = requests.post(url, headers=headers, data=data, verify=False)
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            err = 'An timeout error occured in creating the authorization rule'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.ConnectionError as errc:
            err = 'An Connection error occured in creating the authorization rule.'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.HTTPError as errh:
            err = 'An Http error occured in creating the authorization rule.'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response
        except requests.exceptions.RequestException as err:
            err = 'An unexpected error occured in creating the authorization rule.'
            response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
            return response

    response_data['msg'] = "Project "+projectcurr['projectName']+" has been successfully associated"
    return HttpResponse(json.dumps(response_data), content_type="application/json")



def disassociateProject(request):
    response_data = {}
    project = request.GET.get('project',None)
    #project=json.loads(project)
    projectcurr = eval(project)
    print projectcurr
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://+dnac_ip+/api/system/v1/auth/login',
                         headers={"Authorization": "Basic %s" % b64Val, "Content-Type": "application/json"},
                         verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in authorization of the DNAC.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in authorization of the DNAC.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in authorization of the DNAC.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in authorization of the DNAC.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response


    a = r.headers['Set-Cookie'].split(";")
    b = a[0].split("=")
    c = b[1]
    cookie = {'X-JWT-ACCESS-TOKEN': c}
    # getting values of the VN
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/VirtualNetwork?name=" + projectcurr[
        'projectName'] + "-FABRIC1"

    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in getting the value of the VN.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in getting the value of the VN.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in getting the value of the VN.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in getting the value of the VN.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response

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
    segment_id = str(project["segment"][0]["idRef"])

    if not CCI:
        cfsChangeInfo = ''
    else:
        cfsChangeInfo = " ".join(CCI)
    # dissasociating the ip with VN
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/VirtualNetwork"
    headers = {'Content-Type': 'application/json', }
    data = '[{"fabricOverride": [],"segment": [],"id": "' + project_id + '","name": "' + name + '","type": "' + project_type + '","isDefault": ' + isDefault + ',"isInfra": ' + isInfra + ',"l3Instance": ' + l3Instance + ',"namespace": "' + namespace + '","instanceId": ' + instanceId + ',"authEntityId": ' + authEntityId + ',"displayName": "' + displayName + '","authEntityClass": ' + authEntityClass + ',"deployPending": "' + deployPending + '","instanceVersion": ' + instanceVersion + ',"deployed": ' + deployed + ',"isStale": ' + isStale + ',"provisioningState": "' + provisioningState + '","cfsChangeInfo": ' + cfsChangeInfo + ',"virtualNetworkContextId": "' + virtualNetworkContextId + '","resourceVersion": ' + resourceVersion + '}]'
    try:
        r = requests.put(tg, data=data, headers=headers, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in dissasociating the vn with the ip.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in dissasociating the vn with the ip.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in dissasociating the vn with the ip.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in dissasociating the vn with the ip.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response

    # getting id of vn

    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/virtualnetworkcontext/?name=" + projectcurr[
        'projectName']

    try:
        r = requests.get(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    objh = json.loads(r.text)
    vn_id = objh['response'][0]['id']

    # delete the vn
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/virtualnetworkcontext/" + vn_id

    try:
        r = requests.delete(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        err = 'An timeout error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.ConnectionError as errc:
        err = 'An Connection error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.HTTPError as errh:
        err = 'An Http error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response
    except requests.exceptions.RequestException as err:
        err = 'An unexpected error occured in deleting the vn.'
        response = HttpResponse(json.dumps({'err': err, 'status_code': r.status_code}),content_type='application/json')
        return response

    #getting the vlan id
    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/Segment/" + segment_id
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

    # delete authrule by id in https://+ise_ip+:9060/ers/config/authorizationrule/name/<rulename>
    b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val,
               'Accept': "application/json",
               'Content-Type': "application/json", }

    for group in projectcurr['userType']:

        # deleting the autorization rule
        tg = "https://"+ise_ip+":9060/ers/config/authorizationrule/name/" + str(group['name'])

        try:

            r = requests.delete(tg, headers=headers, verify=False)
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
        # Delete SGT https://+ise_ip+:9060/ers/config/sgt/{id}
        tg = "https://"+ise_ip+":9060/ers/config/sgt/name/" + str(group['name'])

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
        objh = json.loads(r.text)
        sgt_id = objh['Sgt']['id']

        tg = "https://"+ise_ip+":9060/ers/config/sgt/" + str(sgt_id)

        try:

            r = requests.delete(tg, headers=headers, verify=False)
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

    # deleting the auth profile
    url = 'https://'+ise_ip+':9060/ers/config/authorizationprofile/name/vlan_' + str(vlanId)
    try:
        r = requests.get(url, headers=headers, data=data, verify=False)
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
    authprofile = objh['AuthorizationProfile']['id']

    url = 'https://'+ise_ip+':9060/ers/config/authorizationprofile/' + str(authprofile)
    try:
        r = requests.delete(url, headers=headers, data=data, verify=False)
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

    # deleting ip pool (getting id)
    tg = "https://+dnac_ip+/api/v2/ippool?ipPoolName=ip_" + projectcurr['projectName']

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
    ipPool_id = objh['response'][0]['id']
    # print ipPool_id
    #print ipPool_id
    # delete the ip pool
    tg = "https://+dnac_ip+/api/v2/ippool/" + str(ipPool_id)
   #print tg
    try:
        r = requests.delete(tg, cookies=cookie, verify=False)
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
    # print json.loads(r.text)
    time.sleep(8)

    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/VirtualNetwork/"+project_id
    print tg
    try:
        r = requests.delete(tg, cookies=cookie, verify=False)
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        response_data['msg'] = "Timeout Error:" + errt
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        response_data['msg'] = "Error Connecting:" + errc
        sys.exit(1)
    except requests.exceptions.HTTPError as errh:
        response_data['msg'] = "Http Error:" + str(errh)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        response_data['msg'] = "Oops: Something Else" + str(err)
        sys.exit(1)
    time.sleep(2)
    response_data['msg'] = "Project "+ projectcurr['projectName']+" has been successfully disassociated"
    return HttpResponse(json.dumps(response_data), content_type="application/json")

from django.http import HttpResponse, HttpResponseServerError, HttpResponseBadRequest, HttpResponseNotFound
from django.shortcuts import render
from django.template import Context, loader
import traceback
import sys
from django.http import Http404

def handler404(request):
    dat=error_data
    global error_data
    error_data=""
    return render(request, '404.html', {'data': dat})


def handler500(request):
    t = loader.get_template('500.html')
    type, value, tb = sys.exc_info()
    return HttpResponseServerError(t.render(Context({'exception_value': value, })))


def refreshProject(request):
    response_data = {}
    project = request.GET.get('project',None)
    projectcurr = eval(project)
    print projectcurr
    b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
    headers_ise = {'Authorization': 'Basic %s' % b64Val,
                   'Accept': "application/json",
                   'Content-Type': "application/json", }
    flag = 2

    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://+dnac_ip+/api/system/v1/auth/login',
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

    b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val, 'Accept': "application/json", 'Content-Type': "application/json", }

    tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/virtualnetworkcontext?name=" + projectcurr[
        "projectName"]

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
    vnc = json.loads(r.text)

    scalableGroupsFinal = json.loads(str(json.dumps(vnc["response"][0]["scalableGroup"])))
    for sg in scalableGroupsFinal:
        tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/scalablegroup/" + sg["idRef"]
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
        # print(objh["response"])
        # print str(objh["response"][0])
        scalablegroupName = str(objh["response"][0]["name"])
        if str(scalablegroupName) not in str(projectcurr['userType']):
            print scalablegroupName
            # deleting the auth rule
            tg = "https://"+ise_ip+":9060/ers/config/authorizationrule/name/" + str(scalablegroupName)

            try:

                r = requests.delete(tg, headers=headers_ise, verify=False)
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

            # deleting the sgt
            tg = "https://"+ise_ip+":9060/ers/config/sgt/name/" + str(scalablegroupName)

            try:
                r = requests.get(tg, headers=headers_ise, verify=False)
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
            sgt_id = objh['Sgt']['id']

            tg = "https://"+ise_ip+":9060/ers/config/sgt/" + str(sgt_id)

            try:

                r = requests.delete(tg, headers=headers_ise, verify=False)
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

            # deleting from VN

            scalableGroupsFinal[:] = [d for d in scalableGroupsFinal if d.get('idRef') != sg["idRef"]]
            flag = 0

    if flag == 0:
        scalableGroupsFinal = str(json.dumps(scalableGroupsFinal))
        data = '[{"id":"' + str(vnc["response"][0]["id"]) + '","instanceId":' + str(vnc["response"][0]["instanceId"]) \
               + ',"authEntityId":' \
               + str(vnc["response"][0]["authEntityId"]) \
               + ',"displayName":"' \
               + str(vnc["response"][0]["displayName"]) + '","authEntityClass":' + str(
            vnc["response"][0]["authEntityClass"]) \
               + ',"deployPending":"' + str(vnc["response"][0]["deployPending"]) + '","instanceVersion":' + str(
            vnc["response"][0]["instanceVersion"]) \
               + ',"createTime":' + str(vnc["response"][0]["createTime"]) + ',"deployed":' + str(
            json.dumps(vnc["response"][0]["deployed"])) \
               + ',"isSeeded":' + str(json.dumps(vnc["response"][0]["isSeeded"])) + ',"isStale":' + str(
            json.dumps(vnc["response"][0]["isStale"])) \
               + ',"lastUpdateTime":' + str(vnc["response"][0]["lastUpdateTime"]) \
               + ',"name":"' + str(vnc["response"][0]["name"]) + '","namespace":"' \
               + str(vnc["response"][0]["namespace"]) + '","provisioningState":"' + str(
            vnc["response"][0]["provisioningState"]) \
               + '","resourceVersion":' + str(vnc["response"][0]["resourceVersion"]) + ',"type":"' + str(
            vnc["response"][0]["type"]) \
               + '","cfsChangeInfo":[],"customProvisions":[],"virtualNetworkContextType":"' + str(
            vnc["response"][0]["virtualNetworkContextType"]) \
               + '","scalableGroup":' + scalableGroupsFinal + '}]'

        tg = "https://+dnac_ip+/api/v2/data/customer-facing-service/virtualnetworkcontext"
        headers = {'Content-Type': 'application/json', }
        print data

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

    # get new vn values
    tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/virtualnetworkcontext?name=" + projectcurr[
        "projectName"]

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
    vnc = json.loads(r.text)

    scalableGroup = []
    for group in projectcurr['userType']:
        if 'sgt_value' not in group:

            # create sgt
            url = "https://"+ise_ip+":9060/ers/config/sgt"
            data = '{  "Sgt" : {    "id" : "id",    "name" : "' + str(group['name']) + '",    "description" : "' + str(
                group['name']) + ' group for ' + str(projectcurr['projectName']) + '",    "value" : -1  } }'
            print data

            try:
                r = requests.post(url, headers=headers_ise, data=data, verify=False)
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
            data = '{"AuthorizationRule": {"id": "' + group["name"] + '","name": "' + group[
                "name"] + '","rank": 0,"enabled": true,"condition": {"conditionType": "AttributeCondition","isNot": false,"operand": "EQUALS","attributeName": "ExternalGroups","value": "' + \
                   group["full_name"] + '","dictionaryName": "DNAC"},"permissions": {"standardList": ["vlan_' + \
                   projectcurr["vlanId"] + '"],"securityGroupList": ["' + \
                   group["name"] + '"] } } }'
            print data
            try:
                r = requests.post(url, headers=headers_ise, data=data, verify=False)
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

            # add to VN
            # get the scalable group created

            scalg = {}
            tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=" + group["name"]

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
            # print(objh["response"])
            # print str(objh["response"][0])
            scalg[str("idRef")] = str(objh["response"][0]["id"])
            scalableGroup.append(scalg)
            flag = 1
        stringsg = str(scalableGroup)
        stringsg = stringsg.replace("'", '"')


    # print stringsg
    if flag == 1:
        scalableGroupsFinal = str(json.dumps(vnc["response"][0]["scalableGroup"]).replace(']', '')) + ' , ' + str(
            stringsg.replace('[', ''))
        data = '[{"id":"' + str(vnc["response"][0]["id"]) + '","instanceId":' + str(vnc["response"][0]["instanceId"]) \
               + ',"authEntityId":' \
               + str(vnc["response"][0]["authEntityId"]) \
               + ',"displayName":"' \
               + str(vnc["response"][0]["displayName"]) + '","authEntityClass":' + str(
            vnc["response"][0]["authEntityClass"]) \
               + ',"deployPending":"' + str(vnc["response"][0]["deployPending"]) + '","instanceVersion":' + str(
            vnc["response"][0]["instanceVersion"]) \
               + ',"createTime":' + str(vnc["response"][0]["createTime"]) + ',"deployed":' + str(
            json.dumps(vnc["response"][0]["deployed"])) \
               + ',"isSeeded":' + str(json.dumps(vnc["response"][0]["isSeeded"])) + ',"isStale":' + str(
            json.dumps(vnc["response"][0]["isStale"])) \
               + ',"lastUpdateTime":' + str(vnc["response"][0]["lastUpdateTime"]) \
               + ',"name":"' + str(vnc["response"][0]["name"]) + '","namespace":"' \
               + str(vnc["response"][0]["namespace"]) + '","provisioningState":"' + str(
            vnc["response"][0]["provisioningState"]) \
               + '","resourceVersion":' + str(vnc["response"][0]["resourceVersion"]) + ',"type":"' + str(
            vnc["response"][0]["type"]) \
               + '","cfsChangeInfo":[],"customProvisions":[],"virtualNetworkContextType":"' + str(
            vnc["response"][0]["virtualNetworkContextType"]) \
               + '","scalableGroup":' + scalableGroupsFinal + '}]'

        tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/virtualnetworkcontext"
        headers = {'Content-Type': 'application/json', }
        print data
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

    response_data['msg'] = "The User Types Have Been Updated"
    return HttpResponse(json.dumps(response_data), content_type="application/json")


def multipleOUs(request):
    response_data = {}
    project_Name = request.GET.get('projectName',None)
    list_of_Projects = request.GET.getlist('oulist[]', None)
    print list_of_Projects
    print project_Name
    response_data = {}
    # index part

    b64Val = base64.b64encode((ise_un+':'+ise_pw).encode('UTF-8')).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % b64Val,
               'Accept': "application/json",
               'Content-Type': "application/json", }

    url = "https://"+ise_ip+":9060/ers/config/activedirectory"
    try:
        r = requests.get(url, headers=headers, verify=False)
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
    ide = objh['SearchResult']['resources'][0]['id']

    url = "https://"+ise_ip+":9060/ers/config/activedirectory/" + ide + "/getGroupsByDomain"
    data = '{  "OperationAdditionalData" : {    "additionalData" : [ {      "name" : "domain",  ' \
           '  "value" : "ciscotest.com"    } ]  } }'
    try:
        r = requests.put(url, headers=headers, data=data, verify=False)
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
    ou = []
    allprojects = []
    for group in objh['ERSActiveDirectoryGroups']['groups']:
        projectinfo = {}
        projectName = group['name'].split('/')[1]
        # print projectName
        usertype = group['name'].split('/')[2]
        # print usertype
        ou.append(group['name'].split('/')[1])
        user = {}
        if any(project.get('projectName', None) == projectName for project in allprojects):
            for project in allprojects:
                if project['projectName'] == projectName:
                    user['name'] = usertype
                    user['full_name'] = group['name']
                    project['userType'].append(user)
        else:
            projectinfo['projectName'] = projectName
            user['name'] = usertype
            user['full_name'] = group['name']
            projectinfo['userType'] = [user]
            allprojects.append(projectinfo)
    ou = list(set(ou))
    # print ou
    # print allprojects[3]
    # adding only the projects that have Org in their name
    projectcurr = {}
    projectcurr['projectName'] = project_Name
    usrtyp = []
    for project in allprojects:
        if project['projectName'] in list_of_Projects:
            usrtyp.extend(project['userType'])
    projectcurr['userType'] = usrtyp
    print projectcurr

    # authenticate to make API calls to DNAC
    b64Val = base64.b64encode((dnac_un+':'+dnac_pw).encode('UTF-8')).decode('utf-8')
    try:
        r = requests.get('https://"+dnac_ip+"/api/system/v1/auth/login',
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

    # the associate project part

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

    # get the scalable groups
    scalableGroup = []
    for group in projectcurr['userType']:
        # creating the sgt
        url = "https://"+ise_ip+":9060/ers/config/sgt"
        data = '{  "Sgt" : {    "id" : "id",    "name" : "' + str(group['name']) + '",    "description" : "' + str(
            group['name']) + ' group for ' + str(projectcurr['projectName']) + '",    "value" : -1  } }'
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

    time.sleep(10)
    for group in projectcurr['userType']:
        # getting the scalable groups

        scalg = {}
        tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/scalablegroup?name=" + group["name"]

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
        # print(objh["response"])
        # print str(objh["response"][0])
        scalg[str("idRef")] = str(objh["response"][0]["id"])
        scalableGroup.append(scalg)
    stringsg = str(scalableGroup)
    stringsg = stringsg.replace("'", '"')
    print stringsg

    # creating the VN or project in this case
    # user_input = "IT"
    tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/virtualnetworkcontext/"
    headers = {'Content-Type': 'application/json', }
    data = '[{"name":"' + projectcurr[
        'projectName'] + '","virtualNetworkContextType":"ISOLATED","scalableGroup": ' + stringsg + '}]'
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
    # objh = json.loads(r.text)
    # print objh

    # get values from IPAM file
    ipam = pd.read_csv("ipam_file.csv")
    # print projectcurr['projectName']
    # print ipam.loc[ipam["project_name"] == projectcurr['projectName']]
    info = ipam.loc[ipam["project_name"] == projectcurr['projectName']].to_string(header=False,
                                                                                  index=False,
                                                                                  index_names=False).split('  ')
    print info
    # print "the infomation is Project name: " + str(info[0]) + " Ip address: " + str(info[1]) + str(
    #   info[2]) + " Gateways: " + str(info[3])

    # create the ip pool
    ip_name = "ip_" + projectcurr['projectName']
    # print ip_name

    tg = "https://"+dnac_ip+"/api/v2/ippool"
    headers = {'Content-Type': 'application/json', }
    data = '{"ipPoolName":"' + ip_name + '","ipPoolCidr":"' + str(info[1]) + str(info[2]) + '","gateways":["' + str(
        info[
            3]) + '"],"dhcpServerIps":["' + dhcp_server + '"],"dnsServerIps":["' + dns_server + '"],"overlapping":false}'
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
    print json.loads(r.text)
    time.sleep(60)

    # associating vn to ip pool (getting the information)
    tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/VirtualNetwork?name=" + str(projectcurr[
                                                                                                    'projectName']) + "-FABRIC1"

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
    data = '[{"fabricOverride": [],"segment": [{"type": "Segment","name": "' + ip_name + '-' + projectcurr[
        'projectName'] + '","trafficType": "DATA","ipPoolId": "' + ipPoolId + '","isFloodAndLearn": true,"isApProvisioning": false,"isDefaultEnterprise": false,"connectivityDomain": {"idRef": "' + namespace + '"} }],"id": "' + project_id + '","name": "' + name + '","type": "' + project_type + '","isDefault": ' + isDefault + ',"isInfra": ' + isInfra + ',"l3Instance": ' + l3Instance + ',"namespace": "' + namespace + '","instanceId": ' + instanceId + ',"authEntityId": ' + authEntityId + ',"displayName": "' + displayName + '","authEntityClass": ' + authEntityClass + ',"deployPending": "' + deployPending + '","instanceVersion": ' + instanceVersion + ',"deployed": ' + deployed + ',"isStale": ' + isStale + ',"provisioningState": "' + provisioningState + '","cfsChangeInfo": ' + cfsChangeInfo + ',"virtualNetworkContextId": "' + virtualNetworkContextId + '","resourceVersion": ' + resourceVersion + '}]'
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
    tg = "https://"+dnac_ip+"/api/v2/data/customer-facing-service/Segment?name=" + ip_name + "-" + projectcurr[
        'projectName']
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
    data = '{"AuthorizationProfile": {"id": "id","name": "vlan_' + vlanId + '","description": "vlan for ' + projectcurr[
        "projectName"] + '","accessType": "ACCESS_ACCEPT","authzProfileType": "SWITCH","vlan": {"nameID": "' + vlanId + '","tagID": 1},"trackMovement": false,"serviceTemplate": false,"easywiredSessionCandidate": false,"voiceDomainPermission": false,"neat": false,"webAuth": false}}'
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
    for group in projectcurr['userType']:

        # creating authorization rule for all
        url = "https://"+ise_ip+":9060/ers/config/authorizationrule"
        data = '{"AuthorizationRule": {"id": "' + group['name'] + '","name": "' + group[
            'name'] + '","rank": 0,"enabled": true,"condition": {"conditionType": "AttributeCondition","isNot": false,"operand": "EQUALS","attributeName": "ExternalGroups","value": "' + \
               group[
                   'full_name'] + '","dictionaryName": "DNAC"},"permissions": {"standardList": ["vlan_' + vlanId + '"],"securityGroupList": ["' + \
               group['name'] + '"] } } }'
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

    response_data['msg'] = "The OUS have been added to a single VN under the name "+project_Name
    return HttpResponse(json.dumps(response_data), content_type="application/json")
