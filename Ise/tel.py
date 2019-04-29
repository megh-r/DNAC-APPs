#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr  3 10:57:48 2019

@author: mesudhak
"""

import telnetlib
import time
import re 
from pandas import DataFrame, set_option, concat
from base64 import b64encode
import requests
import json
import ast

#packages required to generate pdf
from numpy import array, vstack
from reportlab.lib.styles import ParagraphStyle as PS
from reportlab.platypus import Table, TableStyle, Spacer
from reportlab.platypus import PageBreak
from reportlab.platypus.paragraph import Paragraph
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus.frames import Frame
from reportlab.lib.units import cm
from reportlab.lib.units import inch
from reportlab.lib import colors

#package required to suppress warnings about not having SSL certificate verification
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#command to suppress warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#pdf generation
class MyDocTemplate(BaseDocTemplate):
    def __init__(self, filename, **kw):
        self.allowSplitting = 0
        BaseDocTemplate.__init__(self, filename, **kw)
        template = PageTemplate('normal', [Frame(2.5*cm, 2.5*cm, 15*cm, 25*cm, id='F1')])
        self.addPageTemplates(template)
                
    def afterFlowable(self, flowable):
        "Registers TOC entries."
        if flowable.__class__.__name__ == 'Paragraph':
            text = flowable.getPlainText()
            style = flowable.style.name
            if style == 'Heading1':
                level = 0
            elif style == 'Heading2':
                level = 1
            elif style == 'Heading3':
                level = 2
            else:
                return
            E = [level, text, self.page]
            
            #if we have a bookmark name append that to our notify data
            bn = getattr(flowable,'_bookmarkName',None)
            if bn is not None: E.append(bn)
            self.notify('TOCEntry', tuple(E))
            
centered = PS(name = 'centered',
        fontSize = 30,
        leading = 16,
        alignment = 1,
        spaceAfter = 20)

h1 = PS(name = 'Heading1',
              fontSize = 14,
             leading = 16,
               alignment=1,
           fontName='Helvetica-Bold')
h2 = PS(name = 'Heading2',
              fontSize = 14,
              leading = 16,
              alignment=1,
           fontName='Helvetica-Bold')
h3 = PS(name = 'Heading3',
              fontSize = 14,
              leading = 16,
              alignment=1,
           fontName='Helvetica-Bold',
           textColor = colors.red)

story=[]

story.append(Paragraph('<b>Table of contents</b>', centered))

toc = TableOfContents()
toc.levelStyles = [
        PS(fontName='Times-Bold', fontSize=20, name='TOCHeading1', leftIndent=20, firstLineIndent=-20, spaceBefore=10, leading=16),
        PS(fontSize=18, name='TOCHeading2', leftIndent=30, firstLineIndent=-20, spaceBefore=5, leading=12),
        PS(fontSize=18, name='TOCHeading3', leftIndent=30, firstLineIndent=-20, spaceBefore=5, leading=12, textColor = colors.red),
        ]

story.append(toc)
story.append(PageBreak())

def doHeading(text,sty):
    from hashlib import sha1
    #create bookmarkname
    bn=sha1((text+sty.name).encode('utf-8')).hexdigest()
    #modify paragraph text to include an anchor point with name bn
    h=Paragraph(text+'<a name="%s"/>' % bn,sty)
    #store the bookmark name on the flowable so afterFlowable can see this
    h._bookmarkName=bn
    story.append(h)

style = PS(
    name='Normal',
    fontName='Helvetica-Bold',
    fontSize=14,
    alignment=1
    )
style1 = PS(
   name='Normal',
    fontName='Helvetica',
    fontSize=10,
    alignment=1
    )
style2 = PS(
    name='Normal',
    fontName='Helvetica',
    fontSize=10,
    alignment=0
    )

#function to flatten lists
def flat(nums):
    res = []
    index = []
    for i in range(len(nums)):
        if isinstance(nums[i], list):
            res.extend(nums[i])
            index.extend([i]*len(nums[i]))
        else:
            res.append(nums[i])
            index.append(i)
    return res,index

#----------------------------------------------ISE------------------------------------------------------
f = open("telinput1.txt", "r")
y=[]
for x in f:
    y.append(x.split("-"))

debug=y[5][1].strip()    #if debug option is yes then detailed output of every API call and steps of parsing the required data is
if debug.lower()=="yes":  #displayed
    debug=1
else:
    debug=0
ise_ip=y[0][1].strip()
if debug==1:
    print(ise_ip)
ise_un=y[1][1].strip()
if debug==1:
    print(ise_un)
ise_pw=y[2][1].strip()
if debug==1:
    print(ise_pw)

unknwnval=0
defaultval=0

#encoding for the request to authorize access to the DNAC instance
def encoder(un,pw):
    encodedvalue=un+":"+pw
    b64Val = b64encode(encodedvalue.encode('UTF-8')).decode('utf-8')
    return (b64Val)

#to get ISE egressmatrix cell ids
def egressconfig(ip,b64Val):
    ids=[]
    repos=[]
    try:
        r= requests.get('https://'+ip+'/ers/config/egressmatrixcell?simple=yes&page=1',headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json","Accept": "application/json"}, verify=False)
        #print(repr(r.text))
        #print(r.status_code)
        #checking for correct username and password
        #if r.status_code!=200:
        if not r.text.startswith('{\n  "SearchResult"'):
            print("Please check the data you entered again")
            return("error",r.status_code)
        json_data = json.loads(r.text)
        repos.append(json_data)
        #checking for next page
        try:
            while json_data["SearchResult"]["nextPage"]['rel'] == 'next':
                url=json_data["SearchResult"]["nextPage"]['href']
                r=requests.get(url,headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json","Accept": "application/json"}, verify=False)
                #print(r.text)
                #print(r)
                json_data = json.loads(r.text)
                repos.append(json_data)
        except:
            print("")
            #print(repos,len(repos))

        for i in repos:
            #print(i)
            x=i['SearchResult']['resources']
            for element in range(len(x)):
                ids.append(x[element]['id'])    
        #print(ids)
        #Error handling 
        r.raise_for_status()
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
        return("error",errt)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
        return("error",errc)
    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
        return("error",errh)
    except requests.exceptions.RequestException as err:
        print ("Oops: Something Else",err)
        return("error",err)
    if debug==1:
        print("ISE EGMatrix Cell Ids: ",ids)
        print(len(ids))
    return(ids, 0)

#to get egressmatrix cell responses 
def egressresp(ids,ip,b64Val):
    responses=[]
    for element in ids:
        try:
            r= requests.get('https://'+ip+'/ers/config/egressmatrixcell/'+element,headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json","Accept": "application/json"}, verify=False)
            json_data = json.loads(r.text)
            #print(element)
            responses.append(json_data)
            #error handling
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
            exit(1)
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
            exit(1)
        except requests.exceptions.HTTPError as errh:
            print ("Http Error:",errh)
            exit(1)
        except requests.exceptions.RequestException as err:
            print ("Oops: Something Else",err)
            exit(1)
    #print(responses)
    return responses

#to get sgtid,dgtid,sgaclid
def idsresp(responses):
    sgtid=[]
    dgtid=[]
    sgaclid=[]
    for i in range(len(responses)):
        sgtid.append(responses[i]['EgressMatrixCell']['sourceSgtId'])
        dgtid.append(responses[i]['EgressMatrixCell']['destinationSgtId'])
        sgaclid.append(responses[i]['EgressMatrixCell']['sgacls'])   
    
    return sgtid,dgtid,sgaclid

#to get sgtresponse and dgtresponse
def gtresponse(ip,b64Val,gtid):
    gtresp=[]
    for i in range(len(gtid)):
        try:
            r= requests.get('https://'+ip+'/ers/config/sgt/'+gtid[i],headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json","Accept": "application/json"}, verify=False)
            #print(r.text)
            json_data = json.loads(r.text)
            gtresp.append(json_data)
            #error handling
            r.raise_for_status()
        except requests.exceptions.Timeout as errt:
            print ("Timeout Error:",errt)
            exit(1)
        except requests.exceptions.ConnectionError as errc:
            print ("Error Connecting:",errc)
            exit(1)
        except requests.exceptions.HTTPError as errh:
            print ("Http Error:",errh)
            exit(1)
        except requests.exceptions.RequestException as err:
            print ("Oops: Something Else",err)
            exit(1)
    #print(gtresp)
    return(gtresp) 

#to get sgacllist and aclcontentlist
def sgaclresponse(ip,b64Val,sgaclid):
    sgaclresp=[]
    for i in sgaclid:
        responses=[]
        for l in i:
            try:
                r= requests.get('https://'+ip+'/ers/config/sgacl/'+l,headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json","Accept": "application/json"}, verify=False)
                json_data = json.loads(r.text)
                responses.append(json_data)
                #error handling
                r.raise_for_status()
            except requests.exceptions.Timeout as errt:
                print ("Timeout Error:",errt)
                exit(1)
            except requests.exceptions.ConnectionError as errc:
                print ("Error Connecting:",errc)
                exit(1)
            except requests.exceptions.HTTPError as errh:
                print ("Http Error:",errh)
                exit(1)
            except requests.exceptions.RequestException as err:
                print ("Oops: Something Else",err)
                exit(1)
        sgaclresp.append(responses)
    sgaclvallist=[]
    aclcontlist=[]
    
    for i in sgaclresp:
        if debug==1:
            print (i)
        sgaclval=[]
        aclcont=[]
        for j in i:
            #print(j)
            sgaclval.append(j['Sgacl']['name'])
            x=j['Sgacl']['aclcontent']
            k=x.split("\n")
            if len(k)==1:
                for z in k:
                    aclcont.append(z)
            else:
                aclcont.append(k) 
        sgaclvallist.append(sgaclval)
        aclcontlist.append(aclcont)
    if debug==1:
        print("SGACL: ",sgaclvallist)
        print("ACLCONTENT: ",aclcontlist)
    return sgaclvallist,aclcontlist

#function to return differences between 2 lists
def returnNotMatches(li1, li2): 
    return (list(set(li1) - set(li2)))

unknwnval=0
defaultval=0

print("Reading ISE Response")

un = ise_un # username of the ISE instance here
pw = ise_pw # password of the ISE instance here
ip = ise_ip # ip address of the ISE instance here

#encoding for the request to authorize access to the ISE instance
b64Val = encoder(un,pw)
#print(b64Val)

ids=[]
#Calls https://ip/ers/config/egressmatrixcell and returns all the id's
ids, check1 = egressconfig(ip,b64Val)
if ids!="error":
    responses=[]
    #Calls https://ip/ers/config/egressmatrixcell/id and returns all the matrix cell responses
    responses = egressresp(ids,ip,b64Val)
    #print(len(responses))

    sgtid=[]
    dgtid=[]
    sgaclid=[]
    #Extracts sgt-id, dgt-id, and sgacl-id
    sgtid,dgtid,sgaclid = idsresp(responses)
    #print(len(ids))
    #print(len(responses))
    if debug==1:
        print(len(sgtid), len(dgtid), len(sgaclid))

    sgtresp=[]
    #Calls https://ip/ers/config/sgt/sgtid to get sgt response
    sgtresp = gtresponse(ip,b64Val,sgtid)

    dgtresp=[]
    #Calls https://ip/ers/config/sgt/dgtid to get sgt response
    dgtresp = gtresponse(ip,b64Val,dgtid)

    #print(len(sgtresp),len(dgtresp))

    #extracting DGT's
    dgtval=[]
    for i in range(len(dgtresp)):
        dgtval.append(dgtresp[i]['Sgt']['value'])

    #extracting SGT's
    sgtval=[]
    for i in range(len(sgtresp)):
        sgtval.append(sgtresp[i]['Sgt']['value'])
    if debug==1:
        print(sgtval,dgtval)
        print(len(sgtval),len(dgtval))    

    sgaclval=[]
    aclcont =[]
    #Calls https://ip/ers/config/sgacl/sgaclid and returns sgacl and aclcontent
    sgaclval, aclcont= sgaclresponse(ip,b64Val,sgaclid)
    if debug==1:
        print(len(sgaclval),len(aclcont))

    print("generating ISE dataframe")

    #Create pandas dataframe for ISE and csv file apitable.csv
    set_option('display.max_colwidth', -1) #to display complete data frame
    df=DataFrame([responses[0]['EgressMatrixCell']])
    for i in range(1,len(responses)):
        df1=DataFrame([responses[i]['EgressMatrixCell']])
        df=concat([df,df1],sort='FALSE',ignore_index='TRUE')    
    
    name=[]
    defaultRule=[]
    for i in range(0,len(responses)):
        #print(responses[i])
        name.append(responses[i]['EgressMatrixCell']['name'])
        defaultRule.append(responses[i]['EgressMatrixCell']['defaultRule'])
        #print(responses[i]['EgressMatrixCell']['defaultRule'])
      
    #Removing columns that are not necessary
    del df['description']
    del df['link']
    del df['matrixCellStatus']
    
    #renaming columns
    df.columns = ['defaultRule','destinationSgtId','id','name','sgacls-id','sourceSgtId']

    #Removing columns that are not necessary
    del df['destinationSgtId']
    del df['id']
    del df['sgacls-id']
    del df['sourceSgtId']

    #adding sgtval column
    df['sgtval']=sgtval
    
    #adding dgtval column
    df['dgtval']=dgtval

    #print(df)

    df1=df

    x="sgaclval"
    list_flat,list_index=flat(eval(x))
    #print(list_flat,list_index)
    dataframe = DataFrame({x:list_flat},index=list_index)
    df1 = concat([df1,dataframe],axis=1,sort=False)

    x="aclcont"
    list_flat,list_index=flat(eval(x))
    #print(list_flat,list_index)
    dataframe = DataFrame({x:list_flat},index=list_index)
    df1 = concat([df1,dataframe],axis=1,sort=False)

    df1.columns=["defaultRule","name","sgtval","dgtval","sgacl","aclcont"]
    #print(df1)
    df1['aclcont'] = df1['aclcont'].astype(str)
    df1.drop_duplicates(keep="first",inplace=True)
    #print(df1)
    df1.to_csv('test1.csv')
    
    df['sgaclval']=sgaclval
    df['aclcont']=aclcont

    #inorder to drop duplicates in dataframe lists have to converted to string for conversion
    df['sgaclval'] = df['sgaclval'].astype(str)
    df['aclcont'] = df['aclcont'].astype(str)
    df.drop_duplicates(keep="first",inplace=True)

    j=-1
    for i,k in zip(df['name'],df['dgtval']):
        j=j+1
        if i=="ANY-ANY": #if name "ANY-ANY" if found in ISE table check if default permissions of ISE and network devices match
            defaultval = 1
            defperm = df['sgaclval'][j]
            defperm = ast.literal_eval(defperm)
        if k==0: #if DGT 0 is found in ISE table append 0 to sgtlist(lgt) of each network device 
            unknwnval = 1

#add ISE dataframe to the pdf            
a= array(df1)
#print(a)
li = ['defaultRule', 'name', 'sgtval', 'dgtval', 'sgacl', 'aclcont']
b = array(li)
#print(b)
p = vstack((b, a))
#print(p)
t1 = Table(array(p).tolist());
t1.setStyle(TableStyle([('GRID',(0,0),(-1,-1),1,colors.black),
                        ('TEXTCOLOR',(0,0),(-1,0),colors.red),
                        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')]))
doHeading("ISE",h1)
story.append(Spacer(1, 0.2 * inch))
story.append(t1)
story.append(PageBreak())

#----------------------------Telnet to network device connected to DNAC-------------------------------------------------

host=[]  #host device IP address
port=[]  #port number of device
un=[]    #username of device
pw=[]    #password of device
en_pw=[]  #enable password of device

f = open('telinput.txt','r') 
y=[]
for (x, line) in enumerate(f):
    if debug==1:
        print(x, line)
    if(int(x)%6==0):
        host.append(line.split('-')[1].strip())
    if(int(x)%6==1):
        port.append(line.split('-')[1].strip())
    if(int(x)%6==2):
        un.append(line.split('-')[1].strip())
    if(int(x)%6==3):
        pw.append(line.split('-')[1].strip())
    if(int(x)%6==4):
        en_pw.append(line.split('-')[1].strip())

if debug==1:
    print(host, port, un ,pw)
count = 0

for h,po,u,p,ep in zip(host,port,un,pw,en_pw):
    
    count=count+1
    print("telnetting to {}:{}".format(host,port))
    time.sleep(2)
    telnet = telnetlib.Telnet()
    telnet.open(h, po)

    #telnet to the device and press enter
    telnet.write(("\n").encode('ascii'))

    out=telnet.read_until(("y").encode('ascii'), 5)
    if debug==1:
        print("1",out)
    #When you telnet to the device you see this line. Escape character is '^]'. Press enter to get into switch
    telnet.write(("\r\n").encode('ascii'))

    #It asks for User access verification if user had logged out from switch.
    out=telnet.expect([b"Username: "], 5)
    if debug==1:
        print("2",out)

    #If it asks for username enter username
    if(out[1]!=None):      
        telnet.write((u + "\n").encode('utf-8'))
        #print(("cisco" + "\n").encode('utf-8'))

    #Next it asks for password
    out=telnet.expect([b"Password: "], 5)
    if debug==1:
        print("3",out)

    #If it asks for password enter password
    if(out[1]!=None):        
        telnet.write((p + "\n").encode('ascii'))
    
    #Login Success line appears and press enter
    telnet.write(("\n").encode('ascii'))

    #next we get switch>. So enable switch to get switch#.
    out=telnet.expect([b">"], 5)
    if debug==1:
        print("4",out)

    #type enable if switch> is found and press enter
    if(out[1]!=None):
        time.sleep(2)
        telnet.write(("\n").encode('ascii'))
        telnet.write(("enable \r\n").encode('ascii'))

    #It asks for enable password so enter password and press enter 
    out=telnet.expect([b"Password:", b"Password:"], 5)
    if debug==1:
        print("5",out)
    if(out[1]!=None):
        telnet.write((ep + "\n").encode('utf-8'))
        time.sleep(5)
    
    #this changes to switch#

    out=telnet.read_until(("#").encode('ascii'), 5) 
    if debug==1:
        print("6",out,"\n")

    telnet.write(("term len 0 \r\n").encode('ascii'))
    out=telnet.read_until(("#").encode('ascii'), 5)  
    if debug==1:
        print("7",out,"\n")

    #to get pac information of the device
    telnet.write(('show cts pac' + '\r\n').encode('ascii'))
    out = telnet.read_until(("#").encode('ascii'), 5)
    pac=out.decode('utf-8')
    if debug==1:
        print("PAC: ",repr(pac),"\n")                        
    l=pac.find('Credential Lifetime')
    if l==-1:
        pacinfo="No information found"
    else:
        pac=pac[l:]
        out1=pac.split("\n")
        pacinfo=out1[0]
    if debug==1:
        print(pacinfo)
        print("\n")
        
    #to  get sxp information of the device
    telnet.write(('show cts sxp connections' + '\r\n').encode('ascii'))
    out = telnet.read_until(("#").encode('ascii'), 5)
    output=out.decode('utf-8')
    if debug==1:
        print("SXP: ",repr(output),"\n")
    match = re.findall(r'\n\s(SXP)\s+:\s(\w+)\r\n',output)
    for el in match:
        sxp="{0} : {1}".format(el[0],el[1])
    sxpinfo=sxp
    if debug==1:
        print(sxpinfo,"\n")

    if defaultval==1:
        #to get default permissions of the device
        telnet.write(('sh cts role-based permission default' + '\r\n').encode('ascii'))
        out = telnet.read_until(("#").encode('ascii'), 5)
        output=out.decode('utf-8')
        if debug==1:
            print("Default: ",repr(output),"\n")
        res = re.findall(r'IPv4 Role-based permissions default:\r\n\t([a-zA-z _]+)-..',output)
        defperm = res
        if debug==1:
            print("Default permission: ",defperm,"\n")

    #to get vrf names of the device
    telnet.write(('sh vrf' + '\r\n').encode('ascii'))
    out = telnet.read_until(("#").encode('ascii'), 5)
    vrfresp=out.decode('utf-8')
    if debug==1:
        print("VRF Response: ",repr(vrfresp),"\n")
    names = re.findall("\n\s\s([\w+-]+)\s+", vrfresp, re.M | re.I)
    names = names[1:]
    if debug==1:    
        print("VRF: ",names,"\n")


    #to get sgts(local group tags) and ip addresses of the device
    sgtresp=[]
    for i in names:
        telnet.write(("sh cts role-based sgt-map vrf %s all" %i + '\r\n').encode('ascii'))
        out = telnet.read_until(("#").encode('ascii'), 5)
        output=out.decode('utf-8')                        
        sgtresp.append(output)
    telnet.write(("sh cts role-based sgt-map all" + '\r\n').encode('ascii'))
    out = telnet.read_until(("#").encode('ascii'), 5)
    output=out.decode('utf-8')                        
    sgtresp.append(output)
    sgtlist=[]
    sgtvrf=[]
    iplist=[]
    for i in sgtresp:
        if debug==1:
            print("SGT Response: ",repr(i))
        if(i.find('Active IPv4')==-1):
            sgtlist.append('')
            sgtvrf.append('')
            iplist.append('')
            continue
        sgt=[]
        ips=[]
        match=re.findall(r'\n(\d*\.\d*\.\d*\.\d*/?\d*?)\s+(\d+)',i)
        if debug==1:
            print(match)
        for i in match:
            sgt.append(i[1])
            ips.append(i[0])
        sgtvrf.append(sgt)
        sgt = list(dict.fromkeys(sgt)) #to remove duplicate sgts
        #print(sgt)
        sgtlist.append(sgt)
        iplist.append(ips)
    if unknwnval==1:
        sgtlist.append(['0'])
    if debug==1:
        print ("SGT: ",sgtlist,"\n IP: ",iplist,"\n SGTVRF: ",sgtvrf,"\n")

    #to get dgts, sgacls and acls
    dgtlist=[]
    sgacllist=[]
    acllist=[]
    for element in sgtlist:
        if not element:
            dgtlist.append('')
            sgacllist.append('')
            acllist.append('')
            continue
        dgt=[]
        sgacl=[]
        acl=[]
        for i in element:
            telnet.write(("sh cts role-based permission to %s" %i+ '\r\n').encode('ascii'))
            out = telnet.read_until(("#").encode('ascii'), 5)
            output=out.decode('utf-8')
            if debug==1:
                print("DGT Response: ",repr(output))
            sgacl1=[]
            acl1=[]     
            res = re.findall(r'IPv4 Role-based permissions from group ([a-zA-Z\d]+)',output) #extracting dgts
            for n, i in enumerate(res):
                if i == 'Unknown':
                    res[n] = '0'
            if debug==1:
                print(res)
            if not res:
                dgt.append('')
                sgacl.append('')
                acl.append('')
                continue
            dgt.append(res)
            res2 = output.split("IPv4")
            res2.pop(0)
            sgacl1=[]
            acl1=[]
            for i in res2:
                #print(i)
                res3 = re.findall(r'\(configured\):',i) #skip if configured is found
                #print(res3)
                if res3:
                    continue
                res4 = re.findall(r'\n\t([\w\d -]+)',i) #exctracting acl
                if debug==1:
                    print(res4)
                res5 = re.findall(r'\n\t([\w ]+)',i) #extracting sgacl
                if debug==1:    
                    print(res5)
                sgacl1.append(res5)
                acl1.append(res4)
            sgacl.append(sgacl1)
            acl.append(acl1)
            #print(dgt,sgacl,acl)
        dgtlist.append(dgt)
        sgacllist.append(sgacl)    
        acllist.append(acl)
    if debug==1:
        print("\n DGT(RGT): ",dgtlist,"\n SGACL: ", sgacllist, "\n ACL: ",acllist,"\n")        

    #to get acl content of the device
    telnet.write(("sh ip access-lists" + '\r\n').encode('ascii'))
    out = telnet.read_until(("#").encode('ascii'), 5)
    output=out.decode('utf-8')   
    l=output.find('Role-based IP access list')
    x=output[l:]
    #print("ACL Response: ",repr(x),"\n")
    z=x.split("\n")
    #print(z)
    aclcontlist=[]
    for el in acllist:
        #print("1",el)
        if not el:
            aclcontlist.append('')
            continue
        aclcont1=[]
        for el1 in el:
            #print("2",el1)
            if not el1:
                aclcont1.append('')
                continue
            aclcont=[]
            for el2 in el1:
                #print("3",el2)
                match=[]
                for el3 in el2:
                    #print("4",el3)
                    res1=[]
                    for i in z:
                        if el3 in i:
                            pos = z.index(i) 
                            for j in range(pos+1,len(z)):
                                if not z[j].startswith(' '):
                                    break
                                else:
                                    res = re.findall(r'\d+\s([a-z ]+)',z[j])
                                    #print(res)
                                    j=j+1
                                    res1.append(res[0].strip())
                    #print("0:",res1)
                    if len(res1)==1:
                        match.append(res1[0])
                    else:
                        match.append(res1)
                #print("3:",match)
                aclcont.append(match)
            #print("2:",aclcont)    
            aclcont1.append(aclcont)
        #print("1:",aclcont1)
        aclcontlist.append(aclcont1)
    if debug==1:
        print("ACLCONTENT:", aclcontlist)

    final_list = []
    for b, c, d, e in zip(sgtlist, dgtlist, sgacllist, aclcontlist):
        #print("1",b,c,d,e)
        if any([b, c, d, e]):
            for b1, c1, d1, e1 in zip(b, c, d, e):
                #print("2",c1,d1,e1)
                if any([c1,d1,e1]):
                    for c2, d2, e2 in zip(c1, d1, e1):
                        #print("3",c2,d2,e2)
                        for d3, e3 in zip(d2, e2):
                            final_list.append([b1, c2, d3, e3])
                else:
                    final_list.append([b1, c1, d1, e1])
        #else:
            #final_list.append([b, c, d, e])

    dfa3 = DataFrame(final_list, columns=['LGT', 'RGT', 'SGACL', 'ACLCONT'])
    dfa3['ACLCONT'] = dfa3['ACLCONT'].astype(str)
    dfa3.drop_duplicates(keep="first",inplace=True)
    dfa3.to_csv('test.csv')

    telnet.close()
    print("telent closed")
    
    names.append('Global')
    names.append('')

    #Create dataframe for all the data extracted from dnac
    dfa = DataFrame({"VRFNames":names})
    #print(dfa)

    x="sgtlist"
    list_flat,list_index=flat(eval(x))
    dataframe = DataFrame({x:list_flat},index=list_index)
    dfa = concat([dfa['VRFNames'],dataframe],axis=1,sort=False)
    sgtbig = list_flat
    #print(dfa)
    
    x="dgtlist"
    list_flat,list_index=flat(eval(x))
    #print(list_flat,list_index)
    dataframe = DataFrame({x:list_flat},index=list_index)
    dfa = concat([dfa,dataframe],axis=1,sort=False)
    dgtbig=list_flat
    #print(dfa)
    
    x="sgacllist"
    list_flat,list_index=flat(eval(x))
    #print (list_flat,list_index)
    dataframe = DataFrame({x:list_flat},index=list_index)
    dfa = concat([dfa,dataframe],axis=1,sort=False)
    #print(dfa)
    
    x="aclcontlist"
    list_flat,list_index=flat(eval(x))
    #print (list_flat,list_index)
    dataframe = DataFrame({x:list_flat},index=list_index)
    dfa = concat([dfa,dataframe],axis=1,sort=False)
    #print(dfa)

    dfa.columns=["VRFNames","LGT","RGT","SGACL","ACLCONT"]

    del dfa["VRFNames"]
    
    dfa['SGACL'] = dfa['SGACL'].astype(str)
    dfa['RGT'] = dfa['RGT'].astype(str)
    dfa['ACLCONT'] = dfa['ACLCONT'].astype(str)
    dfa.drop_duplicates(keep="first",inplace=True)
    #print(dfa)

    del names[-1]
    
    dfa1= DataFrame({"VRFNames":names})
        
    x="iplist"
    list_flat,list_index=flat(eval(x))
    dataframe = DataFrame({x:list_flat},index=list_index)
    dfa1 = concat([dfa1,dataframe],axis=1,sort=False)    
        
    x="sgtvrf"
    list_flat,list_index=flat(eval(x))
    #print (list_flat,list_index)
    dataframe = DataFrame({x:list_flat},index=list_index)
    dfa1 = concat([dfa1,dataframe],axis=1,sort=False)
    
    dfa1.columns=["VRFNames","IP","LGT"]
    dfa1.drop_duplicates(keep="first",inplace=True)
 
    print("Checking policies")
    
    set_option('display.max_colwidth', -1)
    output1={}
    output2={}
    set_option('display.max_colwidth', -1)
    res=[]
    res1=[]
    d=[]
    for a,c in zip(sgtbig,dgtbig):
        b=[]
        if a in d:
            continue
        if a:
            #print(a)
            d.append(a)
            b.append(a)
            df_temp = df1.loc[df1['dgtval'].isin(b)]
            df_temp.columns=['DF','name','SGT','DGT','SGACL','ACL_ISE']
            del df_temp['DF']
            del df_temp['name']
            columnsTitles=["DGT","SGT","SGACL","ACL_ISE"]
            df_temp=df_temp.reindex(columns=columnsTitles)
            df_temp = df_temp.sort_values(by=['SGT'])
            df_temp=df_temp.reset_index(drop=True)
            if debug==1:
                print(df_temp)
            df_temp1 = dfa3.loc[dfa3['LGT'].isin(b)]
            df_temp1.columns=['DGT','SGT','SGACL','ACL_device']
            df_temp1.sort_values(by=['SGT'])
            df_temp1=df_temp1.reset_index(drop=True)
            if debug==1:
                print(df_temp1)
            if not c:
                continue
            df_temp1['SGT']=df_temp1['SGT'].astype(int)
            df_temp1['DGT']=df_temp1['DGT'].astype(int)
            df_final1 = df_temp.merge(df_temp1, on=["DGT","SGT","SGACL"], how='outer')
            df_final1.columns=["1.DGT","2.SGT","3.SGACL","4.ACL_ISE","5.ACL_Device"]
            if debug==1:
                print(df_final1)
            di = df_final1.to_dict(orient='records')
            #print(di)
            table={}
            j=0
            for i in di:
                table.update({j:i})
                j=j+1
                #print(table)
                table = DataFrame(table)
                #print(table)
                def isNaN(num):
                    return num != num
            res.append(df_final1)
            res1.append(df_temp)
    output2=res1
    output1=res
    #print(dfa)

    #print(output2)
    #print(output1)
    
    out=[]
    yes=[]
    for a,b,c,d in zip(dfa['LGT'],dfa['RGT'],dfa['SGACL'],dfa['ACLCONT']):
        match=0
        if a=='':
            continue
        for e in df['dgtval']:
            #print(a,e)
            if(int(a)==e):  #comparing LGT with dgt
                #print(a,e)
                match=1
                if b:
                    b = ast.literal_eval(b)
                    for n in b:
                        if(isinstance(b, str)):
                            n.strip()
                if c:
                    #print(c)
                    c = ast.literal_eval(c)
                    for n in c:
                        #print(n)
                        if(isinstance(c, str)):
                            n.strip()
                if d:
                    #print(d)
                    d = ast.literal_eval(d)
                    for n in d:
                        #print(n)
                        if(isinstance(d, str)):
                            n.strip()
                f=[]
                g=[]
                h=[]
                for i,j,k,l in zip(df['dgtval'],df['sgtval'],df['sgaclval'],df['aclcont']):
                    if(i==e):                #comapring current dgt value with outer loop dgt value and if it matches
                        #print(i,e,type(i))
                        k = ast.literal_eval(k)
                        for n in k:
                            if(isinstance(k, str)):
                                n.strip()
                        l = ast.literal_eval(l)
                        for n in l:
                            #print(n)
                            if(isinstance(n, str)):
                                n.strip()
                        f.append(str(j))     #append all sgt, sgacl and aclcont that corresponds to dgt
                        g.append(k)
                        h.append(l)
                #print(f,b,g,c,h,d)        
                f, g, h = (list(t) for t in zip(*sorted(zip(f, g, h))))
                #print(type(f),type(b),type(g),type(c),type(h),type(d))
                f, g, h = (list(t) for t in zip(*sorted(zip(f, g, h))))
                b, c, d = (list(t) for t in zip(*sorted(zip(b, c, d))))
                if debug==1:
                    print("final", f,b,g,c,h,d)
                if(f==b):   #check if all sgt is there in device ie sgt==rgt
                    if(g==c and h==d): #check if all sgacl and aclcont is there in device ie sgacl==SGACL and acl==ACLCONT
                        #print("policy %s download okay"%a)
                        if a=='0':
                            out.append("policy 'unknown' download okay")
                            if debug==1:
                                print("policy 'unknown' download okay")
                        else:
                            out.append("policy %s download okay"%a)
                            if debug==1:
                                print("policy %s download okay"%a)
                        yes.append('')
                        break
                    else: #if sgacl didnt match SGACL print the missing acls in SGACL
                        match1=returnNotMatches(g,c)
                        if not match1:
                            match1=returnNotMatches(c,g)
                        if a=='0':
                            out.append("policy 'unknown' download not okay as these acl's are missing: {}".format(match1))
                            if debug==1:
                                print("policy 'unknown' download not okay as these acl's are missing: {}".format(match1))
                        else:    
                            out.append("policy {} download not okay as these acl's are missing: {}".format(a,match1))
                            if debug==1:
                                print("policy {} download not okay as these acl's are missing: {}".format(a,match1))
                    break
                else: #if sgt didnt match rgt print missing sgt in rgt
                    match1=returnNotMatches(f,b)
                    if not match1:
                        match1=returnNotMatches(b,f)
                    if a=='0':
                        out.append("policy 'unknown' download not okay as these remote group tags (source) are missing: {}".format(match1))
                        if debug==1:
                            print("policy 'unknown' download not okay as these remote group tags (source) are missing: {}".format(match1))
                    else:
                        out.append("policy {} download not okay as these remote group tags (source) are missing: {}".format(a,match1))
                        if debug==1:
                            print("policy {} download not okay as these remote group tags (source) are missing: {}".format(a,match1))
                break
        #print(match)
        if match == 0: #LGT wasnt found in dgt list at all
            if a=='0':
                out.append("policy 'unknown' download not okay as {} local group tag (dest) is missing".format(a))
                if debug==1:
                    print("policy 'unknown' download not okay as {} local group tag (dest) is missing".format(a))
            else:
                out.append("policy {} download not okay as {} local group tag (dest) is missing".format(a,a))
                if debug==1:
                    print("policy {} download not okay as {} local group tag (dest) is missing".format(a,a))
    out1=out
    if(len(yes)==len(out)):
        success="success"
    else:
        success="failed"
        
    if debug==1:
        print(success)
    print("generating pdf")

#========================================pdf generation=====================================================

    if success=="failed":
        doHeading("DEVICE %s"%count,h3)
    else:
        doHeading("DEVICE %s"%count,h2)
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(pacinfo,style1))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(sxpinfo,style1))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("ISE",style))
    story.append(Spacer(1, 0.2 * inch))
    li = ['DGT','SGT','SGACL_ISE','ACL_ISE']
    b = array(li)
    #print(b)
    for k in output2:
        a= array(k)
        # print(a)
        p = vstack((b, a))
        #print(p)
        t2 = Table(array(p).tolist());
        #print(t2)
        t2.setStyle(TableStyle([('GRID',(0,0),(-1,-1),1,colors.black),
                        ('TEXTCOLOR',(0,0),(-1,0),colors.red),
                        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')]))
        story.append(t2)
        story.append(Spacer(1, 0.1 * inch))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Network Device",style))
    story.append(Spacer(1, 0.2 * inch))
    a=array(dfa1)
    #print(a)
    li = ['VRFNames','IP','LGT']
    b=array(li)
    #print(b)
    p = vstack((b,a))
    #print(p)
    t3 = Table(array(p).tolist());
    t3.setStyle(TableStyle([('GRID',(0,0),(-1,-1),1,colors.black),
                        ('TEXTCOLOR',(0,0),(-1,0),colors.red),
                        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')]))
            #print(t3)
    a=array(dfa3)
    li = ['LGT','RGT','SGACL','ACLCONT']
    b=array(li)
    p = vstack((b,a))
    t4 = Table(array(p).tolist());
    t4.setStyle(TableStyle([('GRID',(0,0),(-1,-1),1,colors.black),
                        ('TEXTCOLOR',(0,0),(-1,0),colors.red),
                        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')]))
    story.append(t3)
    story.append(Spacer(1, 0.1 * inch))
    story.append(t4)
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("ISE/Device consistency comparison",style))
    story.append(Spacer(1, 0.2 * inch))
    li = ['DGT','SGT','SGACL','ACL_ISE','ACL_Device']
    b = array(li)
    #print(b)
    for l in out1:
        story.append(Paragraph(l,style2))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Spacer(1, 0.2 * inch))
    for k in output1:
        s=[]
        #print(k)
        dfb = k[isNaN(k['5.ACL_Device'])].index.values.astype(int)
        #print(dfb)
        dfb1=(k[isNaN(k['4.ACL_ISE'])].index.values.astype(int))
        #print(dfb1)
        a= array(k)
        # print(a)
        p = vstack((b, a))
        #print(p)
        t5 = Table(array(p).tolist());
        #print(t5)
        t5.setStyle(TableStyle([('GRID',(0,0),(-1,-1),1,colors.black),
                        ('TEXTCOLOR',(0,0),(-1,0),colors.red),
                        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold')]))
        if dfb.size>0:
            for i in dfb:
                #print(i+1)
                t5.setStyle(TableStyle([('BACKGROUND',(4,i+1),(4,i+1),colors.red)]))
        if dfb1.size>0:
            for j in dfb1:
                #print(j+1)
                t5.setStyle(TableStyle([('BACKGROUND',(3,j+1),(3,j+1),colors.red)]))
        #print(t5)
        for ix in k.index:
            if isNaN(k.loc[ix]['4.ACL_ISE']) or isNaN(k.loc[ix]['5.ACL_Device']):
                continue
            if not k.loc[ix]['4.ACL_ISE']==k.loc[ix]['5.ACL_Device']:
                s.append(ix)
            if s:
                for i in s:
                    t5.setStyle(TableStyle([('BACKGROUND',(3,i+1),(4,i+1),colors.yellow)]))
        story.append(t5)
        story.append(Spacer(1, 0.1 * inch)) 
    story.append(Spacer(1, 0.2 * inch))
    story.append(PageBreak())
    
doc = MyDocTemplate('teltable.pdf')    

doc.multiBuild(story)
print('"teltable.pdf" is ready to view')
