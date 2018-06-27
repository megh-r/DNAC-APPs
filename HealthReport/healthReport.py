#packages required for making requests and processing responses
import requests, base64, json, sys


#packages required for handling large data
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

#package required to suppress warnings about not having SSL certificate verification
from requests.packages.urllib3.exceptions import InsecureRequestWarning
#command to suppress warning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

'''

ENTER YOUR DNAC INSTANCE CREDENTIALS BELOW


'''

un = 'username' # enter the username of the DNAC instance here
pw = 'password' # enter the password of the DNAC instance here
ip = 'ip address' # enter the ip address of the DNAC instance here


#encoding for the request to authorize acces to the DNAC instance
encodedvalue=un+":"+pw
b64Val = base64.b64encode(encodedvalue.encode('UTF-8')).decode('utf-8')

try:

    r=requests.get('https://'+ ip +'/api/system/v1/auth/login', headers={"Authorization": "Basic %s" % b64Val,"Content-Type": "application/json"}, verify=False)

#error handling 

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

#getting the cookie value from the returned header to set authentication for the rest of the session
a=r.headers['Set-Cookie'].split(";")
b=a[0].split("=")
c=b[1]
cookie = {'X-JWT-ACCESS-TOKEN':c}

#packages for writing to PDF and generating the index with clickable links
from reportlab.platypus import Paragraph, Spacer, Image, PageBreak, Table, TableStyle, SimpleDocTemplate
from reportlab.platypus.doctemplate import BaseDocTemplate, PageTemplate
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, inch
from reportlab.rl_config import defaultPageSize
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.platypus.frames import Frame

#packages for calculating uptime
from datetime import datetime
import os


#Setting the styles for the Index and rest of the PDF
styles = getSampleStyleSheet()
PAGE_HEIGHT=defaultPageSize[1]
PAGE_WIDTH=defaultPageSize[0]

#name of pdf to be generated
filename = 'Health_Report.pdf'

class MyDocTemplate(BaseDocTemplate):

    def __init__(self, filename, **kw):
        self.allowSplitting = 0
        BaseDocTemplate.__init__(self, filename, **kw)
        self.pagesize = defaultPageSize

    def afterFlowable(self, flowable):
        "Registers TOC entries."
        if flowable.__class__.__name__ == 'Paragraph':

            text = flowable.getPlainText()
            style = flowable.style.name
            if style == 'Heading1':
                level = 0
            elif style == 'Heading2':
                level = 1
            else:
                return
            E = [level, text, self.page]
            #if we have a bookmark name, append that to our notify data
            bn = getattr(flowable,'_bookmarkName',None)
            if bn is not None: E.append(bn)
            self.notify('TOCEntry', tuple(E))



def titlePage(canvas, doc):
    canvas.saveState()
    canvas.setFont('Times-Bold', 22)
    canvas.drawCentredString(PAGE_WIDTH/2, PAGE_HEIGHT/2 + 4*12, "Model Test Report")
    canvas.setFont('Times-Bold', 20)
    canvas.drawCentredString(PAGE_WIDTH/2, PAGE_HEIGHT/2 - 6*12, model_type)
    canvas.setFont('Times-Roman', 16)
    canvas.drawCentredString(PAGE_WIDTH/2, PAGE_HEIGHT/2 - 10*12, date)
    canvas.restoreState()

def contentPage(canvas, doc):    
    canvas.saveState()   
    canvas.setFont('Times-Roman', 12)
    canvas.drawString(inch, 0.75*inch, "Page %d" %(doc.page))
    canvas.restoreState()


def doHeading(text,sty):
    from hashlib import sha1
    #create bookmarkname
    bn=sha1(text+sty.name).hexdigest()
    #modify paragraph text to include an anchor point with name bn
    h=Paragraph(text+'<a name="%s"/>' % bn,sty)
    #store the bookmark name on the flowable so afterFlowable can see this
    h._bookmarkName=bn
    parts.append(h)


df = pd.DataFrame() 
#list of only the information we need
lis=['type','errorCode','family','managementIpAddress','platformId','reachabilityFailureReason','reachabilityStatus','role','lastUpdated','softwareType','errorDescription','softwareVersion','macAddress','upTime','hostname','serialNumber','id']

try:
    r= requests.get('https://'+ip+'/api/v1/network-device',cookies=cookie,verify=False)
#error handling
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

#writing the response to JSON and CSV formats
obj = json.loads(r.text)
with open('devices.json', 'w') as outfile:
    json.dump(obj['response'], outfile)
train = pd.DataFrame(obj['response'])
train.to_csv('devices.csv')

#getting the host information
tg='https://'+ ip +'/api/v1/host'
    
try:
    r= requests.get(tg,cookies=cookie,verify=False)
    #error Handling
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

#writing the response to JSON and CSV formats
objh = json.loads(r.text)
with open('hosts.json', 'w') as outfile:
    json.dump(objh['response'], outfile)
outfile.close()
train = pd.DataFrame(objh['response'])
train.to_csv('hosts.csv')
del train

#starting the document for final PDF
doc = MyDocTemplate(filename)
frameT = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
doc.addPageTemplates([PageTemplate(id='TitlePage', frames=frameT ), PageTemplate(id='ContentPage', frames=frameT)])
parts = []
toc = TableOfContents()
#defining styles
style = ParagraphStyle(
        name='Normal',
        fontName='Helvetica',
        fontSize=9,
    )
centered = ParagraphStyle(name = 'centered',
            fontSize = 20,
            leading = 16,
            alignment = 1,
            spaceAfter = 20)

h1 = ParagraphStyle(name = 'Heading1',
            fontSize = 14,
            fontName='Helvetica-Bold',
            alignment = 1,)


h2 = ParagraphStyle(name = 'Heading2',
            fontSize = 12,
            leading = 14)
stylet = ParagraphStyle(
name='title',
fontName='Helvetica-Bold',
fontSize=14,
alignment = 1,
)
styleh = ParagraphStyle(
name='title',
fontName='Helvetica-Bold',
fontSize=12,
)

i=1
parts.append(Paragraph('<b>Health Report</b>', centered))
toc.levelStyles = [
            ParagraphStyle(fontName='Times-Bold', fontSize=14, name='TOCHeading1',
            leftIndent=20, firstLineIndent=-20, spaceBefore=5, leading=16),
            ParagraphStyle(fontSize=12, name='TOCHeading2',
            leftIndent=40, firstLineIndent=-20, spaceBefore=0, leading=12),
            ]
parts.append(toc)
parts.append(PageBreak())
for dic in obj['response']:
    data = []
            
    ipadd=dic['managementIpAddress']
    doHeading("Device "+ str(i)+"     -    "+str(ipadd), h1)

    parts.append(Spacer(1,2*cm))
    i=i+1;
    for key,val in sorted(dic.items()):
        if key in lis:
            data.append([Paragraph(key,style),Paragraph(":   "+str(val),style)])                    
        if key=='managementIpAddress':
            t=val
            device=val                  
        #getting uptime in hours    
        if key=='upTime':
            if val == None:
                uptime=0
            else:
                up=val.split(" ")
                uptm=up[-1].split(':')
                if 'days' in up[0]:
                    x=up[0][:-4]
                    upt=int(x)*24 + int(uptm[0])
                else:
                    if up[0]!= up[-1]:
                        upt=int(up[0])*24+int(uptm[0])
                    else:
                        upt=int(uptm[0])
                
            uptime=upt
    df = df.append({'Device':device, 'Uptime (In hours)':uptime}, ignore_index=True)
    tbl = Table(data)
    tbl.setStyle(TableStyle([('VALIGN', (0, 0), (1, 0), 'TOP')])) 
    parts.append(tbl)
    parts.append(Spacer(1, 0.2 * inch))    
    parts.append(Paragraph("\n\n\tHOSTS:\n", styleh))

    flag=0
    for dich in objh['response']:
        if dich['connectedNetworkDeviceIpAddress']==t:
            hdat=[]
            parts.append(Spacer(1, 0.2 * inch))
            for keyh,valh in dich.items():
                hdat.append([keyh,":  "+valh])
            htbl = Table(hdat)
            htbl.setStyle(TableStyle([('VALIGN', (0, 0), (1, 0), 'TOP')])) 
            parts.append(htbl)
            flag=1
    if flag==0:
        parts.append(Spacer(1, 0.2 * inch))
        parts.append(Paragraph("\tNo hosts Connected to Device", style))
    parts.append(PageBreak())

#plotting comparison of uptime of differnet devices
df.set_index('Device', inplace=True)
df.plot.barh(figsize=(20,10))
plt.savefig('fig.jpg')
#saving the plot as summary
parts.append(PageBreak())
parts.append(Paragraph("SUMMARY",stylet))
parts.append(Spacer(1, 0.1 * inch))
I=Image('fig.jpg')
parts.append(I)
I.drawHeight =  12*cm
I.drawWidth = 20*cm
del df    
#building final pdf
doc.multiBuild(parts)
f=open('fig.jpg','rb')
f.close()
os.remove(f.name)