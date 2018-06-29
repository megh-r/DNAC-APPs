from apscheduler.schedulers.blocking import BlockingScheduler
import sys, os, json, csv, telnetlib, time, pytz
from datetime import datetime

def some_job():
	d=dict()
	fil = open("hosts.json","rb") 
	strdata = fil.read()
	expdata = json.loads(strdata)
	for host in expdata:
	    interface = host['connectedInterfaceName']
	    ip = host['connectedNetworkDeviceIpAddress']
	    if ip in d:
	        d[ip].append(interface)
	    else:
	        d[ip]=[interface]
	for nwdevice, ip in d.iteritems():
	    ip = list(set(ip))
	    d[nwdevice]=ip
	time_mod = datetime.now(pytz.timezone('Asia/Calcutta'))
	for nwdevice, ports in d.iteritems():
	    tn = telnetlib.Telnet(str(nwdevice))
	    TELNET_PROMPT=">"
	    ENABLE_PROMPT="#"
	    TIMEOUT=5
	    
	    tn.write("\n")
	    un= 'cisco'
	    pw= 'cisco'
	    tn.read_until("Username: ",2)
	    tn.write(un + "\r\n")
	    tn.read_until("Password: ",2)
	    tn.write(pw + "\r\n")
	    #print "Username : "+un+" Password : "+pw
	    tn.read_until(ENABLE_PROMPT, TIMEOUT)
	    tn.write("term len 0" + "\r\n")
	    tn.read_until(ENABLE_PROMPT, TIMEOUT)
	    for port in ports:
	        tn.write("show int "+str(port)+" | include minute input rate\n")
	        t=tn.read_until(ENABLE_PROMPT, 5)
	        ten=t.split(" ")
	        index_element = ten.index('bits/sec,') 
	        input_rate = int(ten[index_element-1])
	        packets = int(ten[index_element+1])        
	        data=[nwdevice,port,input_rate,packets,time_mod]
	        with open('schedule_data.csv', 'ab') as f:
	            writer = csv.writer(f)
	            writer.writerow(data)

scheduler = BlockingScheduler()
scheduler.add_job(some_job, 'interval', minutes=10)
scheduler.start()