import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output, Event
#parsing the time_mod values
import datetime
from dateutil import parser
import pandas as pd

import plotly.plotly as py
import plotly.graph_objs as go

import paramiko

server_source = 'server source for cronjob'
local_destination = 'local destination for cron job'

app = dash.Dash()
ssh_client=paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
f=open("password.txt",'rb')
pw=f.read()
ssh_client.connect(hostname='bgl-ads-4055',username='sausuvar',password=pw)
ftp_client=ssh_client.open_sftp()
ftp_client.get(server_source,local_destination)
ftp_client.close()
paramiko.util.log_to_file("filename.log")
    

df = pd.read_csv('schedule_data.csv')

x_list=[]
sample_val = df['time_mod'].unique()
trace={}
k= df[df['time_mod']==sample_val[0]]


for j in range(0,len(sample_val)):
	dobj = parser.parse(sample_val[j])
	dval= datetime.datetime.strftime(dobj,"%y-%m-%d %H:%M:%S")
	x_list.append(dval)
dat=[]
for j in range(0,len(k)):
	y_list0=[]
	for i in range(0,len(x_list)):
		y0=df[(df['time_mod']==sample_val[i]) & (df['nw_device']==k.iloc[j]['nw_device']) & (df['port']==k.iloc[j]['port'])]
		if y0['input_rate'].empty:
			y_list0.append(0)
		else:	
			y_list0.append(int(y0['input_rate']))
	trace0=go.Scatter(x = x_list,y = y_list0,mode = 'lines+markers',name = k.iloc[j]['nw_device'] + ':' + k.iloc[j]['port'])
	dat.append(trace0)

print len(dat)
fh = open("hello.txt","w")
fh.write(str(dat))
fh.close()

app.layout = html.Div(children=[
    html.H1(children='User Usage Dashboard',
        style={
            'textAlign': 'center',
        }),

    html.Div(children='''A dashboard showing the utilization by different users.''',style={
            'textAlign': 'center',
        }),

    dcc.Graph(
        id='example-graph',
        figure={
            'data': dat,

        },
        config={'editable': False, 'modeBarButtonsToRemove': ['sendDataToCloud']}
    ),
html.Div(id='intermediate-value', style={'display': 'none'}),
dcc.Interval(id='refresh', interval=60),]

)


@app.callback(Output('example-graph', 'figure'), [Input('intermediate-value', 'children')], events=[Event('refresh', 'interval')])
def update_graph(value):
	ssh_client=paramiko.SSHClient()
	ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	f=open("password.txt",'rb')
	pw=f.read()
	ssh_client.connect(hostname='bgl-ads-4055',username='sausuvar',password=pw)
	ftp_client=ssh_client.open_sftp()
	ftp_client.get('/users/sausuvar/user_usage/schedule_data.csv','C:/Users/sausuvar/Documents/schedule_data.csv')
	ftp_client.close()
	paramiko.util.log_to_file("filename.log")
	    

	df = pd.read_csv('schedule_data.csv')

	x_list=[]
	sample_val = df['time_mod'].unique()
	trace={}
	k= df[df['time_mod']==sample_val[0]]


	for j in range(0,len(sample_val)):
		dobj = parser.parse(sample_val[j])
		dval= datetime.datetime.strftime(dobj,"%y-%m-%d %H:%M:%S")
		x_list.append(dval)
	dat=[]
	for j in range(0,len(k)):
		y_list0=[]
		for i in range(0,len(x_list)):
			y0=df[(df['time_mod']==sample_val[i]) & (df['nw_device']==k.iloc[j]['nw_device']) & (df['port']==k.iloc[j]['port'])]
			if y0['input_rate'].empty:
				y_list0.append(0)
			else:	
				y_list0.append(int(y0['input_rate']))
		trace0=go.Scatter(x = x_list,y = y_list0,mode = 'lines+markers',name = k.iloc[j]['nw_device'] + ':' + k.iloc[j]['port'])
		dat.append(trace0)
	return {
        'data': dat,
    	}



if __name__ == '__main__':
    app.run_server(debug=True)