# User Usage Dashboard
The user usage dashboard gets the information about the usage of the hosts connected to the DNAC. Cureently we are telnetting into the device(host) to get the information however the same could be done using the command runner API of the DNAC if you want information about the devices connected to the DNAC (this will not work on the hosts though). 
Refer the [Jive page](https://cisco.jiveon.com/docs/DOC-1963052) that has a detailed explaination of how to use the command runner API.

### Requirements: 
- Dash
- Paramiko or another SSH client
- Pandas
- Apscheduler or another scheduler to run a cron job
- Requests 

### File Structure:
1. The ```get_hosts.py``` file contains the code to get the list of all hosts in the network.
2. The ```dashboard_code.py``` file contains the dashboard code to run and refresh the results.
3. The ```extract_user_info.py``` file contains the code that you run periodically to poll for the data.

### Screenshot:
![alt text][logo]

[logo]:https://github.com/lmukund/DNAC-APPs/tree/master/userUsageDashboard/img/dashboard.JPG "User Usage Dashboard"