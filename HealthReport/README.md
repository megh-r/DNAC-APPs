# Health Report and Reachability Status Generation

This folder contains that Python scripts and the sample outputs of the Health Report Generation and the Reachability Status Generation.

##### Requirements
  - Python 2.7  
  - Requests 
  - DNAC instance up and running

# Steps to Run the Application

  - Run ```healthReport.py``` to generate a pdf containing the health report of the devices connected to the DNAC 
  - Fill in the values of the variables in ```views.py``` in PriD -> SAP
  - To start the server run ```python manage.py runserver 127.0.0.1:8000```
  - Navigate to (https://127.0.0.1:8000/index)
 

Points to be noted:
  - ```auth.csv``` has the login credentials of all the devices with three columns. 
     1. un is the username
     2. pw is the password
     3. enpw is the enable password.  
  - The current working telnets into the deivce however, you can use the command runner API to perform the same functionality. More information is given here [Jive Page](https://cisco.jiveon.com/docs/DOC-1963052)
  