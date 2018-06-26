# PriD

[Detailed documentation on Jive](https://cisco.jiveon.com/docs/DOC-1962482)

This folder contains that django application for the PriD Application.

##### Requirements
  - Python 2.7  
  - Django 1.9
  - Requests 
  - DNAC instance up and running 
  - Ise instance up and running
  - AD that is synced with the ISE

# Steps to Run the Application

  - From the PriD directory (```manage.py``` should in the directory) run ```python manage.py migrate``` 
  - Fill in the values of the variables in ```views.py``` in PriD -> SAP
  - To start the server run ```python manage.py runserver 127.0.0.1:8000```
  - Navigate to (https://127.0.0.1:8000/index)
 


Points to be noted:
  - We are asssuming a host is up and running. 
  - The pre requisistes as given in the Jive page are present. 
  - The COA functionalities have been commented out. You will have to uncomment them. 
  - The email trigger is based on a manual trigger right now. however you can configure your own mail server to provide the trigger. 