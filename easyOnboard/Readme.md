# EasyOnBoard

[Detailed documentation on Jive](https://cisco.jiveon.com/docs/DOC-1936987)

This folder contains that django application for the EasyonBoard Apllication.

##### Requirements
  - Python 2.7  
  - Django 1.9
  - Requests 
  - DNAC instance up and running 
  - Ise instance up and running
  - AD that is synced with the ISE

# Steps to Run the Application

  - From the easyOnboard directory (```manage.py``` should in the directory) run ```python manage.py migrate``` 
  - Fill in the values of the variables in ```views.py``` in easyOnboard -> project
  - To start the server run ```python manage.py runserver 127.0.0.1:8000```
  - Navigate to (https://127.0.0.1:8000/index)
 


Points to be noted:
  - For using the refresh option, the page has to be first refreshed. 
  - The logic of polling the response to find has not been implemented and instead a ```time.sleep()``` has been used. This may result in an error. To fix this error, check the steps that have been completed till now. If the authorization rules haven't been created yet, then the error must have been that we were trying to get the information before the DNAC finished pushing it. 

    1. Go to the DNAC and unlink the IP from the VN if it is linked
    2. Delete the VN using the API (https://<dnac-ip>/api/v2/data/customer-facing-service/VirtualNetwork/<vn-id>)
    3. Delete the IP Address pool created.
    4. Go to ISE and delete the SGTs created.


  - If the authorization rule has been created
    1. First delete the authorization rules created.
    2. Delete the autorization profile for the rule using api (https://<ise-ip>:9060/ers/config/authorizationprofile/<authorizationprofile-id>)
    3.  Go to the DNAC and unlink the IP from the VN if it is linked
    4.  Delete the VN using the API (https://<dnac-ip>/api/v2/data/customer-facing-service/VirtualNetwork/<vn-id>
    5.  Delete the IP Address pool created.
    6.  Go to ISE and delete the SGTs created.
    
After you are done with this, you can increase the ```time.sleep(60)``` on line 605 and try again.