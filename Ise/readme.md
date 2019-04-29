ISE DNAC Network Devices Consistency Checker

This folder contains the Python scripts and the sample outputs of the ISE and DNAC Network devices Consistency check.

Requirements

Python 3.7

Steps to Run the Application

Run policy.py to generate a pdf containing the consistency report of the devices connected to the DNAC with ISE.
Run tel.py to generate a pdf containing the cosistency report of the devices (by telnetting to them) with ISE

Points to be noted:

"table.pdf" is the pdf generated from the policy.py code.
"teltable.pdf" is the pdf generated from the tel.py code.

input.txt has the login credentials of DNAC and ISE instance. Same format should be followed to enter login credentials.
For detailed output of each function type 'yes' in debug mode.

telinput.txt has the login credentials of devices to telnet. Same format should be followed to enter login credentials.
telinput1.txt has the login credentials of ISE and input to debug mode.

ISE DNAC Network Devices Consistency Check is the document that explains procedure to be followed to generate the final pdf.
