tn = telnetlib.Telnet("enter IP address")

TELNET_PROMPT = ">"
ENABLE_PROMPT = "#"
TIMEOUT = 5

tn.write("\n")

tn.read_until(ENABLE_PROMPT, TIMEOUT)
tn.write("term len 0" + "\r\n")
tn.read_until(ENABLE_PROMPT, TIMEOUT)
tn.write("write command here")
output = tn.read_until(ENABLE_PROMPT, TIMEOUT)
print output