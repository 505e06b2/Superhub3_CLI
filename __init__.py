#https://www.netscylla.com/blog/2019/02/04/Arris-CableModem-SNMP.html
#https://github.com/alexmartinio/vmsuperhub-smnp/blob/master/app.py

import requests, base64, random, time

#would have used urllib, but needed greater control

from .mib import mib_dict, mib_reverse_dict

def parseIP(hex_string):
	return ".".join([str(int(hex_string[i:i+2], 16)) for i in range(1, len(hex_string), 2)]) #lol pythonic

class Superhub:
	def __init__(self, admin_password):
		self.http_address = "192.168.0.1"
		self.username = "admin"
		self.password = admin_password

		self.n_value = str(random.randint(1, 99999))
		self.cookie_string = ""
		self.last_login_time = 0

		self._login()

	def get(self, oid):
		return self._manipulateOid("snmpGet", oid).json()

	def walk(self, oid):
		return self._manipulateOid("walk", oid).json()

	def set(self, oid):
		return self._generateRequest("snmpSet", {"oid": oid}).json()

	#Port filter functions
	def getIndexOfPortFilter(self, ip_address):
		all_values = list(self.get(mib_dict["source_ip_start"]).values()) #get all
		for i in range(len(all_values)):
			x = all_values[i]
			if x: #not empty
				filter_ip = parseIP(x)
				if filter_ip == ip_address:
					return i
		return -1

	def getPortFilterState(self, index):
		value = list(self.get(mib_dict['port_filter_enabled'][index]).values())
		if len(value) < 1:
			return None
		return True if value[0] == "1" else False

	def setPortFilterState(self, index, state):
		ret = self.set(f"{mib_dict['port_filter_enabled'][index]}={1 if state else 2};2;") #1 = On, 2 = Off, 6 = Delete
		self.set(mib_dict["apply"])
		return ret

	def __del__(self):
		self._logout()

	def _generateRequest(self, path, param_dict={}):
		query = []
		for key, value in param_dict.items():
			query.append(f"{key}={value}")
		query.append(f"_n={self.n_value}")
		url = f"http://{self.http_address}/{path}?{'&'.join(query)}"
		#print(url)
		auth_cookie = {"credential": self.cookie_string} if self.cookie_string else {}
		return requests.get(url, cookies=auth_cookie)

	def _manipulateOid(self, path, oid):
		if isinstance(oid, list):
			oid = ";".join(oid)
		return self._generateRequest(path, {"oids": oid})

	def _login(self):
		credentials = base64.urlsafe_b64encode(f"{self.username}:{self.password}".encode()).decode()
		r = self._generateRequest("login", {"arg": credentials})
		if r.status_code == 200 and r.content:
			self.cookie_string = r.content.decode()
			self.last_login_time = time.time()
			return True
		return False

	def _logout(self):
		if self.cookie_string:
			r = self._generateRequest("logout")
			if r.status_code == 500: #for some reason seems to work with 500
				self.cookie_string = ""
				self.last_login_time = 0
				return True
			return False
		return True
