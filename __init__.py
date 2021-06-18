#https://www.netscylla.com/blog/2019/02/04/Arris-CableModem-SNMP.html
#https://github.com/alexmartinio/vmsuperhub-smnp/blob/master/app.py

#a lot of these functions are not portable to other languages, since they rely on python dicts being in-order
#would have used urllib, but needed greater control

import requests, base64, random, time, html

from .mib import mib_dict, mib_reverse_dict

def parseIP(hex_string):
	return ".".join([str(int(hex_string[i:i+2], 16)) for i in range(1, len(hex_string), 2)]) #lol pythonic

def parseMac(hex_string):
	return ":".join([hex_string[i:i+2].lower() for i in range(1, len(hex_string), 2)]) #lol pythonic

#TO BE SAFE, MAKE SURE TO DEL ANY REFERENCES BEFORE EXIT or !!! use WITH !!!
class Superhub:
	#public
	def __init__(self, admin_password):
		self.enable_warnings = True
		self.http_address = "192.168.0.1"
		self.username = "admin"
		self.password = admin_password

		self.n_value = str(random.randint(1, 99999))
		self.cookie_string = ""
		self.last_login_time = 0

		self._login()
		if self.enable_warnings and not self.cookie_string:
			print("[WARN] Not logged in")

	def __enter__(self):
		if self.cookie_string: #logged in
			return self
		return None

	def get(self, oid):
		with self._manipulateOid("snmpGet", oid) as r:
			return r.json()

	def walk(self, oid):
		with self._manipulateOid("walk", oid) as r:
			return r.json()

	def set(self, oid):
		with self._generateRequest("snmpSet", {"oid": oid}) as r:
			return r.json()

	#General functions
	def getWiFiPasswords(self):
		values = [html.unescape(x) for x in self.get(mib_dict["password_5ghz"] + ";" + mib_dict["password_2.4ghz"]).values()]
		return {
			"5ghz": values[0],
			"2.4ghz": values[1]
		}

	def getThisMachineNetworkInfo(self):
		with self._generateRequest("checkConnType") as r:
			return r.json()

	def getConnectedDeviceInfo(self, target_ip=None):
		store = {}
		ret = {}
		with self._generateRequest("getConnDevices") as r:
			result = r.json()

		for key, value in result.items():
			split_ip = key.rsplit(".", 4)
			if len(split_ip) >= 4:
				ip = ".".join(split_ip[1:])
				if not store.get(ip):
					store[ip] = {}
				if key.startswith(mib_dict["device_mac"]):
					store[ip]["mac"] = parseMac(value)
				elif key.startswith(mib_dict["device_hostname"]) and value != "unknown":
					store[ip]["hostname"] = value
				elif key.startswith(mib_dict["device_name"]) and value != "unknown device": #seems to always be the case
					store[ip]["name"] = value
				elif key.startswith(mib_dict["device_online"]):
					store[ip]["online"] = True if value == "1" else False

		if target_ip:
			found = store.get(target_ip)
			if found:
				ret[target_ip] = found
		else:
			ret = store
		return ret

	#Port filter functions

	#this only supports a single local IP and not a range
	def getIndexOfPortFilter(self, ip_address):
		all_values = list(self.get(mib_dict["source_ip_start"]).values()) #get all
		for i in range(len(all_values)):
			x = all_values[i]
			if x: #not empty
				filter_ip = parseIP(x)
				if filter_ip == ip_address:
					return i
		return -1

	def countPortFilters(self):
		all_values = list(self.get(mib_dict["source_ip_start"]).values()) #get all
		for i in range(len(all_values)):
			x = all_values[i]
			if not x: #empty
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

	#private
	def __del__(self):
		if self.enable_warnings and self._logout() == False:
			print("[WARN] Did not log out")

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.__del__()

	def _generateRequest(self, path, param_dict={}):
		query = []
		for key, value in param_dict.items():
			query.append(f"{key}={value}")
		query.append(f"_n={self.n_value}")
		url = f"http://{self.http_address}/{path}?{'&'.join(query)}"
		#print(url)
		auth_cookie = {"credential": self.cookie_string} if self.cookie_string else {}
		return requests.get(url, cookies=auth_cookie) #status_code will be 401 if not logged in

	def _manipulateOid(self, path, oid):
		if isinstance(oid, list):
			oid = ";".join(oid)
		return self._generateRequest(path, {"oids": oid})

	def _login(self):
		credentials = base64.urlsafe_b64encode(f"{self.username}:{self.password}".encode()).decode()
		with self._generateRequest("login", {"arg": credentials}) as r:
			if r.status_code == 200 and r.content:
				self.cookie_string = r.content.decode()
				self.last_login_time = time.time()
				return True
		return False

	def _logout(self):
		if self.last_login_time != 0:
			self.last_login_time = 0
			with self._generateRequest("logout") as r:
				if r.status_code == 500: #for some reason seems to work with 500
					self.cookie_string = ""
					return True
				return False
