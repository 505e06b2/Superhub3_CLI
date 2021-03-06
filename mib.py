#https://mibs.observium.org/mib/ARRIS-ROUTER-DEVICE-MIB/
#https://mibs.observium.org/mib/ARRIS-CM-DEVICE-MIB/

base_mib = "1.3.6.1.4.1.4115.1.20."

mib_dict = {
	"ssid_2.4ghz": base_mib + "1.1.3.22.1.2.10001",
	"ssid_5ghz": base_mib + "1.1.3.22.1.2.10101",

	"password_2.4ghz": base_mib + "1.1.3.26.1.2.10001",
	"password_5ghz": base_mib + "1.1.3.26.1.2.10101",

	"port_filter_entries": "1.3.6.1.4.1.4115.1.20.1.1.4.47.1", #walk
	#These are for the Xth rule in the IPv4 port filter list, the last digit is the index in the system - if a filter has been removed, the rest will shift down
	"source_ip_start": [base_mib + "1.1.4.47.1.1.6." + str(i) for i in range(1,10)],
	"source_ip_end": [base_mib + "1.1.4.47.1.1.7." + str(i) for i in range(1,10)],

	"destination_ip_start": [base_mib + "1.1.4.47.1.1.10." + str(i) for i in range(1,10)],
	"destination_ip_end": [base_mib + "1.1.4.47.1.1.11." + str(i) for i in range(1,10)],

	"port_filter_enabled": [base_mib + "1.1.4.47.1.1.18." + str(i) for i in range(1,10)],

	#getConnDevices - APPEND IP FOR DEVICE INFO
	"device_hostname": base_mib + "1.1.2.4.2.1.3.200.1.4.",
	"device_mac": base_mib + "1.1.2.4.2.1.4.200.1.4.",
	"device_online": base_mib + "1.1.2.4.2.1.14.200.1.4.",
	"device_name": base_mib + "1.1.2.4.2.1.20.200.1.4.",

	"apply": base_mib + "1.1.9.0=1;2"
}

mib_reverse_dict = {} #not needed if lib is fleshed out
"""
for key, value in mib_dict.items():
	if isinstance(value, list):
		for x in value:
			mib_reverse_dict[x] = key
	else:
		mib_reverse_dict[value] = key
"""
