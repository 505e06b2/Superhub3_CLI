#https://mibs.observium.org/mib/ARRIS-ROUTER-DEVICE-MIB/
#https://mibs.observium.org/mib/ARRIS-CM-DEVICE-MIB/

base_mib = "1.3.6.1.4.1.4115.1.20."

mib_dict = {
	"ssid_2.4ghz": base_mib + "1.1.3.22.1.2.10001",
	"ssid_5ghz": base_mib + "1.1.3.22.1.2.10101",

	#I can only assume these are for the first rule in the IPv4 port filter list
	"source_ip_start": base_mib + "1.1.4.47.1.1.6.1",
	"source_ip_end": base_mib + "1.1.4.47.1.1.7.1",

	"destination_ip_start": base_mib + "1.1.4.47.1.1.10.1",
	"destination_ip_end": base_mib + "1.1.4.47.1.1.11.1",

	"port_filter_enabled": base_mib + "1.1.4.47.1.1.18.1",

	"apply": base_mib + "1.1.9.0=1;2"
}

mib_reverse_dict = {}
for key, value in mib_dict.items():
	mib_reverse_dict[value] = key
