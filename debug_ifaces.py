from scapy.arch.windows import get_windows_if_list
from scapy.all import conf

ifaces = get_windows_if_list()
print('Sample interface from get_windows_if_list:')
print(ifaces[0])
print('\nGUID mapping (first 3):')
for iface in ifaces[:3]:
    print(f"{iface.get('name')} -> {iface.get('guid')}")

print('\nconf.ifaces keys:')
print(list(conf.ifaces.keys())[:5])

print('\nconf.ifaces values (interfaces) - first 2:')
for key in list(conf.ifaces.keys())[:2]:
    iface_obj = conf.ifaces[key]
    print(f"Key: {key} -> Name: {iface_obj.name if hasattr(iface_obj, 'name') else 'N/A'}")

# Check if guid appears in conf.ifaces keys
print('\nChecking if GUIDs match:')
for iface in ifaces[:3]:
    guid = iface.get('guid')
    if guid:
        guid_with_braces = f"{{{guid.strip('{}')}}}"
        print(f"GUID {guid} -> search for {guid_with_braces} in conf.ifaces: {guid_with_braces in conf.ifaces}")
