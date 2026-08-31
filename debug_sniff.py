from scapy.all import conf

iface_obj = list(conf.ifaces.values())[2]
print('Interface object:')
print(f'  Name: {iface_obj.name}')
print(f'  Name type: {type(iface_obj.name)}')
print(f'  Dir: {[x for x in dir(iface_obj) if not x.startswith("_")]}')
print(f'  Str: {str(iface_obj)}')

# Try to see if there's a better identifier
print('\nConf.ifaces key for this interface:')
for key, val in conf.ifaces.items():
    if val == iface_obj:
        print(f'  Key: {key}')
        break

# Try a simple sniff to see what works
print('\nTrying to figure out the right iface parameter for sniff()...')
print('Scapy documentation suggests using the interface name or the entire interface object.')
print(f'  iface_obj.name would be: {iface_obj.name}')
print(f'  The GUID key would be: {key}')
