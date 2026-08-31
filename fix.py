import pathlib
import sys

p = pathlib.Path('routes/api.py')
text = p.read_text('utf-8')

start_idx = text.find('@api.route("/api/interfaces")')
end_idx = text.find('@api.route("/api/capture/start")')

if start_idx == -1 or end_idx == -1:
    print("Cannot find indices!")
    sys.exit(1)

new_func = '''@api.route("/api/interfaces")
def get_interfaces():
    try:
        from scapy.all import conf
        result = []
        for k, v in conf.ifaces.items():
            ident = getattr(v, "network_name", getattr(v, "name", str(k)))
            desc = getattr(v, "description", getattr(v, "name", str(k)))
            if getattr(v, "win_index", -1) == -1 and ident != "\\\\\\\\Device\\\\\\\\NPF_Loopback" and getattr(v, "mac", "") == "":
                continue
            combined = f"{ident} {desc}".lower()
            is_eth = any(kw in combined for kw in ["ethernet", "realtek", "intel", "broadcom", "gigabit", "tap-", "en", "eth"])
            is_wifi = any(kw in combined for kw in ["wi-fi", "wifi", "wireless", "wlan", "killer"])
            ips_dict = getattr(v, "ips", {})
            ipv4s = [ip for ip in ips_dict if "." in ip and not ip.startswith("169.254")]
            result.append({
                "name": ident,
                "description": desc,
                "ips": ipv4s,
                "ipv4": ipv4s,
                "is_ethernet": is_eth,
                "is_wifi": is_wifi,
            })
        result.sort(key=lambda x: (not x["is_ethernet"], not x["is_wifi"], x["description"]))
        return jsonify({"interfaces": result})
    except Exception as e:
        from flask import jsonify
        print(f"[ERROR] Cannot get interfaces: {e}")
        return jsonify({"interfaces": []})

'''

new_text = text[:start_idx] + new_func + text[end_idx:]

p.write_text(new_text, 'utf-8')
print("Replaced using str.find!")
