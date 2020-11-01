import sys
import asyncio
import datetime
import select
from socket import socket
import OpenSSL
import csv


def get_certificate(host):
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    sock = socket()
    sock.settimeout(5)
    sock_ssl = OpenSSL.SSL.Connection(ctx, sock)
    sock_ssl.set_tlsext_host_name(host.encode('ascii'))
    sock_ssl.connect((host, 443))
    while True:
        try:
            sock_ssl.do_handshake()
            break
        except OpenSSL.SSL.WantReadError:
            select.select([sock_ssl], [], [])
    return (host, sock_ssl.get_peer_cert_chain())


class CSVWriter():
    filename = None
    fp = None
    writer = None

    def __init__(self, filename):
        self.filename = filename
        self.fp = open(self.filename, 'w', encoding='utf8')
        self.writer = csv.writer(self.fp, delimiter=';', quotechar='"',
                                 quoting=csv.QUOTE_ALL, lineterminator='\n')

    def close(self):
        self.fp.close()

    def write(self, elems):
        self.writer.writerow(elems)


def basic_info(certificate, host):
    ssl_validity = ""
    for domain, cert_chain in certificate:
        if cert_chain is None:
            continue
        if not any(isinstance(cert, OpenSSL.crypto.X509) for cert in cert_chain):
            ssl_validity = "Couldn't find certificate for %s" % host
            continue
        cert = cert_chain[0]
        expires = datetime.datetime.strptime(
            cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        if expires:
            t = ((expires - datetime.datetime.utcnow())
                 // 60 // 10 ** 6) * 60 * 10 ** 6
            ssl_validity = "The certificate will expire in %s" % t
    return (ssl_validity)


def get_basic_info(hosts, certs):
    result = []
    for host in hosts:
        certificate = [(host, certs[host])]
        ssl_validity = basic_info(certificate, host)
        result.append((''.join(host), ssl_validity))
    return result


def hosts_from_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        result = []
        current = []
        current_start = 1
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                if not current:
                    current_start += 1
                continue
            if line.startswith('https:'):
                line = line.split('/')[2]
            if line.endswith('/'):
                line = line.replace('/', '')
            current.append(line)
            hostnames = ("".join(current))
            result.append(hostnames)
            current = []
            current_start = i + 1

    return result


def main(file):
    hosts = hosts_from_file(file)
    ssl_check = get_basic_info(hosts, exec_loop_call(hosts))

    csv = CSVWriter('/tmp/output.csv')
    csv.write(["Host", 'SSL_validityExpires'])
    ## print dict to csv file
    for key in ssl_check:
        csv.write(key)
    csv.close()


def exec_loop_call(hosts):
    loop = asyncio.get_event_loop()

    tasks = [loop.run_in_executor(None, get_certificate, x) for x in hosts]

    (finished, unfinished) = loop.run_until_complete(asyncio.wait(tasks))
    loop.close()

    return dict(x.result() for x in finished)


if __name__ == '__main__':
    main(sys.argv[1])
