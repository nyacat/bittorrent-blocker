import io
import time
import shlex
import socket
import ipaddress
import subprocess
import xmlrpc.client
from datetime import datetime


"""
    UNIX SCGI From https://github.com/Flexget/Flexget/blob/05dd18f47d9476a092f05fe87a2e5b801f01de14/flexget/plugins/clients/rtorrent.py#L106
"""
def encode_netstring(input):
    return str(len(input)).encode() + b':' + input + b','


def encode_header(key, value):
    return key + b'\x00' + value + b'\x00'


class SCGITransport(xmlrpc.client.Transport):
    """
    Public domain SCGITrannsport implementation from:
    https://github.com/JohnDoee/autotorrent/blob/develop/autotorrent/scgitransport.py
    """

    def __init__(self, *args, **kwargs):
        self.socket_path = kwargs.pop('socket_path', '')
        xmlrpc.client.Transport.__init__(self, *args, **kwargs)

    def single_request(self, host, handler, request_body, verbose=False):
        self.verbose = verbose
        if self.socket_path:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(self.socket_path)
        else:
            host, port = host.split(':')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))

        request = encode_header(b'CONTENT_LENGTH', str(len(request_body)).encode())
        request += encode_header(b'SCGI', b'1')
        request += encode_header(b'REQUEST_METHOD', b'POST')
        request += encode_header(b'REQUEST_URI', handler.encode())

        request = encode_netstring(request)
        request += request_body

        s.send(request)

        response = b''
        while True:
            r = s.recv(1024)
            if not r:
                break
            response += r

        response_body = io.BytesIO(b'\r\n\r\n'.join(response.split(b'\r\n\r\n')[1:]))

        return self.parse_response(response_body)


def exec_system_cmd(command: str):
    process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    if process.returncode != 0:
        # print(out, err)
        return False
    else:
        return True


def ip_kind(addr):
    return ipaddress.ip_address(addr).version


def get_ban_peer():
    block_peer = []
    torrent_list = rtorrent_client.download_list()
    for torrent in torrent_list:
        torrent_info = rtorrent_client.p.multicall(torrent, "", "p.address=", "p.port=", "p.client_version=")
        if torrent_info:
            for peer in torrent_info:
                address, port, client_version = peer
                client_version = client_version.lower()

                for block_client in black_list:
                    if block_client in client_version:
                        block_peer.append(
                            {
                                "address": address,
                                "port": port,
                                "clientName": client_version
                            }
                        )
    return block_peer


if __name__ == "__main__":
    # setup env
    rtorrent_client = xmlrpc.client.ServerProxy('http://none', transport=SCGITransport(socket_path=("/home/rtorrent/.session/rpc.socket")))
    speed_limit = 64 # in kb

    # system setup
    print("setup ipset and iptables rule")
    ipv4_set_name = "bt-ban-v4"
    ipv6_set_name = "bt-ban-v6"
    exec_system_cmd("ipset create {} hash:ip family inet timeout 300".format(ipv4_set_name))
    exec_system_cmd("ipset create {} hash:ip family inet6 timeout 300".format(ipv6_set_name))
    assert exec_system_cmd("iptables -I OUTPUT -m set --match-set {} dst -j DROP".format(ipv4_set_name))
    assert exec_system_cmd("ip6tables -I OUTPUT -m set --match-set {} dst -j DROP".format(ipv6_set_name))
    assert exec_system_cmd("iptables -I OUTPUT -m set --match-set {} dst -m hashlimit --hashlimit-mode dstip --hashlimit-upto {}/sec --hashlimit-burst {} --hashlimit-name conn_rate_limit -j ACCEPT".format(ipv4_set_name, speed_limit, speed_limit*2))
    assert exec_system_cmd("ip6tables -I OUTPUT -m set --match-set {} dst -m hashlimit --hashlimit-mode dstip --hashlimit-upto {}/sec --hashlimit-burst {} --hashlimit-name conn_rate_limit -j ACCEPT".format(ipv6_set_name, speed_limit, speed_limit*2))
    # black list client
    black_list = ["xfplay", "xunlei", "thunder"]

    while True:
        try:
            block_peers_info = get_ban_peer()
            for peer_info in block_peers_info:
                peer_address = peer_info["address"]
                ip_version = ip_kind(peer_address)
                if ip_version == 4:
                    rc = exec_system_cmd("ipset add {} {}".format(ipv4_set_name, peer_address))
                    if rc:
                        print("{}, Block peer: {} in {}:{}".format(datetime.now().strftime("%Y/%m/%d %H:%M:%S"), peer_info["clientName"], peer_info["address"], peer_info["port"]))
                elif ip_version == 6:
                    rc = exec_system_cmd("ipset add {} {}".format(ipv6_set_name, peer_address))
                    if rc:
                        print("{}, Block peer: {} in {}:{}".format(datetime.now().strftime("%Y/%m/%d %H:%M:%S"), peer_info["clientName"], peer_info["address"], peer_info["port"]))
                else:
                    print("unknown ip address version")        
            time.sleep(10)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(e)

    # clean
    print("removing ipset and iptables rule")
    assert exec_system_cmd("iptables -D OUTPUT -m set --match-set {} dst -j DROP".format(ipv4_set_name))
    assert exec_system_cmd("ip6tables -D OUTPUT -m set --match-set {} dst -j DROP".format(ipv6_set_name))
    assert exec_system_cmd("iptables -D OUTPUT -m set --match-set {} dst -m hashlimit --hashlimit-mode dstip --hashlimit-upto {}/sec --hashlimit-burst {} --hashlimit-name conn_rate_limit -j ACCEPT".format(ipv4_set_name, speed_limit, speed_limit*2))
    assert exec_system_cmd("ip6tables -D OUTPUT -m set --match-set {} dst -m hashlimit --hashlimit-mode dstip --hashlimit-upto {}/sec --hashlimit-burst {} --hashlimit-name conn_rate_limit -j ACCEPT".format(ipv6_set_name, speed_limit, speed_limit*2))
    # fix for wait iptables remove
    time.sleep(3)
    assert exec_system_cmd("ipset destroy {}".format(ipv4_set_name))
    assert exec_system_cmd("ipset destroy {}".format(ipv6_set_name))
