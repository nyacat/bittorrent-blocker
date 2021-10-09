import json
import time
import shlex
import requests
import ipaddress
import subprocess
from datetime import datetime


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


def send_req(post_data: dict):
    r = req_session.post(rpc_url, json=post_data)
    if r.status_code == 409:
        req_session.headers.update({'X-Transmission-Session-Id': r.headers["X-Transmission-Session-Id"]})
        return send_req(post_data)
    else:
        return r


def get_ban_peer():
    resp = send_req({
        'tag': 12801,
        'method':"torrent-get",
        'arguments': {
            'fields': ["id", "name", "peers"]
        }
    }).json()

    block_peer = []
    for torrent in resp["arguments"]["torrents"]:
        for peer in torrent["peers"]:
            peer_name = peer["clientName"].lower()
            for block_client in black_list:
                if block_client in peer_name:
                    block_peer.append(peer)
    return block_peer


if __name__ == "__main__":
    # req setup
    req_session = requests.Session()
    rpc_url = "http://127.0.0.1:9001/transmission/rpc"
    req_session.auth = ('username', 'password')
    req_session.headers.update({'X-Transmission-Session-Id': '0'})

    # system setup
    print("setup ipset and iptables rule")
    ipv4_set_name = "bt-ban-v4"
    ipv6_set_name = "bt-ban-v6"
    exec_system_cmd("ipset create {} hash:ip family inet timeout 300".format(ipv4_set_name))
    exec_system_cmd("ipset create {} hash:ip family inet6 timeout 300".format(ipv6_set_name))
    assert exec_system_cmd("iptables -I OUTPUT -m set --match-set {} dst -m limit --limit 15/s --limit-burst 5 -j DROP".format(ipv4_set_name))
    assert exec_system_cmd("ip6tables -I OUTPUT -m set --match-set {} dst -m limit --limit 15/s --limit-burst 5 -j DROP".format(ipv6_set_name))
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
    assert exec_system_cmd("iptables -D OUTPUT -m set --match-set {} dst -m limit --limit 15/s --limit-burst 5 -j DROP".format(ipv4_set_name))
    assert exec_system_cmd("ip6tables -D OUTPUT -m set --match-set {} dst -m limit --limit 15/s --limit-burst 5 -j DROP".format(ipv6_set_name))
    # fix for wait iptables remove
    time.sleep(3)
    assert exec_system_cmd("ipset destroy {}".format(ipv4_set_name))
    assert exec_system_cmd("ipset destroy {}".format(ipv6_set_name))
