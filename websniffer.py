import pyshark
import json
import requests

last_host_address = None

def capture_live_packets(network_interface):
    try:
        capture = pyshark.LiveCapture(interface=network_interface)
        for raw_packet in capture.sniff_continuously():
            print(filter_all_tcp_traffic_file(raw_packet))
    except Exception:
        pass
    print("Exception ignored")



def get_packet_details(packet):
    try:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        website_ip = 'Enter the ip address you wish to track'
        global last_host_address

        if destination_address == website_ip and last_host_address != source_address:
            last_host_address = source_address
            body = json.dumps({

                "notification": "Enter your notification message here",

                "accessCode": "Enter your access code here"

            })

            requests.post(url="https://api.notifymyecho.com/v1/NotifyMe", data=body)
            print(source_address)
    except Exception:
        pass
    print("Exception ignored")


def filter_all_tcp_traffic_file(packet):
    try:
        if hasattr(packet, 'tcp'):
            return get_packet_details(packet)
    except Exception:
        pass
    print("Exception ignored")


try:
    capture_live_packets('en0')
except Exception:
    pass

print("Exception ignored")
