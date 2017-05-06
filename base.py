"""

Purpose: base class for the UPNP socket.

Author : denjK

"""

# IMPORTS

import re
import requests
from misc import XmlObject
from consts import UPNPConsts
from consts import XMLServiceParserConsts, XMLDeviceParserConsts
import copy
import socket
from consts import SSDPConsts


class Address(object):
    """
        defines an address
    """

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def get_address(self):
        return self.ip, self.port


class NetworkSocket(object):
    def __init__(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        """
        creates a UPNP socket.

        :param socket_family: the socket family (IPv4 = AF_INET, IPv6 = AF_INET6 ..)
        :param socket_type: the socket type (TCP = SOCK_STREAM, UDP = SOCK_DGRAM)
        """

        self.family = socket_family
        self.type = socket_type
        self.socket = socket.socket(self.family, self.type)
        self.address = None

    def bind(self, local_interface_ip, port):
        self.address = Address(local_interface_ip, port)
        print self.address.get_address()
        self.socket.bind(self.address.get_address())

    def connect(self, local_interface_ip, port):
        self.address = Address(local_interface_ip, port)
        self.socket.connect(self.address.get_address())


class UPNPSocket(NetworkSocket):
    """
        class for creating socket with background NAT Traversal using UPNP.
    """

    def bind(self, local_interface_ip, port):
        self.address = Address(local_interface_ip, port)
        self.socket.bind(self.address)

    def listen(self, upnp_router, back_log):
        """

        :param UPNPRouter upnp_router: the upnp router to port forward from.
        :param back_log: the maximum number of queued connections.

        * IS blocking.
        """

        if not upnp_router.is_discovered:
            upnp_router.discover()

        self.socket.listen(back_log)


class MultiCastSocket(object):
    """
        implementing multicast socket.
    """

    def __init__(self, socket_family=socket.AF_INET, socket_type=socket.SOCK_DGRAM):
        self._sending = NetworkSocket(socket_family, socket_type)
        self._listening = NetworkSocket(socket_family, socket_type)
        self.is_on_group = False
        self.address = None

    def join_group(self, multicast_ip, port, interface_ip):
        """
            join the multicast ip group.
        :return:
        """

        self.address = Address(multicast_ip, port)
        mreq = socket.inet_aton(multicast_ip) + socket.inet_aton(interface_ip)
        print self.address.ip, self.address.port
        self._sending.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, str(mreq))
        self._listening.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, str(mreq))
        self.is_on_group = True

    def connect(self, multicast_ip, port):
        self._sending.connect(multicast_ip, port)

    def bind(self, multicast_ip, port):
        """

        :param multicast_ip:
        :param port:
        :return:
        """

        self.address = Address(multicast_ip, port)
        self._listening.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listening.socket.bind((self.address.ip, self.address.port))

    def receive(self):
        data, address = self._listening.socket.recvfrom(2048)
        return data

    def send(self, data):
        self._sending.socket.send(data)

    def listen(self, back_log):
        self._listening.socket.listen(back_log)


class SSDPSocket(MultiCastSocket):
    """
        implementing multicast socket
    """

    def __init__(self):
        super(SSDPSocket, self).__init__()

        # the socket which gets the replies. (because address is multicast)

    def discover(self):
        """
            purpose : discover upnp object on the lan.
            CTRL + C to quit.
        :return UPNPObjects: the upnp objects
        """
        upnp_hosts = []
        try:
            ip, port = self._sending.socket.getsockname()
            sock_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_listener.settimeout(10)
            sock_listener.bind((ip, port))

            self.send_multi_search()

            while 1:
                data, address = sock_listener.recvfrom(1024)
                if address[0] == '10.0.0.138':
                    upnp_hosts.append(UPNPHost.parse_to_upnp_host(data))

        except KeyboardInterrupt:
            print "finished!"
        except Exception as e:
            print type(e), e

        return upnp_hosts

    def send_multi_search(self):
        """

        :return:
        """

        packet = SSDPConsts.MULTICAST_SEARCH_PACKET.format(http_version=SSDPConsts.DEFAULT_HTTP_VERSION,
                                                           ip=SSDPConsts.DEFAULT_SSDP_MULTICAST_ADDRESS,
                                                           port=SSDPConsts.DEFAULT_SSDP_MULTICAST_PORT,
                                                           message=SSDPConsts.DEFAULT_MUST_MAN,
                                                           seconds=SSDPConsts.DEFAULT_MX,
                                                           search_target=SSDPConsts.DEFAULT_ST)
        self.connect()
        self.send(packet)

    def connect(self, multicast_ip=SSDPConsts.DEFAULT_SSDP_MULTICAST_ADDRESS,
                port=SSDPConsts.DEFAULT_SSDP_MULTICAST_PORT):
        super(SSDPSocket, self).connect(multicast_ip, port)

    def join_group(self, multicast_ip=SSDPConsts.DEFAULT_SSDP_MULTICAST_ADDRESS,
                   port=SSDPConsts.DEFAULT_SSDP_MULTICAST_PORT, interface_ip="10.0.0.1"):
        super(SSDPSocket, self).join_group(multicast_ip, port, interface_ip)


class UPNPHost(object):
    """
        class for creating upnp object.
    """

    def __init__(self, cache_control, location, server, st, usn, bootid_upnp_org=None, date=None,
                 configid_upnp_org=None, searchport_upnp_org=None, ext='', upnp_devices=None):
        """

        :param cache_control: max_age, when service is expired.
        :param location: the xml file location.
        :param server: server information (server_info on object)
        :param st: search target (what does it targets (in sense of upnp device) (search_target on object)
        :param usn: unique service name (with uuid) (unique_service_name on object)
        :param bootid_upnp_org: --- (its must but somehow some not implement it)
        :param date: the date which the response was given.
        :param configid_upnp_org: ---
        :param searchport_upnp_org: ---
        :param ext: legacy, should be empty.
        :param upnp_devices: upnp devices, you can found them with self functions.
        """

        self.cache_control = cache_control
        self.location = location
        self.server_info = server
        self.search_target = st
        self.unique_service_name = usn

        self.bootid_upnp_org = bootid_upnp_org
        self.date = date
        self.configid_upnp_org = configid_upnp_org
        self.searchport_upnp_org = searchport_upnp_org
        self.ext = ext

        ip, port, protocol = self.parse_location()
        self.address = Address(ip, port)
        self.protocol = protocol

        if not upnp_devices:
            self.upnp_devices = []

    def load_devices(self):
        """
            connects to the host and get the upnp devices.
        :return:
        """
        if self.upnp_devices:
            return self.upnp_devices

        request = requests.get(self.location, headers=UPNPConsts.XML_GET_HEADERS)
        if str(request.status_code) != UPNPConsts.HTTP_OK_CODE_NUMBER:
            raise Exception('xml not found..')

        # TODO LOGGING.
        xml_data = request.text

        xml_object = XmlObject.parse_xml(xml_data)
        self.upnp_devices = UPNPDevice.get_upnp_devices(xml_object)
        return self.upnp_devices

    def parse_location(self):
        """
            returns ip, port, protocol
        :return:
        """
        match = re.match(UPNPConsts.URL_PATTERN, self.location)
        ip, port, protocol = match.group(UPNPConsts.IP_GROUP_NAME), match.group(
            UPNPConsts.PORT_GROUP_NAME), match.group(UPNPConsts.PROTOCOL_GROUP_NAME)
        return ip, port, protocol

    @staticmethod
    def parse_to_upnp_host(data):
        """
            parse data to a upnp.
        :param data: the data to parse.
        :return: UPNPObject, or None if didn't successfully parsed.
        """

        upnp_object = None
        lines = data.split('\r\n')
        info_header = lines[0]
        lines = lines[1:-2]

        match = re.match(UPNPConsts.INFO_HEADER_PATTERN, info_header)
        error_code = match.group(UPNPConsts.GROUP_ERROR_CODE)

        if str(error_code) != UPNPConsts.HTTP_OK_CODE_NUMBER:
            return None
        try:
            object_attributes = {}
            for header in lines:
                if header:
                    print "header - " + header
                    match = re.match(UPNPConsts.SSDP_UPNP_HEADER_PATTERN, header)
                    name = match.group(UPNPConsts.HEADER_NAME_PATTERN)
                    print match.groups()
                    name = name.replace('.', '_').replace('-', '_')
                    object_attributes[name.lower()] = match.group(UPNPConsts.HEADER_DATA_PATTERN)

            upnp_object = UPNPHost(**object_attributes)
        except Exception as e:
            print type(e), e
            print "could not parse.."

        finally:
            return upnp_object

    def __getitem__(self, key):
        """
            gets the wanted device from the host.
        :param key: the name of the device.
        :return: UPNPDevice.
        """
        if self.upnp_devices is not None:
            for device in self.upnp_devices:
                if device.name == key:
                    return device

        raise IndexError('Device not found, check if you haven\'t gotten your devices yet with self.load_devices ')


class UPNPDevice(object):
    def __init__(self, name, device_type, manufacturer_url=None, model_name=None, upc=None, model_number=None,
                 presentation_url=None, friendly_name=None, model_url=None, model_description=None, udn=None,
                 manufacturer=None, upnp_services=None, xml=None):
        self.name = name
        self.manufacturerurl = manufacturer_url
        self.model_name = model_name
        self.upc = upc
        self.model_number = model_number
        self.presentation_url = presentation_url
        self.device_type = device_type
        self.friendly_name = friendly_name
        self.model_url = model_url
        self.model_description = model_description
        self.udn = udn
        self.manufacturer = manufacturer
        self.upnp_services = upnp_services
        self.xml = xml

    # TODO: change to a self method. (can be if on __init__...)
    @staticmethod
    def parse_device_type(device_type):
        delim1 = 'device:'
        delim2 = ':'

        if delim1 in device_type and not device_type.endswith(delim1):
            return device_type.split(delim1)[1].split(delim2, 1)[0]
        raise Exception("parsing not good!.")

    @classmethod
    def get_upnp_devices(cls, xml_object):
        """
            get UPNPDevices from object.
        :return:
        """

        upnp_devices = []

        try:
            device = xml_object.root.device

            while 1:
                device_members = {}
                for tag in XMLDeviceParserConsts.DEVICE_MEMBERS_TAGS:
                    try:
                        device_members[tag] = getattr(device, tag).text_nodes.data
                    except:
                        pass
                device_members['name'] = UPNPDevice.parse_device_type(device_members['device_type'])
                device_members['xml'] = copy.copy(device)

                dev = UPNPDevice(**device_members)
                upnp_devices.append(dev)

                device = device.device_list.device

        except AttributeError as e:
            if cls.__name__ in e.args[0] and XMLDeviceParserConsts.DEVICE_LIST_TAG_NAME in e.args[0]:
                print "found all."
                # TODO: NOT GOOD.

        except Exception as e:
            print type(e), e
            print "probably a parsing error.."

        return upnp_devices


class UPNPService(object):
    def __init__(self, name, service_type, service_id=None, control_url=None, event_sub_url=None, scpdurl=None):
        self.name = name
        self.service_id = service_id
        self.control_url = control_url
        self.event_sub_url = event_sub_url
        self.scpdurl = scpdurl
        self.service_type = service_type

    @classmethod
    def get_upnp_services(cls, xml_of_device):
        """
            get UPNPServices from an XmlObject.
        :return:
        """

        upnp_services = []

        try:

            service = xml_of_device.service_list.service

            while 1:
                services_members = {}
                for tag in XMLServiceParserConsts.SERVICE_MEMBERS_TAGS:
                    try:
                        services_members[tag] = getattr(service, tag).text_nodes.data
                    except:
                        pass
                services_members['name'] = cls.parse_service_type(services_members['service_type'])

                dev = UPNPService(**services_members)
                upnp_services.append(dev)

                service = service.service_list.service

        except AttributeError as e:
            if cls.__name__ in e.args[0] and XMLServiceParserConsts.SERVICE_LIST_TAG_MAME in e.args[0]:
                print "found all."

        except Exception as e:
            print type(e), e
            print "probably a parsing error.."

        return upnp_services

    # TODO: change it to a self method.
    @classmethod
    def parse_service_type(cls, service_type):
        delim1 = 'service:'
        delim2 = ':'

        if delim1 in service_type and not service_type.endswith(delim1):
            return service_type.split(delim1)[1].split(delim2, 1)[0]
        return False
