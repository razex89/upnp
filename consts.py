"""
    CONSTS for SSDP and UPNP.
"""


class SSDPConsts(object):
    def __init__(self):
        raise NotImplementedError("static class!")

    # multicast search format

    # M-SEARCH (multicast search) * HTTP/1.1
    #  HOST: IP:PORT (the destination ip and port, probably multicast).
    #  MAN (mandatory): "ssdp:discover" must have " " on the message.
    #  MX: seconds to delay response
    # ST: search target the upnp target we are searching for. (all root devices in our case).
    # (OPTIONAL_NOT_IMPLEMENTED) USER-AGENT: OS/version UPnP/1.1 product/version

    MULTICAST_SEARCH_PACKET = 'M-SEARCH * {http_version}\r\n' \
                              'HOST: {ip}:{port}\r\n' \
                              'MAN: {message}\r\n' \
                              'MX: {seconds}\r\n' \
                              'ST: {search_target}\r\n' \
                              '\r\n'

    # DEFAULT_ST = 'upnp:rootdevice'
    DEFAULT_ST = "urn:schemas-upnp-org:device:InternetGatewayDevice:1"
    # DEFAULT_ST = "ssdp:all"

    DEFAULT_MX = '2'

    DEFAULT_MUST_MAN = '"ssdp:discover"'

    DEFAULT_SSDP_MULTICAST_ADDRESS = '239.255.255.250'

    DEFAULT_SSDP_MULTICAST_PORT = 1900

    DEFAULT_HTTP_VERSION = 'HTTP/1.1'


class UPNPConsts(object):
    INFO_HEADER_PATTERN = r'HTTP/\d+\.\d (?P<code>\d{3}) ([\w\s]+)'

    SSDP_UPNP_PACKET = r'HTTP/\d+\.\d (?P<code>\d{3}) ([\w\s]+)\r\n' \
                       r'Server: *(?P<upnp_type>.*)\r\nEXT: *.*\r\n' \
                       r'Location: {0,1}(?P<xml_page>https{0,1}://(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}))' \
                       r'[\w\d/]*(uuid:.+){0,1}\r\n' \
                       r'Cache-Control: {0,1}(.+=.+)*\r\nST:.+\r\n' \
                       r'USN.+\r\n' \
                       r'\r\n'

    SSDP_UPNP_HEADER_PATTERN = r'(?P<name>[\w\-\.]+): {0,1}(?P<data>.*)'

    HEADER_NAME_PATTERN = 'name'
    HEADER_DATA_PATTERN = 'data'
    GROUP_ERROR_CODE = 'code'
    HTTP_OK_CODE_NUMBER = '200'

    URL_PATTERN = r'(?P<protocol>\w+)://(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<port>\d{1,5})'

    IP_GROUP_NAME = 'ip'
    PORT_GROUP_NAME = 'port'
    PROTOCOL_GROUP_NAME = 'protocol'

    XML_GET_HEADERS = {'USER-AGENT': 'uPNP/1.0', 'CONTENT-TYPE': 'text/xml; charset="utf-8"'}

    # you can group cache control to be implicit (to don't have to have it ({0,1})).


class XMLDeviceParserConsts(object):
    DEVICE_TAG_NAME = 'device'
    DEVICE_LIST_TAG_NAME = 'device_list'
    DEVICE_MEMBERS_TAGS = ['friendly_name', 'model_description', 'model_name', 'model_number', 'model_url',
                           'presentation_url', 'udn', 'upc', 'manufacturer', 'manufacturer_url', 'device_type']


class XMLServiceParserConsts(object):
    SERVICE_TAG_NAME = 'service'
    SERVICE_LIST_TAG_MAME = 'service_list'
    SERVICE_MEMBERS_TAGS = ['service_id', 'control_url', 'event_sub_url', 'scpdurl', 'service_type']
