what to do:
think about what to do with the listening socket on ssdp.

listen will join multicast group + will send packets and gets them.


QA on SSDP parser, also look at info about ssdp\upnp to see how packet is really built.

HTTP/1.1 200 OK
Server: Custom/1.0 UPnP/1.0 Proc/Ver
EXT:
Location: http://10.0.0.138:5431/dyndev/uuid:c412f5f4-05a2-a205-f4f5-12c412f4a20000
Cache-Control:max-age=1800
ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1
USN:uuid:c412f5f4-05a2-a205-f4f5-12c412f4a20000::urn:schemas-upnp-org:device:InternetGatewayDevice:1



HTTP/\d+\.\d \d{3} .+\r\nServer:.(+)\r\n


supports only upnp 1.0

exceptions.

minidom is not secure.

more than one tag with the same name on an element

make good log.
make good doc
make good code on parse_device_type


camel case and snake case ?? on xmlobject and upnpdevice

# TODO: LOG
# TODO: exceptions
# TODO: windows\linux
# TODO: finish