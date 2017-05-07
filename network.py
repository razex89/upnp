"""
    Purpose : networking classes

    Author: denjK
"""



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
