from __future__ import annotations

import asyncio
import random

TCP_FLAGS_SYN = 0x02
TCP_FLAGS_RST = 0x04
TCP_FLAGS_ACK = 0x10

TCP_STATE_LISTEN = 0
TCP_STATE_SYN_SENT = 1
TCP_STATE_SYN_RECEIVED = 2
TCP_STATE_ESTABLISHED = 3
TCP_STATE_FIN_WAIT_1 = 4
TCP_STATE_FIN_WAIT_2 = 5
TCP_STATE_CLOSE_WAIT = 6
TCP_STATE_CLOSING = 7
TCP_STATE_LAST_ACK = 8
TCP_STATE_TIME_WAIT = 9
TCP_STATE_CLOSED = 10

from buffer import TCPSendBuffer, TCPReceiveBuffer

from headers import IPv4Header, UDPHeader, TCPHeader, \
        IP_HEADER_LEN, UDP_HEADER_LEN, TCP_HEADER_LEN, \
        TCPIP_HEADER_LEN, UDPIP_HEADER_LEN


#From /usr/include/linux/in.h:
IPPROTO_TCP = 6 # Transmission Control Protocol
IPPROTO_UDP = 17 # User Datagram Protocol

loop = asyncio.get_event_loop()

class UDPSocket:
    def __init__(self, local_addr: str, local_port: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> UDPSocket:

        self._local_addr = local_addr
        self._local_port = local_port
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        self.buffer = []

    def handle_packet(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        udp_hdr = UDPHeader.from_bytes(pkt[IP_HEADER_LEN:UDPIP_HEADER_LEN])
        data = pkt[UDPIP_HEADER_LEN:]

        self.buffer.append((data, ip_hdr.src, udp_hdr.sport))
        self._notify_on_data()

    @classmethod
    def create_packet(cls, src: str, sport: int, dst: str, dport: int,
            data: bytes=b'') -> bytes:

        data_len = len(data)
        pkt_len = UDPIP_HEADER_LEN + data_len
        pkt_ttl = 64

        # Create the IP header
        ip_hdr = IPv4Header(pkt_len, pkt_ttl, IPPROTO_UDP, 0, src, dst)
        ip_hdr_bytes = ip_hdr.to_bytes()
        
        # UDP header
        udp_hdr = UDPHeader(sport, dport, UDP_HEADER_LEN + data_len, 0)
        udp_hdr_bytes = udp_hdr.to_bytes()

        return ip_hdr_bytes + udp_hdr_bytes + data

    def send_packet(self, remote_addr: str, remote_port: int,
            data: bytes) -> None:

        pkt = self.create_packet(self._local_addr, self._local_port,
                remote_addr, remote_port, data)
        self._send_ip_packet(pkt)

    def recvfrom(self) -> tuple[bytes, str, int]:
        return self.buffer.pop(0)

    def sendto(self, data: bytes, remote_addr: str, remote_port: int) -> None:
        self.send_packet(remote_addr, remote_port, data)


class TCPSocketBase:
    def handle_packet(self, pkt: bytes) -> None:
        pass

class TCPListenerSocket(TCPSocketBase):
    def __init__(self, local_addr: str, local_port: int,
            handle_new_client_func: callable, send_ip_packet_func: callable,
            notify_on_data_func: callable,
            socket_cls: type=None,
            fast_retransmit: bool=False, initial_cwnd: int=1000,
            mss: int=1000,
            congestion_control: str='none') -> TCPListenerSocket:

        # These are all vars that are saved away for instantiation of TCPSocket
        # objects when new connections are created.
        self._local_addr = local_addr
        self._local_port = local_port
        self._handle_new_client = handle_new_client_func

        self._send_ip_packet_func = send_ip_packet_func
        self._notify_on_data_func = notify_on_data_func
        if socket_cls is None:
            socket_cls = TCPSocket
        self._socket_cls = socket_cls

        self._fast_retransmit = fast_retransmit
        self._initial_cwnd = initial_cwnd
        self._mss = mss
        self._congestion_control = congestion_control

    def handle_packet(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.flags & TCP_FLAGS_SYN:
            sock = self._socket_cls(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport,
                    TCP_STATE_LISTEN,
                    send_ip_packet_func=self._send_ip_packet_func,
                    notify_on_data_func=self._notify_on_data_func,
                    fast_retransmit=self._fast_retransmit,
                    initial_cwnd=self._initial_cwnd, mss=self._mss,
                    congestion_control=self._congestion_control)

            self._handle_new_client(self._local_addr, self._local_port,
                    ip_hdr.src, tcp_hdr.sport, sock)

            sock.handle_packet(pkt)


class TCPSocket(TCPSocketBase):
    '''
    A TCP Connection.  The class is instantiated with an initial state, either
    CLOSED (client) or LISTEN (server).  It takes the necessary actions to
    transition to state ESTABLISHED, after which data is exchanged between apps
    on either side of the connection, with this instance providing the reliable
    transport.

    The following example is taken directly from RFC 793:

        TCP A                                                TCP B

    1.  CLOSED                                               LISTEN

    2.  SYN-SENT    --> <SEQ=100><CTL=SYN>               --> SYN-RECEIVED

    3.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK>  <-- SYN-RECEIVED

    4.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK>       --> ESTABLISHED

    5.  ESTABLISHED --> <SEQ=101><ACK=301><CTL=ACK><DATA> --> ESTABLISHED

    (https://tools.ietf.org/html/rfc793#section-3.4)

    See continue_connection(), initiate_connection(), handle_syn(),
    handle_syn_ack(), handle_ack(), and handle_data().

    '''

    def __init__(self, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int, state: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPSocket:

        # The local/remote address/port information associated with this
        # TCPConnection
        self._local_addr = local_addr
        self._local_port = local_port
        self._remote_addr = remote_addr
        self._remote_port = remote_port

        # The current state (TCP_STATE_LISTEN, TCP_STATE_CLOSED, etc.)
        self.state = state

        # Helpful methods for helping us send IP packets and
        # notifying the application that we have received data.
        self._send_ip_packet = send_ip_packet_func
        self._notify_on_data = notify_on_data_func

        # Base sequence number
        self.base_seq_self = self.initialize_seq()

        # Base sequence number for the remote side
        self.base_seq_other = None

    @classmethod
    def connect(cls, local_addr: str, local_port: int,
            remote_addr: str, remote_port: int,
            send_ip_packet_func: callable,
            notify_on_data_func: callable) -> TCPSocket:
        '''
        Create the client side of a new TCP connection.  Instantiate the
        TCPConnection based on the remote address and remote port (and,
        optionally, the local address and port) specified.  Call
        initiate_connection() to send the initial SYN packets.
        '''

        sock = cls(local_addr, local_port,
                remote_addr, remote_port,
                TCP_STATE_CLOSED,
                send_ip_packet_func, notify_on_data_func)

        sock.initiate_connection()

        return sock


    def handle_packet(self, pkt: bytes) -> None:
        '''
        Handle an incoming packet corresponding to this connection.  If the
        connection is not yet established, then continue connection
        establishment.  For an established connection, handle any payload data
        (TCP segment) and any data acknowledged.
        '''

        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if self.state != TCP_STATE_ESTABLISHED:
            self.continue_connection(pkt)

        if self.state == TCP_STATE_ESTABLISHED:
            if data:
                # handle data
                self.handle_data(pkt)
            if tcp_hdr.flags & TCP_FLAGS_ACK:
                # handle ACK
                self.handle_ack(pkt)


    def initialize_seq(self) -> int:
        '''
        Initialize the sequence number used by our side of the connection.
        '''

        #XXX
        return random.randint(0, 65535)


    def initiate_connection(self) -> None:
        '''
        Initiate a TCP connection.  Send a TCP SYN packet to a server,
        which includes our own base sequence number.  Transition to state
        TCP_STATE_SYN_SENT.
        '''

        self.send_packet(self.base_seq_self, 0, flags=TCP_FLAGS_SYN)
        self.state = TCP_STATE_SYN_SENT

    def handle_syn(self, pkt: bytes) -> None:
        '''
        Handle an incoming TCP SYN packet.  Ignore the packet if the SYN
        flag is not sent.  Save the sequence in the packet as the base sequence
        of the remote side of the connection.  Send a corresponding SYNACK
        packet, which includes both our own base sequence number and an
        acknowledgement of the remote side's sequence number (base + 1).
        Transition to state TCP_STATE_SYN_RECEIVED.

        pkt: the incoming packet, a bytes instance
        '''

        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.flags & TCP_FLAGS_SYN:
            self.base_seq_other = tcp_hdr.seq

            # Modification to incorporate receive buffer for dynamic 3-way handshake
            self.ack = tcp_hdr.seq + 1
            self.receive_buffer = TCPReceiveBuffer(self.base_seq_other + 1)

            self.send_packet(self.base_seq_self, self.base_seq_other + 1, flags=TCP_FLAGS_SYN | TCP_FLAGS_ACK)
            self.state = TCP_STATE_SYN_RECEIVED

    def handle_synack(self, pkt: bytes) -> None:
        '''
        Handle an incoming TCP SYNACK packet.  Ignore the packet if the SYN and
        ACK flags are not both set or if the ack field does not represent our
        current sequence (base + 1).  Save the sequence in the packet as the
        base sequence of the remote side of the connection.  Send a
        corresponding ACK packet, which includes both our current sequence
        number and an acknowledgement of the remote side's sequence number
        (base + 1).  Transition to state TCP_STATE_ESTABLISHED.

        pkt: the incoming packet, a bytes instance
        '''

        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.flags & (TCP_FLAGS_SYN | TCP_FLAGS_ACK) and tcp_hdr.ack == self.base_seq_self + 1:
            
            self.base_seq_other = tcp_hdr.seq

            # Modification to incorporate receive buffer for dynamic 3-way handshake
            self.ack = tcp_hdr.seq + 1
            self.receive_buffer = TCPReceiveBuffer(self.base_seq_other + 1)

            self.send_packet(self.base_seq_self + 1, self.base_seq_other + 1, flags=TCP_FLAGS_ACK)
            self.state = TCP_STATE_ESTABLISHED

    def handle_ack_after_synack(self, pkt: bytes) -> None:
        ip_hdr = IPv4Header.from_bytes(pkt[:IP_HEADER_LEN])
        tcp_hdr = TCPHeader.from_bytes(pkt[IP_HEADER_LEN:TCPIP_HEADER_LEN])
        data = pkt[TCPIP_HEADER_LEN:]

        if tcp_hdr.ack == self.base_seq_self + 1:
            self.state = TCP_STATE_ESTABLISHED


    def continue_connection(self, pkt: bytes) -> None:
        '''
        Continue connection establishment, based on the current state.  This is
        method is called when a client or server receives a TCP packet and it
        is in a state other than TCP_STATE_CLOSED or TCP_STATE_ESTABLISHED.

        pkt: the incoming packet, a bytes instance
        '''

        if self.state == TCP_STATE_LISTEN:
            self.handle_syn(pkt)
        elif self.state == TCP_STATE_SYN_SENT:
            self.handle_synack(pkt)
        elif self.state == TCP_STATE_SYN_RECEIVED:
            self.handle_ack_after_synack(pkt)

        if self.state == TCP_STATE_ESTABLISHED:
            pass


    def send_data(self, data: bytes, flags: int=0) -> None:
        pass

    @classmethod
    def create_packet(cls, src: str, sport: int, dst: str, dport: int,
            seq: int, ack: int, flags: int, data: bytes=b'') -> bytes:

        data_len = len(data)
        pkt_len = TCPIP_HEADER_LEN + data_len
        pkt_ttl = 64

        # Create the IP header
        ip_hdr = IPv4Header(pkt_len, pkt_ttl, IPPROTO_TCP, 0,
                src, dst)
        ip_hdr_bytes = ip_hdr.to_bytes()
        
        # TCP header
        tcp_hdr = TCPHeader(sport, dport, seq, ack, flags, 0)
        tcp_hdr_bytes = tcp_hdr.to_bytes()

        return ip_hdr_bytes + tcp_hdr_bytes + data

    def send_packet(self, seq: int, ack: int, flags: int,
            data: bytes=b'') -> None:
        pkt = self.create_packet(self._local_addr, self._local_port,
                self._remote_addr, self._remote_port,
                seq, ack, flags, data)
        self._send_ip_packet(pkt)

    def handle_data(self, pkt: bytes) -> None:
        pass

    def handle_ack(self, pkt: bytes) -> None:
        pass
