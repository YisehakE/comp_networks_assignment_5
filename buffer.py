class TCPSendBuffer(object):

    def __init__(self, seq: int):
        self.buffer = b''
        self.base_seq = seq
        self.next_seq = self.base_seq
        self.last_seq = self.base_seq

    def bytes_not_yet_sent(self) -> int:
        return self.last_seq - self.next_seq

    def bytes_outstanding(self) -> int:
        return self.next_seq - self.base_seq

    def put(self, data: bytes) -> int:
        self.buffer += data
        self.last_seq += len(data)

    def get(self, size: int) -> tuple[bytes, int]:
        if self.next_seq + size > self.last_seq:
            size = self.last_seq - self.next_seq
        start = self.next_seq - self.base_seq
        data = self.buffer[start:start + size]
        sequence = self.next_seq
        self.next_seq = self.next_seq + size
        return data, sequence

    def get_for_resend(self, size: int) -> tuple[bytes, int]:
        if self.base_seq + size > self.last_seq:
            size = self.last_seq - self.base_seq
        data = self.buffer[:size]
        sequence = self.base_seq
        return data, sequence

    def slide(self, sequence: int) -> None:
        acked = sequence - self.base_seq
        self.buffer = self.buffer[acked:]
        self.base_seq = sequence
        # adjust next in case we slide past it
        if self.next_seq < self.base_seq:
            self.next_seq = self.base_seq


class TCPReceiveBuffer(object):
    def __init__(self, seq: int):
        """ The buffer holds all the data that has been received,
            indexed by starting sequence number. Data may come in out
            of order, so this buffer will order them. Data may also be
            duplicated, so this buffer will remove any duplicate
            bytes."""
        self.buffer = {}
        # starting sequence number
        self.base_seq = seq


    def put(self, data: bytes, sequence: int) -> None:
        """ Add data to the receive buffer. Put it in order of
        sequence number and remove any duplicate data."""
        # ignore old chunk
        if sequence < self.base_seq:
            return
        # ignore duplicate chunk
        if sequence in self.buffer:
            if len(self.buffer[sequence]) >= len(data):
                return
        self.buffer[sequence] = data

        next_seq = -1
        for sequence in sorted(self.buffer.keys()):
            segment = self.buffer[sequence]
            if next_seq < 0:
                next_seq = sequence + len(segment)
                continue

            if next_seq > sequence:
                del self.buffer[sequence]
                segment = segment[next_seq - sequence:]
                sequence = sequence + (next_seq - sequence)
                self.buffer[sequence] = segment
            next_seq = sequence + len(segment)

    def get(self) -> tuple[bytes, int]:
        """ Get and remove all data that is in order. Return the data
            and its starting sequence number. """
        data = b''
        start = self.base_seq
        for sequence in sorted(self.buffer.keys()):
            chunk = self.buffer[sequence]
            if sequence <= self.base_seq:
                # append the data, adjust the base, delete the chunk
                data += chunk[self.base_seq - sequence:]
                self.base_seq += len(chunk) - (self.base_seq - sequence)
                del self.buffer[sequence]
        return data, start
