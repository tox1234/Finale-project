"""
Author: Ido Shema
Last_updated: 04/05/2025
Description: the protocol
"""

import socket


def encode_protocol(*values: any) -> bytes:
    """
        Encodes a variable number of values into a single byte string.
        Each value is prefixed by its length, followed by '!', then the value
        itself (e.g., "3!foo5!world"). The entire string is UTF-8 encoded.
        :return: bytes: The encoded message as a UTF-8 byte string.
    """
    parts = []
    for value in values:
        value_str = str(value)
        parts.append(f"{len(value_str)}!{value_str}")
    return ''.join(parts).encode('utf-8')


def send_msg(sock: socket.socket, *values: any) -> None:
    """
        Encodes values using encode_protocol and sends them over a socket.
        The values are first encoded into the custom protocol format, then
        transmitted via the provided socket connection.
        :param sock: socket.socket: The socket object for sending data.
        :return: None
    """
    msg = encode_protocol(*values)
    sock.sendall(msg)


def recv_msg(sock: socket.socket, num_values: int) -> list[str]:
    """
        Receives a message formatted by the protocol from a socket.
        It reads the specified number of values, each prefixed by its length
        and delimited by '!'.
        :param sock: socket.socket: The socket object for receiving data.
        :param num_values: int: The number of values expected in the message.
        :return: list[str]: A list of the decoded string values.
        :raises ConnectionError: If the socket is closed unexpectedly during
                                 the receive operation.
    """
    values = []
    for _ in range(num_values):
        length_bytes = b''
        while True:
            char_byte = sock.recv(1)
            if not char_byte:
                raise ConnectionError("Socket closed unexpectedly while reading length.")
            if char_byte == b'!':
                break
            length_bytes += char_byte

        try:
            length = int(length_bytes.decode('utf-8'))
        except ValueError:
            raise ConnectionError("Invalid length prefix received.")

        value_bytes = b''
        remaining_length = length
        while remaining_length > 0:
            chunk = sock.recv(remaining_length)
            if not chunk:
                raise ConnectionError("Socket closed unexpectedly while reading value.")
            value_bytes += chunk
            remaining_length -= len(chunk)
        values.append(value_bytes.decode('utf-8'))
    return values
