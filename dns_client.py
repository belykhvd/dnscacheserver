import argparse
import socket
import sys
from enum import Enum


class Transaction:
    def __init__(self, transaction_id, flags, queries_count, answers_count, authorities_count,
                 additional_rrs_count, queries, answers, authoritative_rrs, additional_rrs):
        self.id = transaction_id
        self.flags = flags
        self.queries_count = queries_count
        self.answers_count = answers_count
        self.authorities_count = authorities_count
        self.additional_rrs_count = additional_rrs_count
        self.queries = queries
        self.answers = answers
        self.authoritative_rrs = authoritative_rrs
        self.additional_rrs = additional_rrs

    @staticmethod
    def default_query_transaction(transaction_id, flags, queries):
        return Transaction(transaction_id, flags, len(queries), 0, 0, 0, queries, [], [], [])

    @staticmethod
    def parse(response):
        reader = ResourceRecordReader(response)

        transaction_id = reader.read_int(2)
        flags = Flags.parse(reader.read(2))

        queries_count = reader.read_int(2)
        answers_count = reader.read_int(2)
        authorities_count = reader.read_int(2)
        additional_rrs_count = reader.read_int(2)

        queries = reader.read_records(TransactionRecordTypes.QUERY, queries_count)
        answers = reader.read_records(TransactionRecordTypes.ANSWER, answers_count)
        authoritative_rrs = reader.read_records(TransactionRecordTypes.ANSWER, authorities_count)
        additional_rrs = reader.read_records(TransactionRecordTypes.ANSWER, additional_rrs_count)

        return Transaction(transaction_id, flags,
                           queries_count, answers_count, authorities_count, additional_rrs_count,
                           queries, answers, authoritative_rrs, additional_rrs)

    def bytes(self):
        raw_bytes = (two_bytes(self.id)
                     + self.flags.bytes()
                     + two_bytes(self.queries_count)
                     + two_bytes(self.answers_count)
                     + two_bytes(self.authorities_count)
                     + two_bytes(self.additional_rrs_count)
                     + b''.join([rr.bytes() for rr in self.queries])
                     + b''.join([rr.bytes() for rr in self.answers])
                     + b''.join([rr.bytes() for rr in self.authoritative_rrs])
                     + b''.join([rr.bytes() for rr in self.additional_rrs]))
        return raw_bytes

    def __str__(self):
        return self._print_properties(str)

    def __repr__(self):
        return self._print_properties(repr)

    def _print_properties(self, func):
        flags = '\r\n' if func == repr else ''
        flags += func(self.flags)
        return '''\
Transaction Id: {0}
Flags: {1}
Questions: {2}
Answer RRs: {3}
Authority RRs: {4}
Additional RRs: {5}
Queries: \r\n{6}
Answers: \r\n{7}
Authoritative nameservers: \r\n{8}
Additional records: \r\n{9}'''.format(self.id, flags, self.queries_count, self.answers_count,
                                      self.authorities_count, self.additional_rrs_count,
                                      '  ' + '\r\n  '.join(map(str, self.queries)),
                                      '  ' + '\r\n  '.join(map(func, self.answers)),
                                      '  ' + '\r\n  '.join(map(func, self.authoritative_rrs)),
                                      '  ' + '\r\n  '.join(map(func, self.additional_rrs)))


class Flags:
    def __init__(self, is_response, operation_code, is_authoritative, is_truncated, is_recursion_desired,
                 is_recursion_available, is_answer_authenticated, is_non_authenticated_data_acceptable, reply_code):
        self.response = is_response
        self.opcode = operation_code
        self.authoritative = is_authoritative
        self.truncated = is_truncated
        self.recursion_desired = is_recursion_desired
        self.recursion_available = is_recursion_available
        self.reserved = '0'
        self.answer_authenticated = is_answer_authenticated
        self.non_authenticated_data = is_non_authenticated_data_acceptable
        self.reply_code = reply_code

    @staticmethod
    def default_query_flags():
        return Flags.parse(b'\x01\x00')  # one standard query, recursion is desired

    @staticmethod
    def parse(flags):
        string_flags = []
        int_flags = int_from_bytes(flags)
        for i in range(15, -1, -1):
            string_flags.append(int_flags & (2 ** i) > 0)
        opcode = ''.join(map(str, map(int, string_flags[1:5])))
        reply_code = ''.join(map(str, map(int, string_flags[11:15])))
        return Flags(string_flags[0], opcode, string_flags[5],
                     string_flags[6], string_flags[7], string_flags[8],
                     string_flags[9], string_flags[10], reply_code)

    def __str__(self):
        return ''.join(self._print_properties())

    def __repr__(self):
        return '''\
  {0}... .... .... .... Is the message a response?
  .{1} {2}... .... .... Operation code
  .... .{3}.. .... .... Is the server is an authority for the domain?
  .... ..{4}. .... .... Is the message truncated?
  .... ...{5} .... .... Do query recursively? (command for DNS resolver)
  .... .... {6}... .... Can the server do recursive queries?
  .... .... .{7}.. .... Reserved bit
  .... .... ..{8}. .... Was the reply data authenticated by the server?
  .... .... ...{9} .... Is non-authenticated data acceptable?
  .... .... .... {10} Reply code'''.format(*self._print_properties())

    def _print_properties(self):
        return (bit(self.response),
                self.opcode[:3], self.opcode[3:],
                bit(self.authoritative),
                bit(self.truncated),
                bit(self.recursion_desired),
                bit(self.recursion_available),
                self.reserved,
                bit(self.answer_authenticated),
                bit(self.non_authenticated_data),
                self.reply_code)

    def bytes(self):
        string = str(self)
        raw_bytes = (int(string[:8], 2).to_bytes(1, 'big')
                     + int(string[8:16], 2).to_bytes(1, 'big'))
        return raw_bytes


class ResourceRecord:
    def __init__(self, domain_name, rr_type, rr_class,
                 time_to_live=None, data_length=None, data=None):
        self.domain_name = domain_name.lower()
        self.rr_type = rr_type
        self.rr_class = rr_class
        self.ttl = time_to_live
        self.data_len = data_length
        self.data = data

    def __hash__(self):
        return hash(self.domain_name) ** 2 + hash(self.data)

    def __eq__(self, other):
        return self.domain_name == other.domain_name and self.data == other.data

    def __str__(self):
        return '{0}: type {1}, class {2}, data: {3}'.format(
            self.domain_name, self.rr_type.name, self.rr_class.name, self.data)

    def __repr__(self):
        return str(self) + '''
    Name: {0}
    Type: {1}
    Class: {2}
    Time to live: {3}
    Data length: {4}
    Data: {5}'''.format(self.domain_name, self.rr_type.name, self.rr_class.name,
                        self.ttl, self.data_len, self.data)

    def bytes(self):
        encoded_data = None
        if self.data:
            if self.rr_type in {RecordTypes.A, RecordTypes.AAAA}:
                encoded_data = encode_ip(self.rr_type, self.data)
            elif self.rr_type in {RecordTypes.NS, RecordTypes.CNAME}:
                encoded_data = encode_name(self.data)
            elif self.rr_type in {RecordTypes.SOA}:
                encoded_data = bytes([int(hx, 16) for hx in self.data.split()])
        raw_bytes = (encode_name(self.domain_name)
                     + self.rr_type.value
                     + self.rr_class.value
                     + (self.ttl.to_bytes(4, 'big') if self.ttl else b'')
                     + ((len(encoded_data).to_bytes(2, 'big') if encoded_data else self.data_len.to_bytes(2, 'big')) if self.data_len else b'')
                     + (encoded_data if self.data else b''))
        return raw_bytes


class ResourceRecordReader:
    def __init__(self, data, offset=0):
        self.data = data
        self.offset = offset

    def read(self, length):
        self.offset += length
        return self.data[self.offset - length:self.offset]

    def read_int(self, length):
        return int.from_bytes(self.read(length), 'big')

    def read_domain_name(self):
        data = self.data
        offset = self.offset

        domain_name = []
        label_max_value = 63
        while data[offset] != 0:
            if data[offset] <= label_max_value:  # is label?        
                count = data[offset]
                domain_name.append(data[offset + 1:offset + 1 + count].decode())
                offset += 1 + count
            else:  # i.e. it's a pointer (ignoring reserved 10 and 01 possibility)
                offset = int.from_bytes(data[offset:offset + 2], 'big') & 0b0011111111111111

        self._skip_domain_name()
        return '.'.join(domain_name)

    def _skip_domain_name(self):
        while self.data[self.offset] != 0 and self.data[self.offset] <= 63:
            self.offset += 1 + self.data[self.offset]
        self.offset += 1 if self.data[self.offset] == 0 else 2

    def read_record(self, tr_type):
        domain_name = self.read_domain_name()
        rr_type = RecordTypes.parse(self.read(2))
        rr_class = RecordClasses.parse(self.read(2))

        if tr_type == TransactionRecordTypes.QUERY:
            return ResourceRecord(domain_name, rr_type, rr_class)

        ttl = self.read_int(4)
        data_len = self.read_int(2)

        if rr_type in (RecordTypes.A, RecordTypes.AAAA):
            data = self.read(data_len)
            data = parse_ip_address(data, rr_type)
        elif rr_type in (RecordTypes.NS, RecordTypes.CNAME):
            data = self.read_domain_name()
        else:
            data = printable_hex(self.read(data_len))

        return ResourceRecord(domain_name, rr_type, rr_class, ttl, data_len, data)

    def read_records(self, tr_type, count):
        return [self.read_record(tr_type) for _ in range(count)]


class TransactionRecordTypes(Enum):
    QUERY = 0
    ANSWER = 1


class RecordTypes(Enum):
    A = b'\x00\x01'
    AAAA = b'\x00\x1c'
    NS = b'\x00\x02'
    CNAME = b'\x00\x05'
    SOA = b'\x00\x06'
    Unknown = b''

    @staticmethod
    def parse(q_type):
        types = {
            b'\x00\x01': RecordTypes.A,
            b'\x00\x1c': RecordTypes.AAAA,
            b'\x00\x02': RecordTypes.NS,
            b'\x00\x05': RecordTypes.CNAME,
            b'\x00\x06': RecordTypes.SOA
        }
        return types[q_type] if q_type in types else RecordTypes.Unknown


class RecordClasses(Enum):
    IN = b'\x00\x01'
    Unknown = b''

    @staticmethod
    def parse(q_class):
        classes = {
            b'\x00\x01': RecordClasses.IN
        }
        return classes[q_class] if q_class in classes else RecordClasses.Unknown


def parse_ip_address(ip, a_type):
    if a_type == RecordTypes.A:
        return '{0}.{1}.{2}.{3}'.format(ip[0], ip[1], ip[2], ip[3])

    elif a_type == RecordTypes.AAAA:
        ip_string = ''.join(['%02x' % int(hex(ip[i])[2:], 16) for i in range(len(ip))])
        return ':'.join([ip_string[i:i + 4] for i in range(0, len(ip_string), 4)])


def parse_name(name):
    domain_name = []
    count = -1
    while count != 0:
        count = name[0]
        domain = name[1:count + 1]
        domain_name.append(domain.decode())
        name = name[count + 1:]
    return '.'.join(domain_name)[:-1]


def encode_name(domain_name):
    if domain_name == '.':
        return b'\x00'

    if domain_name[-1] == '.':
        domain_name = domain_name[:-1]
    domains = domain_name.encode().split(b'.')
    return b''.join(map(lambda domain: bytes([len(domain)]) + domain, domains)) + b'\x00'


def int_from_bytes(int_bytes):
    return int.from_bytes(int_bytes, 'big')


def bit(flag):
    return str(int(flag))


def two_bytes(integer):
    return integer.to_bytes(2, 'big')


def encode_ip(rr_type, ip):
    if rr_type == RecordTypes.A:
        return bytes(map(int, ip.split('.')))
    if rr_type == RecordTypes.AAAA:
        ip_hex = ip.replace(':', '')
        return bytes([int(ip_hex[i:i+2], 16) for i in range(0, len(ip_hex), 2)])


class DNSTransmissionHandler:
    @staticmethod
    def request(transaction, connection_info, attempts_count=1):
        this = DNSTransmissionHandler
        response_result = None
        with connection_info.configure_socket() as sock:
            for i in range(attempts_count):
                response_result = (
                    this._send(transaction.bytes(), sock, connection_info)
                        .then(lambda: this._receive(sock, connection_info))
                )
                if response_result.is_success:
                    break
            if connection_info.protocol == socket.SOCK_STREAM:
                sock.shutdown(socket.SHUT_RDWR)
            return response_result

    @staticmethod
    def request_bytes(transaction_bytes, connection_info, attempts_count=1):
        try:
            this = DNSTransmissionHandler
            response_result = None
            with connection_info.configure_socket() as sock:
                for i in range(attempts_count):
                    response_result = (
                        this._send(transaction_bytes, sock, connection_info)
                            .then(lambda: this._receive(sock, connection_info))
                    )
                    if response_result.is_success:
                        break
                if connection_info.protocol == socket.SOCK_STREAM:
                    sock.shutdown(socket.SHUT_RDWR)
                return response_result
        except OSError:
            return Result.fail(DNSClientException(DNSClientException.HostUnreachableException))

    @staticmethod
    def _send(transaction_bytes, sock, connection_info):
        protocol = connection_info.protocol
        destination = connection_info.get_destination()
        try:
            if protocol == socket.SOCK_STREAM:
                transaction_bytes = len(transaction_bytes).to_bytes(2, 'big') + transaction_bytes
                sock.connect(destination)
                sock.send(transaction_bytes)
            else:
                sock.sendto(transaction_bytes, destination)
        except OSError:
            return Result.fail(DNSClientException(DNSClientException.HostUnreachableException))
        return Result.ok(None)

    @staticmethod
    def _receive(sock, connection_info):
        response = b''
        sock.settimeout(connection_info.timeout)
        try:
            if connection_info.protocol == socket.SOCK_STREAM:
                while len(response) < 2:
                    response += sock.recv(1024)
                length = int.from_bytes(response[:2], 'big')
                response = response[2:]
                while len(response) != length:
                    response += sock.recv(1024)
            else:
                response = sock.recv(1024)  # TODO: maybe, need timeouts composition
        except socket.timeout:
            return Result.fail(DNSClientException(DNSClientException.ReceiveTimeoutException))
        return Result.ok(response)


class ConnectionInfo:
    def __init__(self, ip, port, transmission_protocol, receive_timeout):
        self.ip = ip
        self.port = port
        self.protocol = transmission_protocol
        self.timeout = receive_timeout

    def configure_socket(self):
        return socket.socket(socket.AF_INET if '.' in self.ip else socket.AF_INET6, self.protocol)

    def get_destination(self):
        return (self.ip, self.port) if '.' in self.ip else (self.ip, self.port, 0, 0)


class Result:
    def __init__(self, error, value):
        self.error = error
        self.value = value
        self.is_success = False if error else True

    def then(self, action):
        if not self.is_success:
            return Result.fail(self.error)
        return Result.of(action)

    @staticmethod
    def ok(value):
        return Result(None, value)

    @staticmethod
    def fail(error):
        return Result(error, None)

    @staticmethod
    def of(func):
        try:
            res = func()
            return res if type(res) == Result else Result.ok(res.value)
        except Exception as e:
            return Result.fail(e)


class DNSClientException(Exception):
    ReceiveTimeoutException = "Socket timeout while receiving"
    HostUnreachableException = "Host is unreachable"


class DNSResolver:
    @staticmethod
    def resolve(domain_name, connection_info):
        flags = Flags.default_query_flags()

        query_ipv4 = ResourceRecord(domain_name, RecordTypes.A, RecordClasses.IN)
        query_ipv6 = ResourceRecord(domain_name, RecordTypes.AAAA, RecordClasses.IN)

        transaction_ipv4 = Transaction.default_query_transaction(0, flags, [query_ipv4])
        transaction_ipv6 = Transaction.default_query_transaction(1, flags, [query_ipv6])

        response_ipv4 = DNSTransmissionHandler.request(transaction_ipv4, connection_info, 3)
        #response_ipv6 = DNSTransmissionHandler.request(transaction_ipv6, connection_info, 3)
        return response_ipv4, None

    @staticmethod
    def resolve_recursively(domain_name, transmission_handler):
        response_ipv4 = DNSResolver._poll_nameservers(domain_name, RecordTypes.A, transmission_handler)
        response_ipv6 = DNSResolver._poll_nameservers(domain_name, RecordTypes.AAAA, transmission_handler)
        return response_ipv4, response_ipv6

    @staticmethod
    def _poll_nameservers(domain_name, record_type, transmission_handler):
        next_ip = '199.7.83.42'  # l.root-server.org

        flags = Flags(False, '0000', False, False, False, False, False, False, '0000')
        query = ResourceRecord(domain_name, record_type, RecordClasses.IN)
        transaction = Transaction.default_query_transaction(0, flags, [query])

        response_result = None
        resolved = False
        while not resolved:
            connection_info = ConnectionInfo(next_ip, 53, socket.SOCK_DGRAM, 2)
            response_result = transmission_handler.request(transaction, connection_info, 3)
            if not response_result.is_success:
                return response_result

            response_transaction = Transaction.parse(response_result.value)
            resolved = response_transaction.flags.authoritative
            if not resolved:
                ips = [record.data for record in response_transaction.additional_rrs if record.rr_type == RecordTypes.A]
                if not ips:
                    next_dn = [record.data for record in response_transaction.authoritative_rrs if
                               record.rr_type == RecordTypes.NS][0]
                    next_ip = Transaction.parse(DNSResolver.resolve_recursively(next_dn)[0].value).answers[0].data
                else:
                    next_ip = ips[0]
        return response_result


def printable_response(response, output_format):
    response_transaction = Transaction.parse(response)
    if output_format == 'RAW':
        return printable_hex(response)
    elif output_format == 'CWS':
        return str(response_transaction)
    elif output_format == 'EWS':
        return repr(response_transaction)
    else:
        return '\r\n'.join([answer.data for answer in response_transaction.answers
                            if answer.rr_type in (RecordTypes.A, RecordTypes.AAAA)])


def printable_hex(hex_bytes):
    return ' '.join([hex(b)[2:].zfill(2) for b in hex_bytes])


def print_output(output_results, output_format):
    ipv4_result, ipv6_result = output_results
    if not ipv4_result.is_success:
        print('Cannot resolve DNS name for ipv4:', ipv4_result.error)
    else:
        print('IPv4:\r\n{0}'.format(printable_response(ipv4_result.value, output_format)))

    #if not ipv6_result.is_success:
    #    print('Cannot resolve DNS name for ipv6:', ipv6_result.error)
    #else:
    #    print('IPv6:\r\n{0}'.format(printable_response(ipv6_result.value, output_format)))


def main():
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument('domain_name', help='Domain name to resolve')
    args_parser.add_argument('-ip', dest='dns_ip', default='77.88.8.7', help='DNS server IP address')
    args_parser.add_argument('-port', dest='dns_port', default=53, type=int, help='DNS server port')
    args_parser.add_argument('-protocol', dest='protocol', default='TCP', choices=['TCP', 'UDP'],
                             help='Desired transmission protocol to use')
    args_parser.add_argument('-t', dest='timeout', default=2, type=float, help='Desired socket timeout in seconds')
    args_parser.add_argument('-f', dest='output_format', default='LIST', choices=['LIST', 'CWS', 'EWS', 'RAW'],
                             help='Desired output format')
    args_parser.add_argument('-r', dest='recursively', action='store_true')
    args_vars = args_parser.parse_args(sys.argv[1:])

    domain_name = args_vars.domain_name

    if args_vars.recursively:
        ipv4_result, ipv6_result = DNSResolver.resolve_recursively(domain_name, DNSTransmissionHandler)
    else:
        protocol = socket.SOCK_STREAM if args_vars.protocol == 'TCP' else socket.SOCK_DGRAM
        connection_info = ConnectionInfo(args_vars.dns_ip, args_vars.dns_port, protocol, args_vars.timeout)
        ipv4_result, ipv6_result = DNSResolver.resolve(domain_name, connection_info)

    print_output((ipv4_result, ipv6_result), args_vars.output_format)


if __name__ == '__main__':
    main()
