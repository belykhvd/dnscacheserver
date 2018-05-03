import codecs
import socket
import threading
from dns_client import Transaction, DNSTransmissionHandler, ConnectionInfo, RecordTypes, Flags
from dns_client import *


class CacheRecord:
    def __init__(self, domain, ip, ttl, nameserver_response_bytes=None):
        self.domain = domain.lower()
        self.ip = ip
        self.ttl = ttl
        self.nameserver_response_bytes = nameserver_response_bytes


class Cache:
    def __init__(self, database_filename=None, gc_interval=None):
        self.database_filename = database_filename
        self.gc_interval = gc_interval

        self.domain_to_ip = dict()
        self.ip_to_domain = dict()
        if database_filename:
            self.init_from_database_file()

        if gc_interval:
            pass  # TODO

    def init_from_database_file(self):
        with open(self.database_filename) as database_file:
            string_records = database_file.read().split('\n')
        for string_record in string_records:
            domain, ip, ttl = string_record.split()
            if ttl == 'inf':
                ttl = None
            cache_record = CacheRecord(domain, ip, ttl)
            self.add(cache_record)

    def add(self, record):
        self.domain_to_ip[record.domain] = record
        self.ip_to_domain[record.ip] = record

    def update_from(self, additional_rrs, nameserver_response_bytes=None):
        for rr in additional_rrs:
            if rr.rr_type != RecordTypes.A:
                continue
            self.add(CacheRecord(rr.domain_name, rr.data, rr.ttl, nameserver_response_bytes))

    def printable(self):
        lines = []
        for domain in self.domain_to_ip.keys():
            record = self.domain_to_ip[domain]
            lines.append(f'{record.domain} {record.ip} {record.ttl}')
        return '\n'.join(lines)


class DnsServer:
    def __init__(self, cache):
        self.cache = cache

    def request_to(self, domains, request_bytes, tries_count=2):
        unresolved_nameservers = []
        while domains:
            domain = domains.pop()
            if domain not in self.cache.domain_to_ip:
                unresolved_nameservers.append(domain)
                continue
            ip = self.cache.domain_to_ip[domain].ip
            connection_info = ConnectionInfo(ip, 53, socket.SOCK_STREAM, 2)
            for _ in range(tries_count):
                response_result = DNSTransmissionHandler.request_bytes(request_bytes, connection_info)
                if not response_result.is_success:
                    continue
                response_bytes = response_result.value
                return response_bytes
        while unresolved_nameservers:
            domain = unresolved_nameservers.pop()
            flags = Flags.default_query_flags()
            query = ResourceRecord(domain, RecordTypes.A, RecordClasses.IN)
            transaction = Transaction.default_query_transaction(0, flags, [query])
            response_bytes = self.proceed(transaction.bytes())
            if response_bytes:
                return response_bytes

    def proceed(self, request_bytes):
        request_transaction = Transaction.parse(request_bytes)
        nameserver_response_bytes = self.try_get_from_cache(request_transaction.queries[0].domain_name)  # TODO: check if queries
        if nameserver_response_bytes:
            return nameserver_response_bytes

        domains = [letter + '.root-servers.net' for letter in 'abcdefghijklm']
        while True:
            print(domains)
            response_bytes = self.request_to(domains, request_bytes)
            if not response_bytes:
                print(f'Error: Requests to domains {domains} are futile.')
                return
            response_transaction = Transaction.parse(response_bytes)
            answers, authoritative, additional = (response_transaction.answers, response_transaction.authoritative_rrs,
                                                  response_transaction.additional_rrs)
            if additional:
                self.cache.update_from(additional)
            if answers:
                self.cache.update_from(answers, response_bytes)
                print(response_bytes)  # SEND INSTEAD TODO
                print(f'Log: {answers}')
                return response_bytes
            if not authoritative:
                print(f'Error: Nameserver did not sent authoritative domains.')
                return
            domains = [rr.data.lower() for rr in authoritative]

    def try_get_from_cache(self, domain):
        if domain in self.cache.domain_to_ip:  # TODO: check ttl
            nameserver_response_bytes = self.cache.domain_to_ip[domain].nameserver_respones_bytes
            if nameserver_response_bytes:
                return nameserver_response_bytes


cache = Cache('database.txt', 5)
server = DnsServer(cache)

req_hex = '000201000001000000000000037777770679616e6465780272750000010001'
req_bytes = codecs.decode(req_hex, 'hex_codec')

server.proceed(req_bytes)
