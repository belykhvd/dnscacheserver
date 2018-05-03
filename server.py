import os.path
import pickle
import threading
from datetime import datetime

from dns_client import *


class CacheRecord:
    def __init__(self, resource_record):
        self.resource_record = resource_record
        self.expiration_time = (datetime.now().timestamp() + resource_record.ttl if resource_record.ttl else None)

    def __hash__(self):
        return hash(self.resource_record)

    def __eq__(self, other):
        return self.resource_record == other.resource_record

    def __repr__(self):
        return f'{self.resource_record} ' \
               f'{datetime.fromtimestamp(self.expiration_time) if self.expiration_time else "INFINITY"}'


class Cache:
    def __init__(self, database_filename=None, gc_interval=None):
        self.database_filename = database_filename
        self.gc_interval = gc_interval

        self._cache = dict()

        if database_filename and os.path.isfile(database_filename):
            self.init_from_database_file()
        else:
            with open('root-nameservers.txt') as root_nameservers_file:
                string_records = root_nameservers_file.read().split('\n')
            for string_record in string_records:
                domain, ip, ttl = string_record.split()
                self.add_or_update(domain, ResourceRecord(domain, RecordTypes.A, RecordClasses.IN, None, 4, ip))

        self.remove_expired_records()

    def __contains__(self, domain_name):
        return domain_name in self._cache

    def __getitem__(self, domain_name):
        return self._cache[domain_name]

    def init_from_database_file(self):
        with open(self.database_filename, 'rb') as database_file:
            dump_object = pickle.load(database_file)
        self._cache = dump_object['cache']

    def add_or_update(self, domain_name, resource_record, rr_type=None):
        if domain_name not in self._cache:
            self._cache[domain_name] = dict()

        rr_type = resource_record.rr_type if not rr_type else rr_type
        if rr_type not in self._cache[domain_name]:
            self._cache[domain_name][rr_type] = set()

        # Да, да, код правильный. Добавление в set рекорда при текущей реализации
        # методов hash, eq не произойдет, если не удалить старую версию такого же объекта.
        cache_record = CacheRecord(resource_record)
        if cache_record in self._cache[domain_name][rr_type]:
            self._cache[domain_name][rr_type].remove(cache_record)
        self._cache[domain_name][rr_type].add(cache_record)

    def remove(self, domain):
        cache_record = self.domain_to_ip[domain]
        del self.domain_to_ip[domain]
        #del self.ip_to_domain[cache_record.ip]

    def update(self, resource_records):
        cnames = dict()
        for rr in resource_records:
            if rr.rr_type == RecordTypes.CNAME:
                cnames[rr.domain_name] = rr.data
                cnames[rr.data] = rr.domain_name
        for rr in resource_records:
            self.add_or_update(rr.domain_name, rr)
            if rr.domain_name in cnames:
                self.add_or_update(cnames[rr.domain_name], rr)

    def printable(self):
        lines = []
        for domain in self._cache:
            lines.append(domain)
            for rr_type in self._cache[domain]:
                lines.append('\t' + str(rr_type))
                for cache_record in self._cache[domain][rr_type]:
                    lines.append('\t\t' + repr(cache_record))
        return '\n'.join(lines)

    def remove_expired_records(self):
        #print('### Clearing expired records.')
        domains = [domain for domain in self._cache]
        for domain in domains:
            rr_types = [rr_type for rr_type in self._cache[domain]]
            for rr_type in rr_types:
                cache_records = list(self._cache[domain][rr_type])
                for cache_record in cache_records:
                    if not cache_record.expiration_time:
                        continue
                    if cache_record.expiration_time <= datetime.now().timestamp():
                        self._cache[domain][rr_type].remove(cache_record)
                if not self._cache[domain][rr_type]:
                    del self._cache[domain][rr_type]
            if not self._cache[domain]:
                del self._cache[domain]
        #if self.gc_interval:
        #    threading.Timer(self.gc_interval, self.remove_expired_records).start()

    def save_to_database_file(self):
        if not self.database_filename:
            return
        with open(self.database_filename, 'wb') as database_file:
            dump_object = {
                'cache': self._cache
            }
            pickle.dump(dump_object, database_file)


class DnsServer:
    def __init__(self, cache):
        self.cache = cache

    def proceed(self, request_bytes):
        request_transaction = Transaction.parse(request_bytes)
        request_query = request_transaction.queries[0]  # TODO: check if queries
        request_domain, request_rr_type = request_query.domain_name, request_query.rr_type

        # TEST ONLY
        # if request_rr_type != RecordTypes.NS:
        #     return self.refuse_response(request_transaction)

        cache_resource_records = self.try_get_from_cache(request_domain, request_rr_type)
        if cache_resource_records:
            response_bytes = self.generate_answer_response(request_transaction, cache_resource_records)  # TODO: is it unversal way to form response?
            print(f'# Response for {request_domain} found in cache.')
            return response_bytes

        domains = [letter + '.root-servers.net' for letter in 'abcdefghijklm']
        while True:
            response_bytes = self.try_get_response_from_any(domains, request_bytes)
            if not response_bytes:
                print(f'# Requests to domains {domains} are futile. Generating refuse response.')
                return self.refuse_response(request_transaction)

            response_transaction = Transaction.parse(response_bytes)
            answers, authoritative, additional = (response_transaction.answers, response_transaction.authoritative_rrs,
                                                  response_transaction.additional_rrs)
            self.cache.update(answers + authoritative + additional)

            if answers:
                response_bytes = self.generate_answer_response(request_transaction, answers)
                return response_bytes
            if authoritative and authoritative[0].rr_type == RecordTypes.SOA:
                soa_record = authoritative[0]
                self.cache.add_or_update(request_domain, soa_record, RecordTypes.NS)
                return self.generate_soa_response(request_transaction, authoritative[0])
            if not authoritative:
                print(f'Nameserver did not sent authoritative domains. Generating refuse response.')
                return self.refuse_response(request_transaction)
            domains = [rr.data.lower() for rr in authoritative]

    def try_get_response_from_any(self, nameservers, request_bytes, tries_count=2):
        unresolved_nameservers = []
        while nameservers:
            nameserver_domain_name = nameservers.pop()
            resource_records_for_nameserver = self.try_get_from_cache(nameserver_domain_name, RecordTypes.A)
            if not resource_records_for_nameserver:
                unresolved_nameservers.append(nameserver_domain_name)
                continue

            ip = resource_records_for_nameserver[0].data  # TODO: try all until get info
            connection_info = ConnectionInfo(ip, 53, socket.SOCK_STREAM, 2)
            for _ in range(tries_count):
                response_result = DNSTransmissionHandler.request_bytes(request_bytes, connection_info)  # NETWORK TODO: try/except?
                if not response_result.is_success:
                    if str(response_result.error) == DNSClientException.HostUnreachableException:
                        return
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

    @staticmethod
    def generate_answer_response(request_transaction, answers):
        flags = Flags(True, '0000', False, False, True, True, False, False, '0000')
        transaction = Transaction(request_transaction.id, flags, 1, len(answers), 0, 0,
                                  [request_transaction.queries[0]], answers, [], [])
        return transaction.bytes()

    @staticmethod
    def generate_soa_response(request_transaction, soa_record):
        flags = Flags(True, '0000', False, False, True, True, False, False, '0000')
        transaction = Transaction(request_transaction.id, flags, 1, 0, 1, 0,
                                  [request_transaction.queries[0]], [], [soa_record], [])
        return transaction.bytes()

    @staticmethod
    def refuse_response(request_transaction):
        flags = Flags(True, '0000', False, False, True, False, False, False, '0101')
        transaction = Transaction(request_transaction.id, flags, 1, 0, 0, 0, [request_transaction.queries[0]], [], [], [])
        return transaction.bytes()

    def try_get_from_cache(self, domain_name, rr_type):
        if domain_name in self.cache and rr_type in self.cache[domain_name]:
            cache_answers = []
            cache_records = list(self.cache[domain_name][rr_type])
            for cache_record in cache_records:
                if not cache_record.expiration_time or cache_record.expiration_time > datetime.now().timestamp():
                    cache_answers.append(cache_record.resource_record)
                else:
                    self.cache[domain_name][rr_type].remove(cache_record)
            if not self.cache[domain_name][rr_type]:
                del self.cache[domain_name][rr_type]
            return cache_answers


def exit_condition():
    exit_lock.acquire()
    cmd = input()
    while cmd != 'exit':
        if cmd == 'cache':
            print(_cache.printable())
            print()
        cmd = input()
    _cache.save_to_database_file()
    exit_lock.release()


_cache = Cache('database.pickle', 30)
server = DnsServer(_cache)

listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('127.0.0.2', 53))
listener.settimeout(1)

exit_lock = threading.Lock()
threading.Thread(target=exit_condition).start()
start_flag = True
while exit_lock.locked() or start_flag:
    start_flag = False
    try:
        _request_bytes, address = listener.recvfrom(1024)
        print(f'<<< Received request from {address}.')

        _response_bytes = server.proceed(_request_bytes)
        print(f'### Response generated for {address}.')

        listener.sendto(_response_bytes, address)
        print(f'>>> Sent response to {address}.')
        print()
    except socket.timeout:
        pass
    #except Exception as e:
        #print(f'### Some error occurred: {e}')
         #import traceback
         #print(traceback.print_exc())
        #print()
