
from dnslib.server import DNSServer



class ACME_DNSServer:
    def __init__(self, dns_records):
        self.resolver = ACME_DNSResolver(dns_records)
        self.server = DNSServer(self.resolver, port=10053)
        self.dns_records = dns_records


class ACME_DNSResolver:
    def __init__(self,dns_records):
        self.dns_records = dns_records
    def resolve(self, request,handler):
        answer = request.reply()
        for record in self.dns_records:
            answer.add_answer(record)
        return answer