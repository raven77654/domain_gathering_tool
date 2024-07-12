
import socket
import dns.resolver
import whois

class DomainInspector:
    
    def __init__(self, domain):
        self.domain = domain
    
    def get_ip(self):
        try:
            ip = socket.gethostbyname(self.domain)
            return ip
        except socket.gaierror:
            return None
    
    def get_dns_records(self):
        records = {}
        try:
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                answers = dns.resolver.resolve(self.domain, record_type)
                records[record_type] = [rdata.to_text() for rdata in answers]
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return None
        except dns.resolver.Timeout:
            return None
        return records
    
    def get_whois_info(self):
        try:
            whois_info = whois.whois(self.domain)
            return whois_info
        except Exception as e:
            return None
    
    def gather_info(self):
        info = {}
        info['IP Address'] = self.get_ip()
        info['DNS Records'] = self.get_dns_records()
        info['WHOIS Information'] = self.get_whois_info()
        return info

if __name__ == "__main__":
    domain = input("Enter a domain: ")
    inspector = DomainInspector(domain)
    domain_info = inspector.gather_info()
    
    print("\n--- Domain Information ---\n")
    for key, value in domain_info.items():
        print(f"{key}: {value}\n")
