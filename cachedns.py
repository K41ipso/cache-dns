import socket
import struct
import threading
import time
import pickle
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

RECORD_TYPE_MAP = {
    1: 'A',
    2: 'NS',
    12: 'PTR',
    28: 'AAAA'
}

REVERSE_RECORD_TYPE = {v: k for k, v in RECORD_TYPE_MAP.items()}


class DNSCache:
    def __init__(self):
        self._store = {rtype: {} for rtype in RECORD_TYPE_MAP.values()}
        self._lock = threading.Lock()
        self._load()

    def get(self, rtype, name):
        with self._lock:
            entry = self._store.get(rtype, {}).get(name)
            if entry and entry['expires'] > time.time():
                return entry['data']
            elif entry:
                del self._store[rtype][name]
        return None

    def set(self, rtype, name, data, ttl):
        with self._lock:
            self._store[rtype][name] = {
                'data': data,
                'expires': time.time() + ttl
            }

    def cleanup(self):
        with self._lock:
            now = time.time()
            for rtype in self._store:
                expired = [k for k, v in self._store[rtype].items() if v['expires'] < now]
                for k in expired:
                    del self._store[rtype][k]

    def save(self):
        with self._lock:
            try:
                with open('dns_cache.pkl', 'wb') as f:
                    pickle.dump(self._store, f)
                logging.info("Cache persisted to disk")
            except Exception as e:
                logging.error(f"Failed to save cache: {e}")

    def _load(self):
        try:
            with open('dns_cache.pkl', 'rb') as f:
                self._store = pickle.load(f)
            logging.info("Cache loaded from disk")
        except FileNotFoundError:
            logging.info("No cache file found, starting fresh")
        except Exception as e:
            logging.error(f"Failed to load cache: {e}")

    def show(self):
        print("\n=== DNS Cache ===")
        for rtype, records in self._store.items():
            if records:
                print(f"\nType: {rtype}")
                for name, entry in records.items():
                    exp = datetime.fromtimestamp(entry['expires']).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"  {name} -> {entry['data']} (expires {exp})")
        print("=" * 40)


class SimpleDNSServer:
    def __init__(self, listen_addr='127.0.0.1', listen_port=53, upstream=('8.8.8.8', 53)):
        self.addr = (listen_addr, listen_port)
        self.upstream = upstream
        self.cache = DNSCache()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.running = True

    def start(self):
        threading.Thread(target=self._cache_cleaner, daemon=True).start()
        logging.info(f"DNS server listening on {self.addr[0]}:{self.addr[1]}")
        try:
            while self.running:
                data, client = self.sock.recvfrom(512)
                threading.Thread(target=self._process_query, args=(data, client), daemon=True).start()
        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        self.running = False
        self.cache.save()
        self.sock.close()
        logging.info("Server stopped.")

    def _cache_cleaner(self):
        while self.running:
            self.cache.cleanup()
            time.sleep(60)

    def _process_query(self, data, client_addr):
        try:
            qid, qname, qtype = self._parse_query(data)
            rtype = RECORD_TYPE_MAP.get(qtype)
            if rtype:
                cached = self.cache.get(rtype, qname)
                if cached:
                    logging.info(f"Cache hit for {qname} ({rtype})")
                    response = self._build_response(data, cached, qtype)
                    self.sock.sendto(response, client_addr)
                    return

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
                upstream_sock.settimeout(5)
                upstream_sock.sendto(data, self.upstream)
                upstream_resp, _ = upstream_sock.recvfrom(512)
                self.sock.sendto(upstream_resp, client_addr)
                self._update_cache_from_response(upstream_resp)
        except Exception as e:
            logging.error(f"Failed to process query: {e}")

    def _parse_query(self, data):
        qid = struct.unpack('!H', data[:2])[0]
        offset = 12
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            labels.append(data[offset+1:offset+1+length].decode())
            offset += 1 + length
        qname = '.'.join(labels)
        qtype = struct.unpack('!H', data[offset:offset+2])[0]
        return qid, qname, qtype

    def _build_response(self, query, answer, qtype):
        qid = query[:2]
        flags = b'\x81\x80'
        counts = struct.pack('!4H', 1, 1, 0, 0)
        question = query[12:]
        name_ptr = b'\xC0\x0C'
        rtype = struct.pack('!H', qtype)
        rclass = b'\x00\x01'
        ttl = struct.pack('!I', 300)
        if qtype == 1:
            rdata = socket.inet_aton(answer)
            rdlength = struct.pack('!H', 4)
        elif qtype == 28:
            rdata = socket.inet_pton(socket.AF_INET6, answer)
            rdlength = struct.pack('!H', 16)
        else:
            return None
        return b''.join([qid, flags, counts, question, name_ptr, rtype, rclass, ttl, rdlength, rdata])

    def _update_cache_from_response(self, resp):
        try:
            header = struct.unpack('!6H', resp[:12])
            ancount = header[3]
            offset = 12
            for _ in range(header[2]):
                while resp[offset] != 0:
                    offset += 1 + resp[offset]
                offset += 5
            for _ in range(ancount):
                if resp[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while resp[offset] != 0:
                        offset += 1 + resp[offset]
                    offset += 1
                rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', resp[offset:offset+10])
                offset += 10
                rdata = resp[offset:offset+rdlength]
                offset += rdlength
                if rtype in RECORD_TYPE_MAP:
                    name = self._extract_name(resp, 12)
                    if rtype == 1:
                        ip = socket.inet_ntoa(rdata)
                        self.cache.set('A', name, ip, ttl)
                    elif rtype == 28:
                        ip6 = socket.inet_ntop(socket.AF_INET6, rdata)
                        self.cache.set('AAAA', name, ip6, ttl)
        except Exception as e:
            logging.error(f"Failed to update cache from response: {e}")

    def _extract_name(self, data, offset):
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                break
            labels.append(data[offset+1:offset+1+length].decode())
            offset += 1 + length
        return '.'.join(labels)


if __name__ == '__main__':
    server = SimpleDNSServer()
    t = threading.Thread(target=server.start, daemon=True)
    t.start()
    try:
        while True:
            server.cache.show()
            time.sleep(10)
    except KeyboardInterrupt:
        server.shutdown()
