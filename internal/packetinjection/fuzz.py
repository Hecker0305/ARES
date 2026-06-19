import sys, json, time, base64, threading

try:
    from boofuzz import *
except ImportError:
    print(json.dumps({"error": "boofuzz not installed"}))
    sys.exit(1)

class FuzzRunner:
    def __init__(self, target_ip, target_port, proto, template):
        self.target_ip = target_ip
        self.target_port = target_port
        self.proto = proto
        self.template = template
        self.results = []
        self.crashes = []
        self.total_sent = 0
        self.running = False

    def build_session(self):
        if self.proto == "tcp":
            proto_def = IP(dst=self.target_ip) / TCP(dport=self.target_port)
        elif self.proto == "udp":
            proto_def = IP(dst=self.target_ip) / UDP(dport=self.target_port)
        elif self.proto == "http":
            proto_def = IP(dst=self.target_ip) / TCP(dport=self.target_port)
        else:
            proto_def = IP(dst=self.target_ip) / TCP(dport=self.target_port)

        protocol_session = Session(
            target=Target(
                connection=TCPSocketConnection(
                    host=self.target_ip,
                    port=self.target_port,
                ) if self.proto in ("tcp", "http") else
                UDPSocketConnection(
                    host=self.target_ip,
                    port=self.target_port,
                )
            ),
            sleep_time=0.1,
        )

        return protocol_session

    def build_http_request(self):
        request = Request("http-request")
        if self.template and self.template.get("fuzz_uri"):
            request.add(Node("uri", "GET / HTTP/1.1\r\n"))
        else:
            request.add(Request("http-fuzz"))
            request.add(Node("method", "GET"))
            request.add(Delim(" ", default_value=" "))
            request.add(Node("path", "/"))
            request.add(Delim(" ", default_value=" "))
            request.add(Node("version", "HTTP/1.1"))
            request.add(Delim("\r\n", default_value="\r\n"))
            request.add(Node("host_header", "Host:"))
            request.add(Delim(" ", default_value=" "))
            request.add(Node("host", self.target_ip))
            request.add(Delim("\r\n", default_value="\r\n"))
            request.add(Node("user_agent", "User-Agent: Mozilla/5.0"))
            request.add(Delim("\r\n", default_value="\r\n"))
            request.add(Node("accept", "Accept: */*"))
            request.add(Delim("\r\n", default_value="\r\n"))
            request.add(Delim("\r\n", default_value="\r\n"))

        return request

    def build_generic_fuzz(self):
        request = Request("generic-fuzz")
        request.add(Block("data-block"))
        request.add(Size("data-block"))
        request.add(String("fuzz-data", default_value=b"A" * 100))
        return request

    def run(self):
        self.running = True
        start = time.time()

        if self.proto == "http":
            req = self.build_http_request()
        else:
            req = self.build_generic_fuzz()

        conn = SocketConnection(self.target_ip, self.target_port, proto=self.proto.upper())

        try:
            fuzzer = FuzzSession(
                target=Target(connection=conn),
            )
            fuzzer.add_request(req)
            fuzzer.fuzz()
        except Exception as e:
            pass

        duration = time.time() - start
        return {
            "target": f"{self.target_ip}:{self.target_port}",
            "proto": self.proto,
            "duration_sec": round(duration, 2),
            "status": "completed",
        }


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(json.dumps({"error": "usage: fuzz.py <target> <port> <proto> [template_json]"}))
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2])
    proto = sys.argv[3].lower()
    template = json.loads(sys.argv[4]) if len(sys.argv) > 4 else None

    runner = FuzzRunner(target, port, proto, template)
    result = runner.run()
    print(json.dumps(result))
