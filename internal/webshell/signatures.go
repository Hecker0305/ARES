package webshell

type signatureEntry struct {
	Name     string
	Pattern  string
	Language Language
	Severity Severity
	Weight   int
}

var signatures = []signatureEntry{
	// --- PHP webshell signatures ---
	{Name: "php_eval_base64", Pattern: `eval\s*\(\s*base64_decode\s*\(`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_system_call", Pattern: `system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[`, Language: LangPHP, Severity: SeverityHigh, Weight: 95},
	{Name: "php_passthru", Pattern: `passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[`, Language: LangPHP, Severity: SeverityHigh, Weight: 95},
	{Name: "php_shell_exec", Pattern: `shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\[`, Language: LangPHP, Severity: SeverityHigh, Weight: 95},
	{Name: "php_preg_replace_e", Pattern: `preg_replace\s*\(\s*["']/.*["']\s*,\s*["'].*["']\s*,\s*\.?\$_(GET|POST|REQUEST)`, Language: LangPHP, Severity: SeverityHigh, Weight: 90},
	{Name: "php_exec_backtick", Pattern: "`\\$_(GET|POST|REQUEST|COOKIE|SERVER)\\[", Language: LangPHP, Severity: SeverityHigh, Weight: 85},
	{Name: "php_assert_call", Pattern: `assert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[`, Language: LangPHP, Severity: SeverityHigh, Weight: 90},
	{Name: "php_create_function", Pattern: `create_function\s*\(\s*["'].*["']\s*,\s*\$_(GET|POST|REQUEST)`, Language: LangPHP, Severity: SeverityHigh, Weight: 85},
	{Name: "php_obfuscated_string", Pattern: `\$\w+\s*=\s*["'][\x00-\x08\x0B\x0C\x0E-\x1F]{10,}["']`, Language: LangPHP, Severity: SeverityMedium, Weight: 50},
	{Name: "php_dynamic_func_call", Pattern: `\$_(GET|POST|REQUEST|COOKIE|SERVER)\[[^]]+\]\s*\(`, Language: LangPHP, Severity: SeverityHigh, Weight: 95},
	{Name: "php_wso_kitchen", Pattern: `wso_module|WSO_\d\.\d|wso_shell`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_c99_style", Pattern: `c99shell|c99_\w+`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_b374k", Pattern: `b374k|\$xxo\[\d+\]|\$sx\[\d+\]|\$_\[\w+`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_r57_style", Pattern: `r57|r57shell|c99_`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_china_chopper", Pattern: `\$_=\$_REQUEST;\$_=pack`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_weevely", Pattern: `weevely|eval\(gzinflate\(base64_decode`, Language: LangPHP, Severity: SeverityHigh, Weight: 100},
	{Name: "php_gzinflate", Pattern: `eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(`, Language: LangPHP, Severity: SeverityHigh, Weight: 95},
	{Name: "php_str_rot13", Pattern: `eval\s*\(\s*str_rot13\s*\(`, Language: LangPHP, Severity: SeverityHigh, Weight: 85},
	{Name: "php_xor_obfuscation", Pattern: `\$[a-z]+\s*=\s*\$[a-z]+\s*\^\s*\$[a-z]+`, Language: LangPHP, Severity: SeverityMedium, Weight: 60},
	{Name: "php_pack_decode", Pattern: `eval\(pack\(["']H{2}`, Language: LangPHP, Severity: SeverityHigh, Weight: 90},

	// --- ASP/ASPX webshell signatures ---
	{Name: "asp_wscript_shell", Pattern: `CreateObject\s*\(\s*["']WScript\.Shell["']`, Language: LangASP, Severity: SeverityHigh, Weight: 100},
	{Name: "asp_cmd_execution", Pattern: `cmd\.exe\s*/c`, Language: LangASP, Severity: SeverityHigh, Weight: 95},
	{Name: "aspx_process_start", Pattern: `System\.Diagnostics\.Process\.Start`, Language: LangASPX, Severity: SeverityHigh, Weight: 100},
	{Name: "aspx_request_queries", Pattern: `Request\.(QueryString|Form|Params)\[`, Language: LangASPX, Severity: SeverityHigh, Weight: 85},
	{Name: "asp_serv_createobj", Pattern: `Server\.CreateObject\s*\(\s*["']\w+\.\w+["']`, Language: LangASP, Severity: SeverityHigh, Weight: 90},

	// --- JSP webshell signatures ---
	{Name: "jsp_runtime_exec", Pattern: `Runtime\.getRuntime\(\)\.exec\(`, Language: LangJSP, Severity: SeverityHigh, Weight: 100},
	{Name: "jsp_process_builder", Pattern: `new ProcessBuilder\(`, Language: LangJSP, Severity: SeverityHigh, Weight: 95},
	{Name: "jsp_request_params", Pattern: `request\.getParameter\(["'].*["']\)`, Language: LangJSP, Severity: SeverityMedium, Weight: 70},
	{Name: "jsp_cmd_injection", Pattern: `Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter`, Language: LangJSP, Severity: SeverityHigh, Weight: 100},

	// --- Python webshell signatures ---
	{Name: "python_os_system", Pattern: `os\.system\s*\(\s*request|subprocess\.(call|Popen|run)\s*\(\s*request`, Language: LangPython, Severity: SeverityHigh, Weight: 95},
	{Name: "python_exec_input", Pattern: `exec\s*\(\s*request\.(GET|POST|form|args|values)`, Language: LangPython, Severity: SeverityHigh, Weight: 95},
	{Name: "python_eval_input", Pattern: `eval\s*\(\s*request`, Language: LangPython, Severity: SeverityHigh, Weight: 90},
	{Name: "python_flask_cmd", Pattern: `__import__\s*\(\s*["']os["']\)\.system`, Language: LangPython, Severity: SeverityHigh, Weight: 95},

	// --- Perl webshell signatures ---
	{Name: "perl_system_cgi", Pattern: `system\s*\(\s*\$ENV|system\s*\(\s*param\(`, Language: LangPerl, Severity: SeverityHigh, Weight: 95},
	{Name: "perl_backtick_cgi", Pattern: "`\\$ENV\\{", Language: LangPerl, Severity: SeverityHigh, Weight: 90},
	{Name: "perl_exec_cgi", Pattern: `exec\s*\(\s*param\(`, Language: LangPerl, Severity: SeverityHigh, Weight: 95},

	// --- Generic obfuscation patterns ---
	{Name: "generic_hex_encoding", Pattern: `\\x[0-9a-fA-F]{2,}`, Language: LangGeneric, Severity: SeverityMedium, Weight: 30},
	{Name: "generic_char_obfuscation", Pattern: `chr\(\d{2,3}\)\.(chr\(\d{2,3}\)\.?){5,}`, Language: LangGeneric, Severity: SeverityMedium, Weight: 40},
	{Name: "generic_eval_with_encoding", Pattern: `(eval|execute|exec)\s*\(\s*(base64_decode|gzinflate|str_rot13|pack|unpack)`, Language: LangGeneric, Severity: SeverityHigh, Weight: 85},
	{Name: "generic_var_from_get", Pattern: `\$\w+\s*=\s*\$\$_?(GET|POST|REQUEST|FILES|SERVER)\[`, Language: LangGeneric, Severity: SeverityMedium, Weight: 50},
}
