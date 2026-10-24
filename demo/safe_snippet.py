# CodeGuard demo - SAFE snippet.  Harmless: it only writes a marker file to prove that it actually ran.
# MARKER_DIR is injected by demo/intercept_check.py.
import os


def main():
    path = os.path.join(MARKER_DIR, "ALLOWED.marker")
    with open(path, "w") as handle:
        handle.write("safe snippet executed\n")
    return path


main()
