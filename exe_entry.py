# exe_entry.py
# Entry point used by PyInstaller to build the Windows executable.

import sys
from codesentry.cli_main import main

if __name__ == "__main__":
    sys.exit(main())
