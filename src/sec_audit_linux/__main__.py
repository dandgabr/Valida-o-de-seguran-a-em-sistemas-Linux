"""Main execution wrapper for sec_audit_linux."""

import sys
from sec_audit_linux.interfaces.cli import main

if __name__ == "__main__":
    sys.exit(main())
