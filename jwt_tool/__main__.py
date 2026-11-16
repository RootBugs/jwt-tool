"""Run the jwt-tool CLI: ``python -m jwt_tool ...``."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
