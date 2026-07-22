import os
import sys

# Make the repo root importable so `import flock_tap` works regardless of the
# directory pytest is invoked from.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
