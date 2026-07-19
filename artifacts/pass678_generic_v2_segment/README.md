# Pass678 generic v2 segment continuation

This bundle replaces one-off 50M continuation scripts with a parameterized, hash-gated v2 checkpoint runner.

The runner:

- requires the exact source `checkpoint_manifest.json` SHA-256;
- uses the verified manifest's embedded identity with the unchanged v2 loader;
- executes one bounded segment only;
- stops on an established watcher event/blocker or exact requested boundary;
- saves, validates, reloads, and compares the target checkpoint;
- scans only changed pages;
- never resumes an unverified or non-v2 checkpoint.

The first intended use is Pass678: validated Pass677 250M checkpoint to 300M.
