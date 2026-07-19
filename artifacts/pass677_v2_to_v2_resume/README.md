# Pass677 prepared continuation

Purpose: validate the first **v2-to-v2** continuation using the exact immutable
Pass676 200M checkpoint.

The script:

- reconstructs the exact identity embedded by Pass676;
- rejects any source-manifest mismatch;
- loads the 200M checkpoint with the unchanged Pass676 v2 serializer;
- executes at most one 50M clean segment;
- preserves an event checkpoint if the watcher stops before 250M;
- otherwise saves `checkpoint_0250000000_v2`;
- reloads and requires byte-equivalent deterministic state;
- scans only pages changed between 200M and the stop point.

No historical checkpoint or replay artifact is modified.
