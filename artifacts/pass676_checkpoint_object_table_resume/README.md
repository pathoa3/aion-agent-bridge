# Pass676 prepared patch

Root cause: `CreateFileMapping*` stores the file backing object in `mapping_handles`; `CloseHandle` removes only the file-handle table entry. This is legitimate mapping lifetime behavior. Pass674 v1 serialized mappings as references to still-open file handles, so it rejected the valid mapping-only object at 200M.

The prepared v2 implementation uses a deterministic synthetic-object table. Both handle tables reference object IDs, preserving:

- open file + mapping aliasing;
- mapping objects after source file-handle closure;
- multiple mapping handles sharing one object;
- distinct objects that happen to contain equal bytes.

Historical Pass674/Pass675 files must remain unchanged. The resume tool loads the validated 150M v1 checkpoint with the unchanged v1 code/identity, executes exactly one 50M segment, then writes a new v2 checkpoint in a non-overwriting Pass676 directory.
