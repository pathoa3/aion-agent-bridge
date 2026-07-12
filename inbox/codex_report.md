# Codex Report - Pass633 Java Path B Xref Review

Reviewed the Java Path B xref output folder directly. It contains `49` files, including usable Java-exported CSVs and per-function pcode/decompile/disassembly exports.

The stale Pass632 diagnostic wording was corrected in the Pass633 review: the current Java export is not empty. The earlier empty state applied only to the failed Python/PyGhidra export.

Strictly new compared to Pass622: `2` rows, consisting of `FUN_11b59832` and its branch/helper edge to `FUN_11b568d5`. The Java direct-caller rows missing from the Pass632 9-row summary are VM branch/thunk/helper paths, not recv-related callers.

A Pass632 parser bug was found and fixed: Java `path_b_functions.csv` rows with `direct_caller` labels were filtered out because their addresses were not in the old Path B term list. The parser now keeps Java-exported function rows.

No S2C initial key or receive-handshake key derivation path was found.
