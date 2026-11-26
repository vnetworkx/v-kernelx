# tree-sitter-vx

Tree-sitter grammar for Vector Language.

This folder is intended for editor integration, incremental parsing, and syntax
highlighting. The runtime parser is separate and lives in Rust under `src/`.

To generate the parser:

```bash
tree-sitter generate
```

To run Tree-sitter tests:

```bash
tree-sitter test
```
