# bsc — project conventions

## commits
- no Co-Authored-By lines ever
- short polish or english messages, no fluff

## code style
- no doc comments, no section banners
- no over-engineering — minimum code for the task
- binary name: bsc, config: ~/.config/bsc/

## UI style (SEC / DEV / HEX tabs)
- panel section headers: label on its own line, then ─────── line to full column width
- divider between columns: ansiCol(t.HDR) + DIM + "│" + RESET
- no "DETAILS" or other meta-bars between sections
- match OVW visual style: renderCols for summary top, scrollable detail below
