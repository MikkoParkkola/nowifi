# Recording the demo GIF

## Prerequisites

```bash
brew install asciinema
cargo install agg  # or: brew install agg
```

## Record

```bash
# From repo root:
asciinema rec demo.cast -c ./demo/record.sh
```

## Convert to GIF

```bash
agg demo.cast demo.gif --theme mocha --font-size 16 --cols 80 --rows 24
```

## Alternative: VHS

```bash
brew install vhs
vhs demo.tape
```
