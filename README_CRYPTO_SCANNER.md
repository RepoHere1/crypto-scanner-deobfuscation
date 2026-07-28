# Crypto Scanner + Deobfuscation Gadgets

Three tools built for fast triage:

- **`paste_box.py`** — universal messy-text preprocessor. Dump URLs, keys, addresses,
  seed phrases, RPC endpoints, and API keys into `~/paste_box.txt`, then run this
  to auto-feed the rest of the pipeline.
- **`crypto_scanner.py`** — continuously scans a `.jsonl` file for BIP39 mnemonics,
  private keys, high-entropy base64/base58, PEM blocks, and crypto addresses;
  checks balances across blockchains in threads.
- **`deobfuscate.py`** — strips backspace/ANSI-obfuscation to recover original text.

## Paste Box (new)

`~/paste_box.txt` is your scratchpad. Put anything in it:

```text
https://github.com/trufflesecurity/trufflehog
0xdAC17F958D2ee523a2206206994597C13D831ec7
5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
https://solana-mainnet.g.alchemy.com/v2/YOUR_KEY
```

Then run:

```bash
python3 ~/paste_box.py
```

It extracts:

| What | Goes to | Used by |
|---|---|---|
| GitHub URLs / orgs | `~/paste.txt` | `trufflehog-mass` scan |
| Crypto addresses / keys / seeds | `~/.trufflehog_results.jsonl` | `crypto_scanner.py` |
| RPC endpoints | `~/rpc_endpoints.jsonl` | `crypto_scanner.py` balance checks |
| API keys / tokens | `~/api_keys.jsonl` | you / scanners |

### Alchemy key

Your active Alchemy key is already configured:

```bash
export ALCHEMY_API_KEY="mi8wM6xm7rRBMYTCjHfM5"
```

You can override it in `~/.bashrc`, or include Alchemy URLs in `~/paste_box.txt`
and `paste_box.py` will extract the key automatically.

### Built-in RPC roster

`crypto_scanner.py` now uses Alchemy + a long list of public RPCs:

- **ETH:** llama, ankr, cloudflare, publicnode, drpc
- **Polygon:** llama, ankr, polygon-rpc, publicnode
- **Avalanche:** meowrpc, ankr, public-rpc, publicnode
- **BSC:** binance, ankr, publicnode
- **Solana:** Alchemy, mainnet-beta, publicnode, ankr

Any RPC URLs you paste are added to the roster automatically.

## Quick start

```bash
# Process your messy paste box
python3 ~/paste_box.py

# Start everything (mass scan + crypto scanner)
bash ~/launch_all.sh

# Or start just the crypto scanner
bash ~/start_crypto_scanner.sh
```

## Useful aliases

```bash
pastebox      # open ~/paste_box.txt in $EDITOR
pastep        # process paste box and show generated paste.txt
pastestatus   # show extracted RPCs and API keys
scanstatus    # show scanner status
go            # launch all services
```
