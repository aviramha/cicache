# cicache

A caching HTTP(S) forward proxy for CI jobs, backed by the GitHub Actions cache service.

Start it at the top of a job and every later step's outbound traffic flows through it. Responses
that are safe to reuse — package tarballs, wheels, crates, release binaries, registry blobs — are
served from the cache when present and stored when not. Everything else is forwarded untouched.
The teardown step prints what was hit, what was missed, and why.

The point is uniform coverage of the long tail: the `curl`-a-binary-from-a-release and
`apt-get install` traffic that no per-ecosystem cache action covers, without wiring a cache step
per language.

## Usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start cache proxy
        uses: aviramha/cicache@v0

      # ... the rest of the job, unchanged ...

      - name: Stop cache proxy
        if: always()
        uses: aviramha/cicache/cleanup@v0
```

The action installs a prebuilt binary (Linux and macOS, x86_64 and arm64) and starts the proxy.
Inputs: `version`, `min-size`, `cache-all`, `bypass`, `key-prefix`, `extra-args`.

`start` writes the proxy and trust-store variables into `$GITHUB_ENV`, so later steps pick them up
with no further changes. `stop` must run with `if: always()` — it is what drains the upload queue,
so skipping it on failure means the run stored nothing.

Calling the binary from a plain `run:` step needs one extra step first. GitHub hands the
cache-service variables to JavaScript actions and withholds them from `run:` steps, so without
this the proxy silently falls back to a cache that lives and dies with the job:

```yaml
- uses: actions/github-script@v7
  with:
    script: |
      for (const name of ['ACTIONS_RESULTS_URL', 'ACTIONS_RUNTIME_TOKEN']) {
        if (name.endsWith('TOKEN')) core.setSecret(process.env[name])
        core.exportVariable(name, process.env[name])
      }
- run: cicache start
```

The composite action above already does this. `cicache start` warns when it lands in a job without
the cache service, and `cicache stop` says so again if a run cached nothing.

## How it decides what to cache

HTTPS is opaque to a forward proxy, so the tool generates a CA at startup, terminates TLS itself,
and exports the CA through every trust-store variable it knows about. A response is stored only if
all of the following hold:

| Condition | Rationale |
|---|---|
| Method is `GET` | Nothing else is safe to replay |
| Host is not bypassed | The cache service and its blob storage must not be cached recursively |
| No `Authorization` or `Cookie` on the request | Entries are readable by every later job on the branch |
| URL carries no pre-signed parameters | A key unique per request could never be read back |
| Status is `200` | Redirects and errors are not worth replaying |
| No `no-store` / `no-cache` / `private` | The origin said not to |
| Size within `--min-size .. --max-size` | Small objects cost more in round trips than they save |
| `immutable`, a long `max-age`, or a known artifact URL | Otherwise the entry would go stale at a stable URL |

That last row is what keeps mutable metadata — npm packuments, the PyPI simple index, git
`info/refs` — out of the cache while still catching the artifacts underneath them. `--cache-all`
disables the check; it is fast and wrong for anything that changes at a fixed URL.

Redirects are followed inside the proxy for cacheable requests, so a GitHub release download is
keyed on the stable `github.com/.../releases/download/...` URL rather than the pre-signed target it
redirects to, which differs on every request. `--no-follow-redirects` turns this off.

Cached bodies are stored and replayed as received, with `Accept-Encoding: identity` sent upstream
so a single entry serves every client regardless of what it negotiated. Each entry records a
SHA-256 of its body and is discarded on mismatch rather than served.

## Cache backing

Objects are stored individually in the Actions cache service as a content-addressed key/value
store — one entry per URL, fetched only on a local miss — rather than through the usual archive
restore/save. Archives are the wrong shape here: a proxy cache is by construction a superset of
what any one job needs, entries are immutable so each job would re-upload a growing blob, and both
ends of the transfer land on the job's critical path.

Reads go to a local directory first, so a URL fetched twice in one job costs one round trip.
Writes are queued and drained by `stop`.

**Objects below `--pack-threshold` share a single entry.** The service charges per entry — two
calls to store one object, against a limit shared by every job running at once — so the number of
objects matters far more than their size. Measured on a Rust build: objects of 1 MiB and up are 17
of the 1380 fetched and 69% of the bytes, while the remaining 1363 are only 31%. Storing those
individually exhausts the limit and most of them fail; collected into one entry they cost two
calls. Large objects stay separate, where they also deduplicate across every job and run.

**Which keys the service holds is read once, as a manifest, at the start of the job.** The cache
API is rate limited per job, and a build makes thousands of requests; asking the service about
each one in turn exhausts the limit long before the build finishes and leaves the cache unusable
for the rest of the run. Consulting a local set instead means the service is only called for keys
it actually has, taking calls per job from roughly one-per-request down to one plus the number of
hits and stores. Entries are immutable, so each job files its own manifest under a unique key and
the newest is found by prefix; a job writes back what it read plus what it confirmed storing, so
concurrent jobs do not drop each other's entries.

Three constraints come from the cache service and cannot be designed away:

- **10 GB per repository, with repository-wide LRU eviction.** A cache of everything will fill
  this and start evicting your build caches, which can make CI slower on net. Keep `--min-size`
  high enough that the cache holds artifacts worth a round trip, and consider `--bypass` for hosts
  whose content is already covered by a dedicated cache step.
- **Entries are branch-scoped.** A branch reads what it wrote, plus its base branch and the
  repository default branch. A cache primed on a pull request does not help other pull requests —
  prime on the default branch.
- **Everything in the job's egress passes through the proxy in cleartext**, including tokens on
  requests that are forwarded rather than cached. The process is local to the runner and stores
  nothing from authenticated requests, but it is a chokepoint worth knowing about.

Outside Actions the tool runs on its local cache only, which is what makes `cicache run`
useful for testing the policy against a real workload.

## Toolchains

`start` exports `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` plus `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`,
and `DENO_CERT`. The variables that replace a trust store get a bundle of the system roots plus the
generated CA, so hosts reached outside the proxy keep validating normally.

Two cases need a step of their own:

```yaml
# Java keeps its own trust store
- run: sudo keytool -importcert -cacerts -storepass changeit -noprompt \
         -alias cicache -file "$SSL_CERT_FILE"

# Docker reads the daemon's trust store, not the environment
- run: |
    sudo cp "$SSL_CERT_FILE" /usr/local/share/ca-certificates/cicache.crt
    sudo update-ca-certificates && sudo systemctl restart docker
```

Anything that pins certificates or uses mutual TLS will fail against an intercepting proxy. Add
those hosts to `--bypass`; they are forwarded blind and never cached.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--port` | `0` | Listen port; zero picks a free one |
| `--state-dir` | `$RUNNER_TEMP/cicache` | CA, local objects, request log |
| `--min-size` | `32768` | Smallest response worth an entry |
| `--max-size` | `536870912` | Above this, stream through without buffering |
| `--min-max-age` | `3600` | `max-age` at which a response counts as immutable enough |
| `--cache-all` | off | Store anything cacheable, ignoring freshness |
| `--cache-authorized` | off | Store responses to credentialed requests |
| `--bypass` | — | Extra hosts to forward untouched; suffix-matched |
| `--mitm-ports` | `443,8443` | Ports whose `CONNECT` tunnels are decrypted |
| `--no-follow-redirects` | off | Return redirects instead of following them |
| `--upload-concurrency` | `8` | Concurrent uploads to the cache service |
| `--key-prefix` | `cicache-v1` | Change to invalidate everything previously stored |

## Debugging

```bash
cicache start --state-dir /tmp/cicache --min-size 1024
eval "$(cat /tmp/cicache/state.json | jq -r '"export HTTPS_PROXY=http://127.0.0.1:\(.port)"')"
export SSL_CERT_FILE=/tmp/cicache/ca-bundle.pem
# ... run something ...
cicache stop --state-dir /tmp/cicache
```

Every response carries `X-Cicache: HIT`, `MISS`, or `PASS`. `curl http://127.0.0.1:$PORT/__cicache/stats`
returns the running summary as JSON; `/__cicache/shutdown` stops the proxy.

The request log records a reason on every line that was not a hit, which is the fastest way to
find out why something you expected to be cached was not:

```
MISS                              311.5 KiB    119ms  GET https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz  -> stored
HIT                               311.5 KiB      0ms  GET https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
MISS (no immutability signal)      80.9 KiB    321ms  GET https://pypi.org/simple/requests/
MISS (no-store/no-cache/private)      191 B    278ms  GET https://github.com/o/r/info/refs?service=git-upload-pack
PASS (not a GET)                        0 B    242ms  POST https://github.com/o/r/git-upload-pack
```

## Reusing it from another repository

The action is versioned by a moving major tag, so a consuming workflow pins `@v0` and picks up
patches automatically:

```yaml
- uses: aviramha/cicache@v0
  with:
    # Rust builds pull large artifacts and few small ones; a higher floor keeps the entry
    # count down and leaves more of the 10 GB budget for the build caches.
    min-size: '262144'
    bypass: 'internal.registry.example'
```

Two things to get right when adding it to an existing repository:

- The teardown step needs `if: always()`, or nothing is stored on a failed run.
- The cache budget is shared with every other cache in the repository. Watch whether entries
  start evicting existing build caches before enabling it on the default branch — a cache that
  evicts a warm `target/` directory is a net loss.

## Building

```bash
cargo build --release
cargo test
```

Releases are cut by pushing a `v*` tag: the workflow builds
`{x86_64,aarch64}-unknown-linux-musl` and both macOS targets, publishes the tarballs, and moves
the major tag so `@v1` follows.
