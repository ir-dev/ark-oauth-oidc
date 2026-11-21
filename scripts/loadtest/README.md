# Load test

What produced the numbers in the [scale test report](https://ir-dev.github.io/ark-oauth-oidc/#reviews),
so they can be measured again on the hardware a deployment actually runs on.

**For a scratch provider and a scratch database only.** The seed gives every account one known
password, and the generator signs in as all of them.

```bash
# 1. Start a scratch provider on a scratch database and request any page once, so it creates its schema.
#    ark_oauth_server__BaseUrl must be the address the generator will call.

# 2. Seed it (pg | mysql | sqlite). The password and secret are yours to choose; keep them out of the repository.
python3 scripts/loadtest/seed.py --db pg --password "$LOADTEST_PASSWORD" --client-secret "$LOADTEST_CLIENT_SECRET" \
  --backchannel-uri http://127.0.0.1:5399/bcl \
  | psql "$SCRATCH_DATABASE_URL"

# 3. Build and run.
dotnet build scripts/loadtest/loadgen -c Release
dotnet scripts/loadtest/loadgen/bin/Release/net10.0/loadgen.dll \
  --base http://127.0.0.1:5391 --tenant ark_idp \
  --users 30000 --concurrency 128 \
  --steady 60 --steady-concurrency 256 --rate 400 \
  --out result.json
```

`LOADTEST_PASSWORD` and `LOADTEST_CLIENT_SECRET` are read from the environment when `--password` and
`--client-secret` are not given.

| Option | Default | Meaning |
|---|---|---|
| `--base` | `http://127.0.0.1:5391` | The provider's public address (its `BaseUrl`) |
| `--bases` | | More instances of the same provider, comma separated; each request goes to the next in turn |
| `--tenant` | `ark_idp` | The tenant in the issuer |
| `--client` | `web` | `web` = `load_web`, confidential; `spa` = `load_spa`, public with PKCE |
| `--users`, `--offset` | `1000`, `1` | How many seeded accounts sign in, starting at which |
| `--concurrency` | `64` | Sign-ins in flight at once |
| `--steady` | `30` | Seconds of the steady mix afterwards (40% single sign-on, 30% refresh, 30% UserInfo); `0` skips it |
| `--steady-concurrency` | as `--concurrency` | Operations in flight during the steady mix |
| `--rate` | `0` | Operations a second to hold once everyone is signed in; `0` runs as fast as the provider answers. Open loop: it does not slow down when the provider does, and operations beyond `--steady-concurrency` in flight are counted as shed |
| `--arrival-rate` | `0` | People signing in per second, alongside the steady mix, which then grows with the number signed in. `0` signs everyone in first |
| `--mix` | `sso=40,refresh=30,userinfo=30` | Weights of the operations: `sso`, `refresh`, `userinfo`, `par` (pushed authorization request), `device` (device flow, approved by the signed-in user), `logout` (sign out, then sign in again), `v1` (the legacy flow). `par` and `v1` need `--client web` |
| `--bcl-port` | `0` | Listen on this port for back-channel logout tokens and count them; give the seed the matching `--backchannel-uri` |
| `--insecure` | `false` | `true` accepts any TLS certificate, for a provider on a development certificate |
| `--max-connections` | `8192` | Connections the generator may hold. Keep it high: real users each have their own, and a small pool makes quick requests queue behind slow ones inside the generator |
| `--connection-lifetime` | `300` | Seconds before a connection is recycled, so a load balancer keeps re-spreading them |
| `--window` | `60` | Seconds per progress line: people signed in, operations a second, errors, the generator's own timer lag, and median/95th-percentile response times in that window |
| `--out` | | Write the result as JSON, windows included |

A session that has run out is not an error: the generator signs that user in again, as a person
would, and reports how many times it did. To see sessions expire and the purge keep up within a short
run, start the scratch provider with a small `Oidc:SessionLifetimeMinutes` and
`Oidc:CleanupIntervalMinutes=1`.

The closest thing to a working day is everything at once:

```bash
dotnet scripts/loadtest/loadgen/bin/Release/net10.0/loadgen.dll --base https://idp.scratch.example \
  --users 30000 --arrival-rate 33 --rate 400 --steady 28800 --steady-concurrency 512 \
  --mix "sso=34,refresh=30,userinfo=25,par=5,device=3,logout=2,v1=1" --bcl-port 5399 --out day.json
```

Watch `lag` in the progress lines: it is how late the generator's own timers fire. When it climbs into the
hundreds of milliseconds the generator, or the machine it shares, is out of CPU, and the response
times it reports are no longer the provider's. Run the generator on a machine of its own for numbers
that matter.

A run without `--rate` measures throughput at saturation. A run with it measures response times at
a load you choose, which is the number a user feels. On a laptop, keep the machine awake for the
length of the run (`caffeinate -dimsu <command>` on macOS): a suspended run reports a stall that
never happened.

Sign-in is deliberately expensive (one PBKDF2 per password), so set `Oidc:MaxFailedSignIns=0` on
the scratch provider if the test reuses accounts in ways that would trip the lockout.
