# Gitpod + Mininet: RPL Black Hole Attack (3 Scenarios)

This repo lets you run a *Mininet-based* emulation of three RPL-like scenarios **in your browser via Gitpod**:

1. Clear network (baseline)
2. Selective forwarding (partial black hole) — malicious router drops forwarded traffic but can send its own
3. Complete black hole — malicious router drops forwarded traffic and its own packets

> Note: This is a **conceptual emulation** of an RPL DAG using Linux namespaces and point-to-point links in Mininet.
> We do **not** run Contiki/RPL/DIO control packets. We model multi-hop forwarding and malicious behaviors with routing + iptables.

## How to use (Gitpod)

1. Create a new GitHub repo and upload these three files:
   - `.gitpod.yml`
   - `rpl_blackhole_mininet.py`
   - `README_GITPOD_MININET.md` (this file)
2. Open the repo in Gitpod: `https://gitpod.io/#<your-github-repo-url>`
3. Wait for the setup task to finish (it installs Mininet and tools).
4. In Gitpod terminal, run:
   ```bash
   sudo python3 rpl_blackhole_mininet.py --run-all
   ```
5. The script will:
   - Build a small DAG-like topology (sink + routers + leaves)
   - Execute pings for each scenario
   - Print delivery ratios and average RTTs
   - Save results to `results.json` and `results.csv`

You can also run scenarios manually:

```bash
sudo python3 rpl_blackhole_mininet.py --scenario 1   # clear
sudo python3 rpl_blackhole_mininet.py --scenario 2   # selective forwarding
sudo python3 rpl_blackhole_mininet.py --scenario 3   # complete black hole
```
