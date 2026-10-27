"""Re-draw Fig. 2 panels (English) from the numbers printed in the run_final notebook output."""
import numpy as np, matplotlib
matplotlib.use("Agg"); import matplotlib.pyplot as plt

P = dict(E_QUERY_WH=(0.16,0.31,0.60), E_OUT_J=(1.0,3.5,4.0), PREFILL=(0.05,0.13,0.30), PUE=(1.09,1.12,1.54),
         CI_CLOUD=(250,350,435), CI_WS=(50,435,750), WS_W=(70,120,250), ATTR=(0.5,1.0,1.0),
         L1=(10,20,45), FULL=(30,70,240), REV=(5,15,30), CLIENT_W=(10,30,60), SOAR_W=(10,30,65))
SOAR_S = 4.48e-6
E1F = {"gpt-4o-2024-08-06":1.0, "gpt-4o-mini-2024-07-18":0.577/0.423}
# per-alert measured stats: n_q, (mean,sd,min,max) prompt, completion, latency(mean,sd,min,max)
CFG = {
 "gpt-4o-2024-08-06_multi_agent":      (4,(1156.7,126.5,933,1512),(986.2,102.6,790,1182),(16.47,5.0,8.7,60.0)),  # 224 regular calls; the single 606.7 s outlier is added below
 "gpt-4o-2024-08-06_single_agent":     (1,(207.5,3.1,202,217),(356.0,72.0,235,518),(3.8,0.8,2.5,8.3)),
 "gpt-4o-mini-2024-07-18_multi_agent": (4,(1195.6,200.3,906,1566),(1026.1,146.9,764,1294),(17.0,7.4,10.4,73.3)),
 "gpt-4o-mini-2024-07-18_single_agent":(1,(207.5,3.1,202,217),(350.9,62.4,224,477),(5.4,1.4,3.2,15.7)),
}
AGENTS = {
 "gpt-4o-2024-08-06_multi_agent": {"triage":(107.5,73.2),"mitre":(182.6,78.7),"investigation":(231.3,411.1),"reporting":(635.3,423.2)},
 "gpt-4o-2024-08-06_single_agent": {"single":(207.5,356.0)},
 "gpt-4o-mini-2024-07-18_multi_agent": {"triage":(107.5,62.0),"mitre":(171.4,105.5),"investigation":(246.9,429.9),"reporting":(669.9,428.6)},
 "gpt-4o-mini-2024-07-18_single_agent": {"single":(207.5,350.9)},
}
TITLE = {"gpt-4o-2024-08-06_multi_agent":"GPT-4o, four agents","gpt-4o-2024-08-06_single_agent":"GPT-4o, single agent",
         "gpt-4o-mini-2024-07-18_multi_agent":"GPT-4o mini, four agents","gpt-4o-mini-2024-07-18_single_agent":"GPT-4o mini, single agent"}
N = 20_000
rng = np.random.default_rng(42)
def tri(k): lo,c,hi = P[k]; return np.full(N,c) if lo==hi else rng.triangular(lo,c,hi,N)
def trunc(m,s,lo,hi): return np.clip(rng.normal(m,s,N),lo,hi)
def lat(m,s,lo,hi):
    sg = np.sqrt(np.log(1+(s/m)**2)); return np.clip(rng.lognormal(np.log(m)-sg**2/2,sg,N),lo,hi)

ORDER = [("Human – L1 triage","L1"),("Human – full investigation","FULL"),("AI only (E1)","AI1"),("AI only (E2)","AI2"),
         ("Hybrid AI (E1) + human review","H1"),("Hybrid AI (E2) + human review","H2"),("Rule-based SOAR (naive baseline)","SOAR")]
report = []
ALL = {}
for cfg,(nq,pt,ct,lt) in CFG.items():
    p = {k:tri(k) for k in P}
    tin, tout, ls = trunc(*pt), trunc(*ct), lat(*lt)
    if cfg == "gpt-4o-2024-08-06_multi_agent":  # one measured alert out of 225 took 606.7 s
        ls = np.where(rng.random(N) < 1/225, 606.7, ls)
    hum = lambda mins: mins/60*p["WS_W"]*p["ATTR"]
    ai1 = nq*p["E_QUERY_WH"]*E1F[cfg.split("_")[0]]
    ai2 = (tout*p["E_OUT_J"] + tin*p["E_OUT_J"]*p["PREFILL"])/3600*p["PUE"]
    cli, rev = ls/3600*p["CLIENT_W"], hum(p["REV"])
    cc, cw = p["CI_CLOUD"]/1000, p["CI_WS"]/1000
    co2 = {"L1":hum(p["L1"])*cw, "FULL":hum(p["FULL"])*cw, "AI1":ai1*cc+cli*cw, "AI2":ai2*cc+cli*cw,
           "H1":ai1*cc+(cli+rev)*cw, "H2":ai2*cc+(cli+rev)*cw, "SOAR":SOAR_S/3600*p["SOAR_W"]*cw}
    for lab,k in ORDER: report.append((cfg,lab,*np.percentile(co2[k],[2.5,50,97.5])))

    ALL[cfg] = co2
    fig, ax = plt.subplots(1,2,figsize=(12,4.2))
    a = AGENTS[cfg]; names = [{"triage":"Triage","mitre":"MITRE","investigation":"Investigation","reporting":"Reporting","single":"Single agent"}[k] for k in a]
    ax[0].bar(names,[v[0] for v in a.values()],label="input (prompt)",color="#8DA0CB")
    ax[0].bar(names,[v[1] for v in a.values()],bottom=[v[0] for v in a.values()],label="output (completion)",color="#FC8D62")
    ax[0].set_ylabel("Mean tokens per call"); ax[0].set_title(f"Measured tokens per agent — {TITLE[cfg]}"); ax[0].legend()
    labs = [l for l,_ in ORDER]
    ax[1].boxplot([co2[k] for _,k in ORDER], orientation='horizontal', showfliers=False)
    ax[1].set_yticks(range(1,len(labs)+1), labs); ax[1].set_xscale("log")
    ax[1].set_xlabel("gCO$_2$e per alert (log scale), Monte Carlo draws")
    ax[1].set_title("Operational emissions per scenario")
    fig.tight_layout()
    for ext in ("png","pdf"): fig.savefig(f"fig_tokens_co2_{cfg}.{ext}", dpi=300)
    plt.close(fig)

for r in report: print(f"{r[0]:38s} {r[1]:34s} {r[2]:9.4g} {r[3]:9.4g} {r[4]:9.4g}")

# ---- combined figure: the four configurations stacked top to bottom, shared x-range on the right ----
fig, axes = plt.subplots(4, 2, figsize=(12, 16), gridspec_kw={"width_ratios": [1, 1.25]})
labs = [l for l, _ in ORDER]
ymax = max(sum(v) for a in AGENTS.values() for v in a.values()) * 1.08
for i, cfg in enumerate(CFG):
    a = AGENTS[cfg]
    names = [{"triage":"Triage","mitre":"MITRE","investigation":"Investigation","reporting":"Reporting","single":"Single agent"}[k] for k in a]
    ax = axes[i][0]
    ax.bar(names, [v[0] for v in a.values()], label="input (prompt)", color="#8DA0CB", width=0.6 if len(a) > 1 else 0.35)
    ax.bar(names, [v[1] for v in a.values()], bottom=[v[0] for v in a.values()], label="output (completion)",
           color="#FC8D62", width=0.6 if len(a) > 1 else 0.35)
    if len(a) == 1: ax.set_xlim(-1, 1)
    ax.set_ylim(0, ymax); ax.set_ylabel("Mean tokens per call")
    ax.set_title(f"({chr(97+2*i)}) Measured tokens per agent — {TITLE[cfg]}", fontsize=11)
    if i == 0: ax.legend(loc="upper left", frameon=False)
    ax = axes[i][1]
    ax.boxplot([ALL[cfg][k] for _, k in ORDER], orientation="horizontal", showfliers=False)
    ax.set_yticks(range(1, len(labs) + 1), labs); ax.set_xscale("log"); ax.set_xlim(1e-10, 1e3)
    ax.set_title(f"({chr(98+2*i)}) Operational emissions per scenario — {TITLE[cfg]}", fontsize=11)
    if i == 3: ax.set_xlabel("gCO$_2$e per alert (log scale), Monte Carlo draws")
fig.tight_layout(h_pad=2.2)
for ext in ("png", "pdf"): fig.savefig(f"fig_tokens_co2_combined.{ext}", dpi=300)
