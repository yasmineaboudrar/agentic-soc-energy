# Energy and carbon emissions of human vs. agentic AI-based SOC triage — data and code

Companion repository of the IEEE Access article *"Towards Sustainable Cybersecurity Operations: Comparative Modeling and Empirical Validation of Energy Consumption and Carbon Emissions in Human versus Agentic AI-Based SOC Triage"* (Aboudrar, Bouragba, Ouzzif).

## Contents
| File | Description |
|---|---|
| `alerts_v2.csv` | 75 curated alerts (50 malicious, 25 benign look-alikes) with ground-truth verdict, ATT&CK tactic and reference techniques. SHA-256: `e539575e8ab55cc600241652a6f17684e9bb4adee98aedda2a7ef15ac0263bac` |
| `agentic_soc_pipeline_v2.ipynb` | Runs the experiment (2 models × 2 architectures × 3 repeats) and recomputes every figure of the paper |
| `outputs/run_final/` | Per-call logs (`llm_calls.jsonl`: prompts, responses, input/output tokens, model version, system fingerprint, latency), per-alert outputs, prompts, parameters with sources, and all result tables |
| `scripts/make_fig2_en.py` | Draws Fig. 2 of the paper (eight panels) from the run's summary statistics (per-agent mean tokens; per-alert mean and SD) with the same Monte Carlo settings as the notebook. Its medians and 95% intervals agree with `mc_co2.csv` within about 3%. Output in `figures/` |
| `requirements.txt` | Python dependencies |
| `LICENSE`, `DATA_LICENSE.md` | MIT licence for the code, CC BY 4.0 for the data |

### Files in `outputs/run_final/`
| File | Content |
|---|---|
| `llm_calls.jsonl` | One line per LLM call (2,250 completed calls plus 2 incomplete attempts): prompt, response, input and output tokens, returned model, system fingerprint, latency, repeat |
| `alert_outputs.jsonl` | Outputs of the agents for each alert, configuration and repeat (900 runs) |
| `failures.jsonl` | The two transient failures (re-run successfully) |
| `prompts.json`, `params.json`, `environment.json` | Prompts and settings; parameters with ranges and sources; software versions and alert-file hash |
| `per_alert.csv`, `token_stats.csv`, `agent_stats.csv` | Measured usage (Tables 2–3) |
| `quality.csv`, `soar_quality.json`, `configuration_comparison.csv` | Triage quality (Table 4) |
| `reconciliation.csv`, `theoretical_model.csv` | Energy estimators (Table 5) |
| `central_estimates.csv`, `mc_co2.csv`, `mc_reductions.csv`, `mc_annual.csv` | Emissions and reductions (Table 6, Fig. 2) |
| `tornado.csv`, `grid_scenarios.csv`, `projection_reasoning.csv` | Sensitivity, grid and projection analyses (Fig. 3) |
| `tables.tex`, `figures_paper/` | LaTeX tables and figures exported by the notebook |

## Reproduce
1. `pip install -r requirements.txt`
2. Open the notebook. To recompute all figures from the released logs **without any API call**, keep `outputs/run_final/` in place: the notebook skips the 900 runs already logged and only redoes the analysis.
3. To re-run the experiment from scratch, delete `outputs/run_final/`, set `os.environ['SOC_CONFIRM_NEW_RUN'] = '1'` and provide an OpenAI API key when prompted (`DRY_RUN = True` gives a free simulated test).

## Settings
Models `gpt-4o-2024-08-06` and `gpt-4o-mini-2024-07-18`; temperature 0, top-p 1, seed 42; prompt version 2.0. Energy coefficients and sources are listed in the notebook (§3) and in Table 1 of the paper.
