# Energy and carbon emissions of human vs. agentic AI-based SOC triage — data and code

Companion repository of the IEEE Access article *"Towards Sustainable Cybersecurity Operations: Comparative Modeling and Measurement-Based Estimation of Energy Consumption and Carbon Emissions in Human versus Agentic AI-Based SOC Triage"* (Y. Aboudrar, K. Bouragba, M. Ouzzif).

Archived version (Zenodo): https://doi.org/10.5281/zenodo.24112833

## What is measured and what is estimated
| Nature | Quantities |
|---|---|
| **Measured** | input/output tokens, latency, number of LLM calls, triage quality (verdict and ATT&CK mapping) |
| **Estimated** | operational energy and CO2e, derived from the measured usage and published coefficients |
| **Assumed** | human handling times and workstation parameters |
| **Projected** | extended reasoning, embodied carbon and water (order-of-magnitude projection) |

## Contents
| Path | Description |
|---|---|
| `agentic_soc_pipeline_v3.ipynb` | Runs the experiment (2 models × 2 architectures × 3 repeats), the paired verbose-alert run, and recomputes every figure and table of the paper |
| `alerts_v2.csv` | 75 curated alerts (50 malicious, 25 benign look-alikes) with ground-truth verdict, ATT&CK tactic and reference techniques |
| `alerts_verbose.csv` | 25 verbose SIEM/EDR-style JSON versions of a subset of the alerts above (paired by `pair_id`, same ground truth) + 8 unchanged control alerts used to detect service drift between runs. No ATT&CK identifier or verdict appears in the JSON; addresses and domains use documentation ranges (RFC 5737 / RFC 2606). The events are synthetic but follow the structure of real exports |
| `make_alerts_verbose.py` | Regenerates `alerts_verbose.csv` deterministically from `alerts_v2.csv` |
| `outputs/run_final/` | Main run (900 pipeline runs): per-call logs (`llm_calls.jsonl`: prompts, responses, input/output tokens, model version, system fingerprint, latency), per-alert outputs, prompts, parameters with sources, and all result tables and figures |
| `outputs/run_verbose/` | Paired verbose-alert run (396 pipeline runs, 990 LLM calls): same logs |
| `requirements.txt` | Python dependencies |
| `LICENSE`, `DATA_LICENSE.md` | Licences for the code and the data |

## File integrity (SHA-256)
| File | SHA-256 |
|---|---|
| `alerts_v2.csv` | `e539575e8ab55cc600241652a6f17684e9bb4adee98aedda2a7ef15ac0263bac` |
| `alerts_verbose.csv` | `a4014634dbc828acfb307227da00fefead594d535783865c12e7aa69b656ffbe` |

Check on Windows: `certutil -hashfile alerts_verbose.csv SHA256` · macOS/Linux: `shasum -a 256 alerts_verbose.csv`

## Reproduce
1. `pip install -r requirements.txt`
2. Open the notebook. To recompute all figures and tables from the released logs **without any API call**, keep `outputs/run_final/` and `outputs/run_verbose/` in place: the notebook skips every run already logged and only redoes the analysis.
3. To re-run the main experiment from scratch, delete `outputs/run_final/`, set `os.environ['SOC_CONFIRM_NEW_RUN'] = '1'` and provide an OpenAI API key when prompted (`DRY_RUN = True` gives a free simulated test).
4. To (re-)run the verbose-alert experiment, set `os.environ['SOC_RUN_VERBOSE'] = '1'` and, for a new run, `os.environ['SOC_CONFIRM_VERBOSE'] = '1'`.

## Settings
- Models `gpt-4o-2024-08-06` and `gpt-4o-mini-2024-07-18`; temperature 0, top-p 1, seed 42; prompt version 2.0.
- Energy coefficients and their sources are listed in the notebook (§3) and in Table 1 of the paper.
- Confidence intervals use a cluster bootstrap over alerts (all repeats of an alert are resampled together); the two architectures are compared with a paired cluster bootstrap.
- Lifecycle projection: server embodied carbon from Luccioni et al. (BLOOM, JMLR 2023); analyst workstation (one desktop + two monitors, 305 kgCO2e) from Dell's lifecycle assessments of the OptiPlex Tower 7020 (Feb. 2024) and P2425H (Mar. 2024), counting manufacturing, distribution and end-of-life (use phase excluded).

## Note on reproducibility
OpenAI has announced the retirement of the two model snapshots used here (shutdown date 2027-01-14). New API calls with these exact snapshots will not be possible after that date, but every analysis remains reproducible from the released logs.

## Citation
Y. Aboudrar, K. Bouragba, and M. Ouzzif, "Towards Sustainable Cybersecurity Operations: Comparative Modeling and Measurement-Based Estimation of Energy Consumption and Carbon Emissions in Human versus Agentic AI-Based SOC Triage," *IEEE Access*, under review, 2026.
