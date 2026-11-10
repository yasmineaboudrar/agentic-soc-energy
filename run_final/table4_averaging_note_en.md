**ATT&CK mapping metrics (Table 4) — averaging procedure.** Predicted techniques were read from the
structured `techniques[].id` field of each agent's JSON output; sub-techniques (e.g., T1059.001) were collapsed to
their parent technique, both in predictions and in the ground truth. For each configuration (model × architecture)
and each of the 3 repeats, metrics were computed over all 75 alerts (50 malicious,
25 benign look-alikes whose ground-truth technique set is empty).
*Precision* and *recall* are **micro-averaged**: true-positive technique matches are summed over all alerts and divided
by the total number of predicted (precision) or ground-truth (recall) techniques; techniques predicted for benign
alerts therefore count as false positives. *Jaccard* is **macro-averaged** over the alerts whose union of predicted
and ground-truth techniques is non-empty (a benign alert with no predicted technique is excluded, as the index is
undefined). We additionally report macro-averaged precision, recall and Jaccard restricted to the 50 malicious
alerts, exact-match rate, and the share of benign alerts for which at least one technique was predicted.
The values in Table 4 are the **mean over the 3 repeats**; the standard deviation between repeats is
reported, and 95% confidence intervals were obtained by a **cluster bootstrap over alerts** (alerts resampled with
replacement, all repeats of a resampled alert kept together; 2000 replicates), so that repeated runs of the same
alert are not treated as independent observations.
