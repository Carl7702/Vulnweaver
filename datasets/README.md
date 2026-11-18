# Published datasets

This directory contains all five fixed dataset partitions used by the project.

| Directory | Split | Cases |
| --- | --- | ---: |
| `01_training_Dtra` | training and validation | 184 |
| `02_evaluation_Dmix` | implementation vulnerabilities | 121 |
| `03_evaluation_Dlog` | business-logic vulnerabilities | 122 |
| `04_evaluation_Dinc` | incident vulnerabilities | 123 |
| `05_practicality_Dcve` | held-out CVE study | 18 |

The release contains case metadata, non-PoC vulnerability reports, and selected source
snapshots where the source is not itself a proof of concept. Generated candidates,
reference PoCs, replay evidence, raw source collections, and temporary build workspaces
are intentionally absent. `checksums.json` records every published payload file.
