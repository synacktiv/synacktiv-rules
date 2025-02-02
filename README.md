# synacktiv-rules

Public repository of Sigma and YARA rules created by Synacktiv.

All rules in this repository should be considered tagged as **TLP:CLEAR** and **PAP:CLEAR**.

## Prerequisites

When using a Sigma rule, please make sure that you collect and correctly parse required logs as defined in the `logsource` field.

Most of the Sigma rules used for detection are **Correlation Rules**, as defined in [Sigma documentation](https://sigmahq.io/docs/meta/correlations.html), to limit false positives. This entails limited SIEM / Backend support.

## Disclaimer

Some rules in this repository are tagged as `experimental` and should be treated as such.

We would greatly appreciate any feedback.
