# Synthetic saved waveform bundles

These five HIL 0.10.0 bundles were generated from lab-instruments 0.9.0 synthetic
AD3/SDS804X captures and native check/JUnit records. They are offline fixtures,
not physical qualification or authenticated historical execution. All originals
are embedded; never follow stored file/SDK/endpoint labels.

`mixed.json` has one pass, one failure and one invalid window. A passing-only or
empty page must keep its global failed verdict and JUnit failure/error counts.
`sds.json` retains four-channel preambles/WORD/CSV plus every wire transaction,
including zero-byte RX. Voltage recomputation and HIL XML validation remain
recorded, not rerun by Trace.
