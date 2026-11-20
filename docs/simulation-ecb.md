# Offline ECB evidence

Embedded Trace 0.21.0 imports `embedded-sim-runner.ecb-report.v1` with the
explicit `nrf52840-ecb-v1` / Sim Runner 0.16.0 plan identity. It checks the
selected plan/report/artifact hashes, qualification declarations, 16 ordered
PRE/POST snapshots, and guest UART samples. The 32 raw fields cover the data
pointer, END, interrupt mask, mailbox and both guarded key/plaintext/ciphertext
contexts. Each uint32 representation and each exact 16-byte ciphertext string
must match its saved raw span. The fault marker is bound between observation
3 POST and 4 PRE. No AES implementation or firmware policy executes here.

Complete, filtered, empty, moved and Markdown views preserve native errors,
unknown evidence, nominal failures and effect observations. Import success is
not native capture success. Host windows are not encryption latency or physical
event alignment. Hardware crypto, security certification and side-channel
qualification remain false; only public fixture vectors should be used.

Model spans are individually capped at 16 KiB to accommodate 32 numeric fields
with at most four exact lifecycle log lines before each field. UART sample
spans retain their 256-byte cap; existing file/record/JSON bounds still apply.
No subprocesses, sockets, devices or simulator launches occur at runtime.
Saved views reopen only the selected timeline. Acceptance measures warm import
and view cost separately from interpreter startup, cold IO and native wall time.
