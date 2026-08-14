# Capture ethics & safety

Wiretap **analyzes** binary captures. It does **not** acquire traffic from networks
you do not control.

## Allowed

- Files you own or are authorized to study (`.bin`, `.hex`, PCAP/PCAPNG exports)
- Drop-folder ingest: `wiretap capture --from-dir drops/` / `wiretap watch samples/ --once`
- PCAP file ingest / follow: `wiretap capture --pcap capture.pcap` and
  `wiretap capture --pcap capture.pcap --follow` (tails a **growing file on disk**)
- Stdin / project `samples/`

## Not provided / not in scope

- MITM, SSL stripping, credential theft
- Unauthorized remote access or exploit helpers
- Silent background sniffing of third-party traffic
- Npcap / WinPcap live interface capture (use an external authorized sniffer, then
  point Wiretap at the exported file)

## Separation

**Acquisition ≠ analysis.** Capture adapters only load operator-provided bytes.
Analysis never opens raw sockets for eavesdropping.

On Windows, prefer authorized file drops / named pipes / exported PCAPs rather
than kernel sniffers. `--follow` only watches file size growth of a path you
provide — it is not live packet capture.
