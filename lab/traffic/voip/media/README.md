# RTP media assets

Place G.711 and Opus RTP sample pcaps here (`g711_media.pcap`, `opus_media.pcap`).
SIPp's `-rtp` payload playback or `play_pcap` (SIPp's `replay` action on the media
line) replays them during calls so the ESP inner stream carries realistic VoIP
packet cadence (20 ms / 50 pps per direction, ~172 B payloads for G.711).

Source: any public G.711 sample, or generate with ffmpeg → rtp:
`ffmpeg -re -i sample.wav -ac 1 -ar 8000 -c:a pcm_mulaw -f rtp rtp://127.0.0.1:6004`
