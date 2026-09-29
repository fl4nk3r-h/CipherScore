# HLS mirror root (server image)

The server entrypoint generates `stream.m3u8` + `.ts` segments continuously
with ffmpeg's lavfi test source (720p), so the video generator always has
480p–1080p-equivalent segment-burst traffic to pull (mvp.md §3.1 "Video
streaming: ffmpeg to Nginx HLS; client pulls segments at 480p–1080p").

Nginx serves this directory at `http://server-b/hls/`.
