# Participant Onboarding Guide

Participants connect via `vn connect` or any of the 5 SDKs (`sdks/{rust,javascript,typescript,python,go}`):
1. Generate independent `participant_key` and `node_key`.
2. Verify `/v1/network/info` matches expected `network_id` and `protocol_version`.
3. Request `/v1/participation/challenge` and submit dual-signed `/v1/participation/join`.
4. Submit signed `.vx` programs via `/v1/programs/submit` or `vn program submit <file.vx>`.
