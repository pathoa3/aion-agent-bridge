# Pass607 Antigravity Minimal Capture Plan

We evaluated whether a new passive capture would help resolve the packet transform and determined that **yes, a targeted minimal capture is highly recommended** to bypass the 31-packet key mutation problem.

## 1. Justification
The current capture contains 31 intermediate C2S packets between the key handshake and the first chat packet. By performing a clean capture and typing the chat message immediately after world entry, we can reduce the intermediate mutation count to nearly zero. An ordinary `/say` capture without the initial `SM_KEY` is useless; the capture must include the complete startup sequence.

## 2. Minimal Timeline for the User
To minimize background traffic and state mutation, follow this sequence:
1. Start Wireshark on the game-client interface.
2. Launch the client and log in.
3. Select character and click "Start Game".
4. **Immediate Action:** The moment your character enters the game world (and is controllable), do **not** move, open any UI elements, or look around. Immediately press Enter and send exactly:
   `/say KXSEQ_001`
5. Wait 5 seconds without moving.
6. Send exactly:
   `/say KXSEQ_002_AAAAAAAA`
7. Wait 5 seconds.
8. Stop the Wireshark capture and save the file.
