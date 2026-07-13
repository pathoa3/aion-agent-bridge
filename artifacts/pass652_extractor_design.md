# Pass652 Offline 10242 Extractor Design

## Can visible chat be extracted from 10242 now?
No. The current transform tests did not recover exact marker text from 10242 as ASCII, UTF-16LE/BE, NUL-split ASCII, visible-prefix UTF-16LE, or simple transformed marker forms.

## Can visible chat be event-labeled from 10242 now?
Yes, moderately. The C2S 22-byte packets align near marker timestamps and can label visible chat events by timing/metadata, even without plaintext extraction.

## Is 7780 still needed for chat text?
Yes for full text unless future 10242 transforms reveal text. Pass651/652 suggest 7780 S2C remains compressed/encrypted or otherwise opaque for direct text, while 10242 provides event metadata.

## Is the 10242 C2S 22-byte packet a heartbeat, poll, or chat trigger?
It behaves more like a structured event trigger/poll aligned to visible chat timing than a pure heartbeat. Repeat length signals are imperfect, so call it chat-event metadata rather than chat text transport.

## Next offline algorithm
Implement a metadata event labeler: detect nearest C2S 22-byte trigger within +/-4s, pair it with subsequent S2C batch lengths in 1s/3s/5s windows, and label events with confidence from timing and repeat fingerprints.

## Better capture if needed
Use whisper-only markers, 5 repeats per marker, 20-30s spacing, lengths 16/32/64/96 visible chars, clear the log first, suppress LFG/noise where possible, and capture with: host 51.83.147.97 and (tcp port 2106 or tcp port 11000 or tcp port 10242 or tcp portrange 7770-7799).
