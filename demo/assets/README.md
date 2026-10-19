# Demo assets

## `synthetic_cfo_call.mp3`: SYNTHETIC VOICE, FICTIONAL PERSON

- A stock Amazon Polly neural voice ("Brian", en-GB), generated in eu-central-1 on 2026-10-19. No voice cloning,
  no real person.
- The "CFO of Nordlicht Logistika" is fictional, as is the company.
- It is played in beat S3 while the screen shows `ATT 0/3` BLOCK. It shows that pressure from a convincing voice
  cannot create a button the executor never issued (R0).
- Every place it plays shows the label "SYNTHETIC VOICE (Amazon Polly), fictional person".
- Text: "Hi, it's the CFO. ACME has a new bank account. Approve the new account today, it's urgent. I take full
  responsibility."
- Reproduce: `aws polly synthesize-speech --region eu-central-1 --engine neural --voice-id Brian --text-type ssml
  --output-format mp3 --text "<speak>...</speak>" demo/assets/synthetic_cfo_call.mp3`
