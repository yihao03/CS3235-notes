# Topic 11 coverage

Source read: [chapter 11](https://compsec.kisp-lab.org/Memory-Safety-Webbook/trusted-execution-environments.dc.html), all 334 extracted lines, including the final review and discussion answers. Direct opening initially failed; the previous chapter's next link worked. Detailed notes independently use the cited primary references.

| Chapter section | Notes | Preserved mechanism |
|---|---|---|
| 01 | 11.1 | Privilege-stack/root assumptions |
| 02 | 11.1, 11.9 | TCB, availability |
| 03 | 11.1 | Design comparison |
| 04 | 11.1 | Cryptographic tools |
| 05 | 11.2, 11.3 | IMA, extend, replay, nonce, AK/EK, appraisal |
| 06 | 11.4 | Recording versus enforcement |
| 07 | 11.4 | Policy, reset caveat |
| 08 | 11.5 | Key hierarchy, PCR11 |
| 09 | 11.6 | DRTM, locality, SMM |
| 10 | 11.7 | Measurement gaps, identity, generations |
| 11 | 11.8 | Phone architectures |
| 12 | 11.9 | Channels, bugs, physical access |
| Final review | 11.1 to 11.9 | Distinctions retained in main sections |

## Omissions and limits

- Omitted literal lab digests, full shell transcripts and interactive widget output. The notes retain the operations, expected outcomes and PCR 23 reset qualification.
- Omitted the legacy TPM 1.2 command spelling example. The firmware-logo overflow case is retained in 11.6 using the original attack presentation.
- No implementation or command execution claim: TPM, BitLocker and SGX behavior is documentation-based. No physical platform was tested.
- TPM PCR initialization and locality rules vary by platform profile. The notes avoid applying one historical TPM profile to every deployment.
- Intel server memory protection is scoped to the cited generation/design. It is not a claim about every future server.
- No SEV/TDX survey: these are peripheral chapter examples; comparison focuses on the four taught mechanisms and Apple case study.
- Read the authors' primary papers/documentation for added details. Near-claim citations identify attribution; supplementary blockquotes are paraphrases, not quotations.
- Workbook-derived prose is restricted to the brief problem/crypto recap, PCR23 caveat and this short coverage map. Other explanations derive from primary references, with source summaries kept within individual budgets.

## Checks and handoff

- Numbered sections, tables and one native Mermaid sequence diagram.
- Read MarkBind authoring instructions and panel reference; no custom JavaScript.
- Checked local prerequisite target exists; no em/en dashes or decorative bold in prose.
- Static MarkBind generation and link checks passed; browser runtime testing was blocked.
- Index terms: root of trust, TCB, TPM, PCR extend, measured boot, event log, attestation, quote, nonce, AK, EK, cuckoo attack, trusted boot, Secure Boot, sealing, BitLocker, VMK, FVEK, PCR7, PCR11, PCR23, SRTM, DRTM, TXT, GETSEC SENTER, SKINIT, Flicker, XMHF, SMM, SGX, MRENCLAVE, MRSIGNER, EADD, EEXTEND, MEE, AES-XTS, TrustZone, secure monitor, Secure Enclave, sepOS, controlled channel, Foreshadow, TeeRex.

## Final editing pass

Repeated recall answers and duplicate source lists removed; unique details remain in the mapped sections. Question headings replaced with topic names.
