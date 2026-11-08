# Topic 12 coverage

Source: [Workbook chapter](https://compsec.kisp-lab.org/Memory-Safety-Webbook/cryptographic-primitives.dc.html), complete 276-line extraction read from `/tmp/cs3235-crypto-chapter.txt`.

| Workbook section | Notes |
|---|---|
| 01 | §12.1 |
| 02 | §12.1 |
| 03 | §12.2 |
| 04 | §12.3 |
| 05 | §12.4 |
| 06 | §12.4 |
| 07 | §12.4.1, §12.4.2 |
| 08 | §12.5 |
| 09 | §12.5, §12.5.1, §12.5.2, §12.6 |
| 10 | §12.7 through §12.7.3 |
| Summary | §12.1 to §12.7 |

## Independent supporting references

| Mechanism/example | Exact note section | Independently read primary support |
|---|---|---|
| Public algorithms and protected keys | 12.1 | Kerckhoffs, requirement 2 |
| Correctness; identity counterexample | 12.2 | Franklin §3.3; own counterexample |
| Posterior independence | 12.2 | Shannon, perfect secrecy |
| Equal conditional distributions; Bayes equivalence | 12.2 | Boneh-Shoup §2.1.2; explicit algebra |
| Exhaustive 16-function table | 12.3 | Own enumeration using definitions |
| OTP proof and key requirements | 12.4 | Shannon; Boneh-Shoup theorem 2.5 |
| Key-length bound and computational alternative | 12.4 | Boneh-Shoup theorem 2.5; Boneh stream slides |
| Reuse and known-plaintext recovery | 12.4.1 | Boneh slides, attack 1; own byte arithmetic |
| Controlled alteration | 12.4.2 | Boneh slides, attack 2; own ASCII calculation |
| EUF-CMA; tagging oracle; correctness | 12.5 | Franklin §3.3 |
| Checksum arithmetic | 12.5 | RFC 1071 §1 |
| Tag guessing; shared-key limitations; replay state | 12.5.1 | Bellare-Rogaway chapter 6 |
| HMAC structure; SHA-256 | 12.5.2 | RFC 2104 §§2 to 5; RFC 4231 §4 |
| EtM order and separate keys | 12.6 | RFC 7366 §3; Franklin §3.3 |
| AEAD, headers and nonce uniqueness | 12.6 | RFC 5116 §§2 and 3 |
| Authentication paths and authentic root | 12.7 | Merkle §6 |
| Update verification and trusted cache | 12.7.1 | Gassend et al. §5 |
| Binary-tree cost | 12.7.2 | Own arithmetic; Gassend et al. caching model |
| MEE counter tree; TME distinction | 12.7.3 | Gueron §§3.1 and 3.2; Linux SGX encryption section; Intel 2025 statement |

## Limits and intentional omissions

- Vue-only trace values and interactive state were unavailable in the extraction. Notes replace those displays with computed tables, explicit proofs and a static diagram.
- No implementation or benchmark reproductions are claimed. The table and numeric calculations were checked locally.
- Digital signatures, key exchange, block-cipher modes and cryptanalysis beyond the stated prerequisites remain outside scope.
- The binary MAC tree is a teaching model, not a literal SGX implementation. Later-platform guarantees are qualified by the processor and physical threat model.
- Full cryptographic constructions and proofs for information-theoretic authentication are outside scope.

## Checks

- Recomputed all 16 truth tables: four invertible, six independent, two satisfying both.
- Recomputed dice counts, demonstration ciphertext, pad reuse, ASCII modification and tree arithmetic.
- Checked local cross-link target, diagram delimiters, heading hierarchy and absence of em/en dashes.
- Site build and browser verification belong to integration.

## Final editing pass

Repeated recall answers and duplicate source lists removed; unique details remain in the mapped sections. Question headings replaced with topic names.
