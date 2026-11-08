# Introduction: security reasoning

> Source: [course overview](https://compsec.kisp-lab.org/Memory-Safety-Webbook/course-home.dc.html) · [Introduction](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html). Figures are source snapshots, not current totals.

Source sections: [why security matters](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html#why-security) · [course objective](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html#objective) · [course philosophy](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html#philosophy).

## Why security matters

- Incidents impose financial loss, mass privacy breaches, and physical risk in cars, medical devices and power grids.
- Underground economy: stolen data, exploit kits, malware installs, laundering; pay-per-install services sell access to compromised machines.
- [Anderson et al., 2012](https://doi.org/10.1007/978-3-642-39498-0_12) estimate direct criminal takings versus larger costs of defense/cleanup; the [2019 follow-up](https://www.cl.cam.ac.uk/~rja14/Papers/cost_of_cybercrime.pdf) revisits them. Source chart (US$ millions/year): direct = advance-fee fraud 1,000; banking malware 370; phishing 320; fake escrow 200; fake antivirus 97; stranded traveler 10. Indirect = user cleanup 10,000; business security 10,000; antivirus 3,400; bank countermeasures 1,000; patching 1,000; law enforcement 400; ISP cleanup 40. Totals: 1,997 vs 25,840 (~13×). Defense and lost trust cost money even without a successful attack.
- [Large-breach visualization](https://www.informationisbeautiful.net/visualizations/worlds-biggest-data-breaches-hacks/): hundreds of millions of records; the claimed 1.1-billion-record Aadhaar incident is [disputed by UIDAI](https://www.tribuneindia.com/news/archive/nation/uidai-denies-any-breach-of-aadhaar-data-523469) (it says public search misuse, no biometric database breach).
- Disclosed CVE counts trend upward, but measure both discovery and assignment of IDs: [OSS-Fuzz](https://google.github.io/oss-fuzz/) helped fix >13,000 bugs in ~1,000 projects; CVE Numbering Authorities rose from 24 (2016) to >400 in 40 countries (2024). [NVD annual statistics](https://nvd.nist.gov/vuln/search/statistics?form_type=Basic&results_type=statistics&search_type=all) are a changing dataset (source chart retrieved July 2026). More CVEs ≠ necessarily the same increase in underlying vulnerability rate.
- NVD chart's annual published-CVE counts (complete years; snapshots): 2005–09: 5,010 / 6,659 / 6,596 / 5,664 / 5,778; 2010–14: 4,667 / 4,172 / 5,351 / 5,324 / 8,008; 2015–19: 6,595 / 6,517 / 18,113 / 18,154 / 18,938; 2020–25: 19,222 / 21,950 / 26,431 / 30,949 / 40,704 / 49,972. Do not treat a partial current year as a full year.
- Memory-safety bugs made up ~70% of [Microsoft's patched CVEs over 12 years](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_BlueHatIL/2019_01%20-%20BlueHatIL%20-%20Trends,%20challenge,%20and%20shifts%20in%20software%20vulnerability%20mitigation.pdf) and ~70% of [Chromium's 912 high-severity bugs](https://www.chromium.org/Home/chromium-security/memory-safety/). The [1988 Morris worm](https://spaf.cerias.purdue.edu/tech-reps/823.pdf) exploited a `gets()` overflow in `fingerd` among other routes.

## Threat models ([section](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html#threat-models))

| Component | Question |
|---|---|
| Setup | What is the starting state? |
| Assumptions | What environmental properties are trusted? |
| Attacker capability | What can and cannot the adversary do? |
| Attacker goal | What is a win? |

- A security claim needs a threat model: changing one assumption can invalidate a defense. Use the model to distinguish actual from perceived protection.
- Signed credit card: already signed; merchant physically compares a fresh signature; attacker cannot forge it or collude; goal is to impersonate the owner. Signature check helps *only* under those assumptions. Online/card-not-present fraud never checks a handwritten signature: card numbers/expiry/CVV are entered, attacker obtains details by phishing/breaches/skimmers, aims for purchases at scale; physical signature is irrelevant. CVV, 3-D Secure, tokenization address different threats.

## Attacker economics ([section](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html#economics))

- Compare marginal cost per victim to the attacker with cost to the defender. Security need not make attack impossible: it should make exploitation uneconomical, especially at scale.
- Dangerous quadrant: cheap-to-repeat, expensive-to-defend attacks (e.g. mass malware). Physical access is costly per target; automated abuse/credential stuffing is cheap; public hardware exploits may be cheap to run but hard to mitigate. CAPTCHA shifts automated-abuse cost onto every attempted signup; judge its attacker-cost increase against deployment costs.

<mermaid>
flowchart LR
  T[Threat and explicit threat model] --> A[How attack works]
  A --> D[What defense stops / does not stop]
  D --> C[Attacker cost per victim vs defender cost]
  C --> R[Revise assumptions and repeat]
</mermaid>
## Module and expectations ([syllabus](https://compsec.kisp-lab.org/Memory-Safety-Webbook/00-introduction.dc.html#logistics))

- Analyze each threat → specify threat model → assess defenses and their limits. Attacks are studied to reason about security, not merely to complete CTFs. Lectures teach abstractions; exercises require systems details and independent tinkering.
- Introduction calls Part I “six lectures” but its displayed syllabus lists five entries (00, 1A, 1B, 2, 3); the live [overview](https://compsec.kisp-lab.org/Memory-Safety-Webbook/course-home.dc.html) additionally lists defenses chapters 4–6, including Rust. Follow the overview for this note set rather than treating the introduction's Part I/II division as the site inventory.
- Background: CS2107, C and basic OS processes; self-paced, substantial work. [Prerequisite self-test](prerequisites.md) covers process maps, build stages, x86 calling convention.
- Graded work: individual memory-safety assignment, Rust assignment and a closed-book Part I midterm without retakes. Canvas gives current weights, dates and Q&A times; Canvas Discussions for general questions; Canvas email (CC `diego.meyer@u.nus.edu`) for individual issues. TAs/instructor do not debug your code; weekly online Q&A, no physical tutorials. Credit outside help.
- Policy discrepancy: this introduction says no AI tools in any Part I assignment/exam, while the current [assignment handout](https://compsec.kisp-lab.org/Memory-Safety-Webbook/assignment.html#instructions) says AI is discouraged but permitted if *every prompt and response* is disclosed in `report.pdf`. Check current Canvas/course staff before using AI in assessed work; do not infer permission from these study notes.
