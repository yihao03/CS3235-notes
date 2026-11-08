# Note writing guide

- Scope: workbook topics 7 through 12. One numbered Markdown file per topic; existing notes stay untouched.
- Read the entire chapter, including examples, interactive explanations and review answers. Read relevant primary references for detail and useful additions. Respect each web source's word budget: distribute detailed explanations across its primary references; do not derive a long paraphrase from a chapter with a 200-word budget.
- Use numbered sections, sentence-case headings, short bullets, comparison tables, essential pseudocode, equations with assumptions, and Mermaid where it explains a mechanism. Avoid dense paragraphs and decorative bold.
- Keep conditions, guarantees, failure modes, distinctions, and historical context. Clearly distinguish historical architectures from current implementations.
- Cite with descriptive Markdown links near supported claims. Mark supplemental principles/examples using blockquotes beginning `> Supplement:`. These are explanations, not direct quotations. Verify extra facts against primary sources.
- Apply humanizer: no em/en dashes in prose, staged openings, inflated claims, repeated closers, fake contrasts or chatbot residue. Preserve technical meaning.
- Use declarative headings. Omit repeated recall tables and source lists when mechanisms and citations already appear inline. Cross-link shared explanations instead of repeating them.
- Each author owns only its assigned topic file and coverage file. Coverage filename: `coverage-N.md`. Enumerate source sections and specific mechanisms/examples, mapping to exact note sections; state omissions and limits. These are review artifacts, not prose padding in study notes.
- Handoff: headings/keywords for index, checks performed, gaps, and reusable writing improvements. Lead owns shared files and integrates patterns.

## Patterns discovered

- An allowed syscall says little about whether its output bytes disclose a secret; state the policy's actual observable inputs.

- Latest user correction: reduce verbosity and AI phrasing. Remove question headings, repeated summaries and ritual labels. Preserve unique technical details.
