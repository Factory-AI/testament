# Testament naming record

Status: Conditionally approved

Version: 1.0.0

Search date: 2026-08-21

Stable ID: RES-STUDY-NAMING-001

This record supports a narrow decision: the project may keep using
`Testament` and `Factory-AI/testament` for this public research repository.
It does not support a broad claim that the name is legally clear.

The machine-readable source is
[`policy/naming-clearance.json`](../../policy/naming-clearance.json). That
record keeps the exact queries, publishers, source URLs, access dates,
observations, inferences, and residual risk.

## Findings

The search found real collisions:

- npm already has an unrelated unscoped package named `testament`;
- `jergason/testament` is an unrelated public GitHub repository;
- `testament.com`, `testament.org`, and `testament.dev` are registered; and
- Arc System Works uses Testament as a Guilty Gear character and game product.

The PyPI and crates.io exact endpoints had no project at the time of the
search. The IETF Datatracker had no active draft or RFC document matching the
name.

The two trademark searches are unresolved. The USPTO interface accepted the
query but did not return results to the anonymous research browser. WIPO's
Global Brand Database showed a maintenance notice and no usable result set.
Those gaps matter more than the package results.

## Review and decision

`factory-droid[bot]` reviewed the evidence as the assigned research worker, not
as trademark counsel. The review found that the evidence supports continued
limited use, but not a clearance claim.

Eno Reyes, the lead maintainer, is the accountable authority. The decision is
grounded in public foundation commit
`7c468336954921d2bb319bac3f52a7dc46d9ed4c`, which created the public
`Factory-AI/testament` repository and chartered the project under this name.
The approval applies only to this public open-source research repository.

The project must not publish an unscoped npm package called `testament`, claim
the three searched domains, or describe this record as legal advice. Naming
review reopens before a trademark filing, commercial launch, domain adoption,
or expansion into another distribution ecosystem. The scheduled review date
is 2026-11-21.

## Source list

- USPTO, [Trademark search](https://tmsearch.uspto.gov/search/search-results)
- WIPO, [Global Brand Database](https://branddb.wipo.int/en/quicksearch)
- npm, [registry record](https://registry.npmjs.org/testament)
- PyPI, [project endpoint](https://pypi.org/pypi/testament/json)
- crates.io, [crate endpoint](https://crates.io/api/v1/crates/testament)
- GitHub, [unrelated exact repository](https://api.github.com/repos/jergason/testament)
- Google Registry, [`testament.dev` RDAP](https://pubapi.registry.google/rdap/domain/testament.dev)
- Verisign, [`testament.com` RDAP](https://rdap.verisign.com/com/v1/domain/testament.com)
- Public Interest Registry, [`testament.org` RDAP](https://rdap.publicinterestregistry.org/rdap/domain/testament.org)
- IETF, [document search](https://datatracker.ietf.org/doc/search/?name=testament&rfcs=on&activedrafts=on)
- Arc System Works, [Guilty Gear character](https://www.guiltygear.com/ggst/en/character/tst/)

All sources were accessed on 2026-08-21.
