# Licensing policy

Status: Active
Version: 1.0.0
Last updated: 2026-08-21

Testament project code and project-authored documentation are licensed under
Apache-2.0. The root [LICENSE](../LICENSE) contains the complete license text,
and [NOTICE](../NOTICE) contains project and required attribution notices.
Source files should use `SPDX-License-Identifier: Apache-2.0` where the file
format supports comments without changing data semantics.

## Artifact inventory

The authoritative [artifact licensing
inventory](../policy/artifact-licensing.json) covers:

- source code and repository scripts;
- direct and transitive dependencies;
- generated files;
- documentation;
- test and conformance fixtures;
- vendored fonts;
- the notice set itself.

An artifact class with no current files stays in the inventory with status
`none`; absence is accounted for rather than silently omitted. Before adding a
third-party artifact, record its source, version, SPDX expression, applicable
paths, redistribution terms, modifications, and required notice.

## Dependency policy

Core runtime and build dependencies must use compatible permissive terms.
Strong-copyleft dependencies, Server Side Public License material, and Elastic
License 2.0 material are prohibited from the core. Weak-copyleft, font, content,
or attribution licenses require review of the actual distribution boundary and
notice obligations before use.

Generated output inherits Apache-2.0 unless the generator, template, schema, or
source material requires compatible attribution. Generated files must identify
their source and generator so those terms can be evaluated.

Fixtures must be harmless and either project-generated under Apache-2.0 or
covered by explicit compatible redistribution terms. A public URL or API
response is not by itself permission to redistribute content.

Vendored fonts must retain their own license files and notices. No font is
currently vendored.

## Verification

`make verify-foundation` rejects:

- a missing or duplicate artifact class;
- an incomplete inventory entry;
- a missing or altered Apache-2.0 license;
- an identified forbidden core dependency license;
- a missing required notice or public policy document.

Future dependency tooling must expand, not bypass, this policy by resolving
package metadata and transitive notices from pinned manifests and lockfiles.
