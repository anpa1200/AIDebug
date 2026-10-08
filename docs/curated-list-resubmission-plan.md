# Curated-List Resubmission Plan

The `awesome-malware-analysis` PR was closed because the project did not yet
meet maturity, adoption, documentation, maintenance, and quality expectations.

## What Was Improved

- Added maintainer ownership and release process notes.
- Added roadmap and changelog.
- Added safety model and analyst workflow documentation.
- Added validation plan and deterministic unit tests.
- Added a clearer README evidence table.
- Kept live malware out of examples and documentation.

## What Still Needs Time

As of 8 October 2026, v1.1.0, v2.0.0 and v3.0.0 are published releases, and
[REMnux inclusion](remnux.md) is a verified external integration. These support
maintenance/distribution evidence; they do not establish user counts or
independent detection-quality review. This plan does not record a new
curated-list resubmission.

Some criteria cannot be solved by a same-day documentation commit:

- release age
- third-party adoption
- independent reviews
- external mentions
- sustained issue and maintenance history

## Resubmission Gate

Resubmit only after the project has:

- at least two tagged releases
- passing CI history after the documentation and test improvements
- public usage feedback or third-party references
- complete install and safety docs
- stable examples and outputs

## Suggested Future PR Note

```text
Thanks for the earlier review. I waited to resubmit until the project had
clearer maintainer information, safety documentation, validation notes, CI,
safe sample outputs, and a documented analyst workflow. The tool is still
positioned as analyst-review seed material, not automated malware truth.
```
