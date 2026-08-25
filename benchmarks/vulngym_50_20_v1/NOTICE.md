# Attribution and transformation notice

This derived split was built from the public Tencent VulnGym v0.1.4 dataset:

- <https://github.com/Tencent/VulnGym>
- source data revision: `cd69f7e163e08485ab5496115ae03439cda6e27e`
- VulnGym license: CC BY 4.0 (see the repository `LICENSE`)

The derived work filters to fully human-reviewed (`verify = 1`) advisory
groups, excludes incomplete repository snapshots, groups by repository and
commit, deterministically samples/splits the remaining tasks, assigns opaque
task identifiers, and separates public test inputs from evaluator-only gold.

VulnGym entries contain short source-code excerpts from several upstream
projects. Those upstream projects may have their own licenses. Reusers should
review the relevant repository license before redistributing excerpts.
