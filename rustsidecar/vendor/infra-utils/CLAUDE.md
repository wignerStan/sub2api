# utils boundary

`utils` is an axisless leaf toolbox. It exposes descriptive modules only; it
must not become a root router, external-dependency facade, runtime supervisor,
or home for owner-specific capability traits.

Keep a helper here only when it provides a real invariant or non-trivial generic
semantics, for example atomic replacement, bounded input, path containment,
SSRF classification, stable hashing, a validated passive value, or a bounded
owner-neutral atomic primitive. State that owns a cache, queue, runtime, or
workflow lifecycle is not owner-neutral and does not belong here.

Do not add:

- stdin/stdout/process relays or Tokio lifecycle code;
- environment/config construction;
- caches, queues, schedulers, retry/readiness/runtime orchestration;
- SQL dialect or database policy;
- `pub use` shims for external crates;
- artifact/report/domain writer contracts.

## YAML exception

`serde_yaml_ng` has no serde_json-style alloc/std feature split. The optional
`utils::yaml` module is therefore allowed as a narrow, bounded pure-memory gate
for meaning/use-flow owners. It must remain default-off, dependency-feature
empty, check input size before parsing, cap output while the serializer writes,
stay free of public reader/writer/filesystem APIs, and expose owned errors rather
than foreign aliases. `front_door(assembly)`, `front_door(entry)`, and `effect_tool` owners
depend on `serde_yaml_ng` directly when they own YAML parsing/rendering.
