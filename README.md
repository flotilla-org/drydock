# drydock

The substrate for just launching vessels: isolated environments for AI coding agents, on any provider.

Drydock hosts out-of-process provider adaptors behind one HTTP protocol, reaches an agent inside each vessel over a single multiplexed pipe, and carries the vessel's egress. [Flotilla](https://github.com/flotilla-org/flotilla) embeds it; it is also usable on its own.

Status: design decided ([flotilla-org/flotilla#3503](https://github.com/flotilla-org/flotilla/issues/3503)); nothing built yet.

Planned contents:

- the protocol crate: Rust types, the generated OpenAPI document and a drift test;
- language hosts for TypeScript and Python, each with its own version of the provider interface;
- provider modules, Namespace first;
- a conformance suite runnable against any language host or built-in provider.

Licensed under either of Apache License 2.0 or MIT, at your option.
