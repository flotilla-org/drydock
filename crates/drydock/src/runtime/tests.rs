use super::operations::prepare_for_platform;
use super::*;
use drydock_host::reference;

mod lifecycle {
    use super::*;
    // Glue: once shutdown starts, the configuration path must refuse even an
    // empty document rather than creating a new generation of observers.
    #[tokio::test]
    async fn configuration_after_shutdown_is_unavailable() {
        let host = Runtime::new(reference::registry());
        host.shutdown(async {}).await;
        let result = host.configure(&HostConfiguration { modules: vec![], providers: vec![] }).await;
        assert!(matches!(result, Err(ProtocolError::Unavailable { .. })));
    }
    // A vendor factory that never returns must not hold shutdown behind its transaction.
    #[tokio::test]
    async fn shutdown_cancels_hung_configuration() {
        struct HangingModule(Arc<tokio::sync::Notify>);
        #[async_trait::async_trait]
        impl module::Module for HangingModule {
            fn version(&self) -> &str {
                "test"
            }
            async fn configure(&self, _: &ProviderConfiguration, _: Arc<dyn module::HttpClient>) -> Result<Arc<dyn Provider>> {
                self.0.notify_one();
                std::future::pending().await
            }
        }
        let entered = Arc::new(tokio::sync::Notify::new());
        let host = Runtime::new(Registry::from([("hanging".into(), Arc::new(HangingModule(entered.clone())) as Arc<dyn module::Module>)]));
        let request = serde_json::from_value(serde_json::json!({
            "modules": [{"name":"test", "entrypoint":"hanging"}],
            "providers": [{"name":"a", "module":"test", "settings":{}, "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        let configuring = tokio::spawn({
            let host = host.clone();
            async move { host.configure(&request).await }
        });
        entered.notified().await;
        tokio::time::timeout(std::time::Duration::from_secs(1), host.shutdown(async {}))
            .await
            .expect("shutdown must cancel a hung factory");
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), configuring)
            .await
            .expect("configuration must observe shutdown")
            .unwrap();
        assert!(matches!(result, Err(ProtocolError::Unavailable { .. })));
        assert!(host.config.read().await.providers.is_empty());
    }

    // Several uncooperative observers share one grace period, independent of count.
    #[tokio::test(start_paused = true)]
    async fn shutdown_observers_share_grace_period() {
        for count in [0, 1, 4] {
            let host = Runtime::new(reference::registry());
            for _ in 0..count {
                host.tasks.lock().unwrap().push(tokio::spawn(std::future::pending()));
            }
            let start = tokio::time::Instant::now();
            host.shutdown(async {}).await;
            assert!(start.elapsed() <= std::time::Duration::from_secs(5), "observers must share one deadline");
        }
    }
    // Abort cannot force a task out of a blocking vendor poll. Shutdown returns
    // after grace even while that observer still occupies its executor thread.
    #[tokio::test(start_paused = true)]
    async fn shutdown_does_not_await_aborted_non_yielding_observer() {
        let (handle_tx, handle_rx) = std::sync::mpsc::channel();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        // Isolate the deliberately blocking vendor boundary from the test clock.
        let worker = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            runtime.block_on(async {
                let task = tokio::spawn(async move {
                    entered_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                });
                handle_tx.send(task).unwrap();
                let _ = done_rx.await;
            });
        });
        let host = Runtime::new(reference::registry());
        host.tasks.lock().unwrap().push(handle_rx.recv().unwrap());
        entered_rx.recv().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(6), host.shutdown(async {}))
            .await
            .expect("shutdown must not await abort completion");
        drop(release_tx);
        let _ = done_tx.send(());
        worker.join().unwrap();
    }
    // A configure queued at commit when shutdown starts must observe the stop
    // under the write lock and leave neither providers nor observers behind.
    #[tokio::test]
    async fn shutdown_racing_configuration_commit_leaves_no_providers() {
        let host = Runtime::new(reference::registry());
        let request = serde_json::from_value(serde_json::json!({
            "modules": [{"name":"memory", "entrypoint":"reference"}],
            "providers": [{"name":"a", "module":"memory", "settings":{}, "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        let held = host.config.read().await;
        let configuring = tokio::spawn({
            let host = host.clone();
            async move { host.configure(&request).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            // Tokio's write-preferring lock refuses new reads once commit queues.
            while host.config.try_read().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("configure must reach commit");
        // Queue a reader after commit but before shutdown's clear, so it can
        // detect even a transient forbidden commit rather than only final state.
        let config = host.config.clone();
        let committed_state = tokio::spawn(async move { config.read().await.providers.is_empty() });
        tokio::task::yield_now().await;
        let shutdown = tokio::spawn(host.shutdown(async {}));
        let mut stopping = host.stopping.subscribe();
        stopping.wait_for(|stopped| *stopped).await.unwrap();
        drop(held);
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), configuring).await.unwrap().unwrap();
        assert!(matches!(result, Err(ProtocolError::Unavailable { .. })));
        tokio::time::timeout(std::time::Duration::from_secs(1), shutdown).await.unwrap().unwrap();
        assert!(host.config.read().await.providers.is_empty());
        assert!(host.tasks.lock().unwrap().is_empty());
        assert!(committed_state.await.unwrap(), "a stopping configure must never commit providers");
    }
}

mod operation_tests {
    use super::module::*;
    use super::*;

    // A basic adapter supplies only core operations, without optional method stubs.
    struct Basic(Arc<dyn Provider>, bool);
    #[async_trait::async_trait]
    impl Provider for Basic {
        fn observation(&self) -> ObservationMode {
            self.0.observation()
        }
        fn capabilities(&self) -> Capabilities {
            let mut c = self.0.capabilities();
            if self.1 {
                return c;
            }
            c.fallback_runner = false;
            c.suspend_resume = false;
            c.export = false;
            c.usage = false;
            c.quota = false;
            c
        }
        async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
            self.0.prepare(r, c).await
        }
        async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
            self.0.provision(r, c).await
        }
        async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
            self.0.list(c).await
        }
        async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
            self.0.inspect(id, c).await
        }
        async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
            self.0.destroy(id, c).await
        }
        async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
            self.0.reach(id, c).await
        }
        async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
            self.0.relay(id, c).await
        }
    }

    // Reports a platform other than the one it was asked for.
    struct Lying(Arc<dyn Provider>);
    #[async_trait::async_trait]
    impl Provider for Lying {
        fn observation(&self) -> ObservationMode {
            self.0.observation()
        }
        fn capabilities(&self) -> Capabilities {
            self.0.capabilities()
        }
        async fn prepare(&self, r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
            Ok(Prepared { platform: Platform::new("linux", "riscv64"), ..self.0.prepare(r, c).await? })
        }
        async fn provision(&self, r: ProvisionRequest, c: &Credentials) -> Result<Provisioned> {
            self.0.provision(r, c).await
        }
        async fn list(&self, c: &Credentials) -> Result<Vec<ObservedEnvironment>> {
            self.0.list(c).await
        }
        async fn inspect(&self, id: &str, c: &Credentials) -> Result<ObservedEnvironment> {
            self.0.inspect(id, c).await
        }
        async fn destroy(&self, id: &str, c: &Credentials) -> Result<()> {
            self.0.destroy(id, c).await
        }
        async fn reach(&self, id: &str, c: &Credentials) -> Result<Connection> {
            self.0.reach(id, c).await
        }
        async fn relay(&self, id: &str, c: &Credentials) -> Result<ByteStream> {
            self.0.relay(id, c).await
        }
    }

    struct BasicModule(bool);
    #[async_trait::async_trait]
    impl Module for BasicModule {
        fn version(&self) -> &str {
            "test"
        }
        async fn configure(&self, config: &ProviderConfiguration, http: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
            Ok(Arc::new(Basic(reference::ReferenceModule.configure(config, http).await?, self.0)))
        }
    }

    // Registration accepts a core-only module and transactionally refuses a
    // module advertising optional capabilities without the corresponding ports.
    #[tokio::test]
    async fn registration_requires_matching_operation_ports() {
        for advertise in [false, true] {
            let host = Runtime::new(Registry::from([("basic".into(), Arc::new(BasicModule(advertise)) as Arc<dyn Module>)]));
            let request = serde_json::from_value(serde_json::json!({
                "modules": [{"name":"memory", "entrypoint":"basic"}],
                "providers": [{"name":"a", "module":"memory", "settings":{},
                    "credential":{"mode":"direct","credential_reference":"test"}}]
            }))
            .unwrap();
            let result = host.configure(&request).await;
            assert_eq!(result.is_ok(), !advertise);
            assert_eq!(host.config.read().await.providers.is_empty(), advertise);
            if advertise {
                assert!(matches!(result, Err(ProtocolError::Refused { .. })));
            }
            host.shutdown(async {}).await;
        }
    }

    async fn instance(operation: &str) -> Arc<Instance> {
        let host = Runtime::new(reference::registry());
        let request = serde_json::from_value(serde_json::json!({
            "modules": [{"name":"memory", "entrypoint":"reference"}],
            "providers": [{"name":"a", "module":"memory", "settings":{"rate_limits":[{"operation":operation,"requests":1,"period_seconds":1}]},
                "credential":{"mode":"direct","credential_reference":"test"}}]
        })).unwrap();
        host.configure(&request).await.unwrap();
        // Exercise admission deterministically without the automatic observation loop.
        for task in host.tasks.recover().drain(..) {
            task.abort();
        }
        host.credential("a", Secret::new("token")).await.unwrap();
        tokio::task::yield_now().await;
        host.instance("a").await.unwrap()
    }

    // A denied single-slot poll reserves the next free slot, even when routes
    // arrive first every window. Routes regain the slot after observation succeeds.
    #[tokio::test(start_paused = true)]
    async fn single_slot_poll_cannot_starve() {
        for scope in ["list", "*"] {
            let i = instance(scope).await;
            for _ in 0..3 {
                assert!(i.reserve("list", false).is_ok());
                assert!(matches!(i.reserve("list", true), Err(ProtocolError::RateLimited { .. })));
                i.auth.recover().rejected = true;
                for poll in [false, true] {
                    let result: Result<()> =
                        i.call_with_budget(Gate::List, poll, |_, _| async { panic!("unready calls must not reach provider") }).await;
                    assert!(matches!(result, Err(ProtocolError::Unavailable { .. })));
                }
                i.auth.recover().rejected = false;
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
                assert!(matches!(i.reserve("list", false), Err(ProtocolError::RateLimited { .. })));
                assert!(i.reserve("list", true).is_ok());
                tokio::time::advance(std::time::Duration::from_secs(2)).await;
            }
        }
    }

    // The same host gate refuses absent optional operations without entering a
    // provider. Core-only adapters remain usable through Arc<dyn Provider>.
    #[tokio::test]
    async fn basic_provider_needs_no_optional_stubs() {
        let mut i = instance("list").await;
        let i = Arc::get_mut(&mut i).unwrap();
        i.provider = Arc::new(Basic(i.provider.clone(), false));
        i.capabilities = i.provider.capabilities();
        assert!(
            i.call(Gate::Prepare, |p, c| async move {
                p.prepare(
                    PrepareRequest {
                        platform: Some(Platform::new("linux", "amd64")),
                        route: None,
                        image_pull: None,
                        size: drydock_protocol::Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 },
                        image_digest: "image".into(),
                        tools_digest: "tools".into(),
                    },
                    &c,
                )
                .await
            })
            .await
            .is_ok()
        );
        for gate in [Gate::Exec, Gate::Suspend, Gate::Resume, Gate::Export, Gate::Usage, Gate::Quota] {
            let result: Result<()> = i.call(gate, |_, _| async { panic!("unsupported port must never be invoked") }).await;
            assert!(matches!(result, Err(ProtocolError::Refused { .. })));
        }
    }
    // The server defaults and checks the platform and image route for every
    // module, and a module that reports building something else is an internal
    // error, not a success.
    #[tokio::test]
    async fn prepare_resolves_and_checks_the_platform() {
        let i = instance("list").await;
        let request = |platform: Option<Platform>| PrepareRequest {
            platform,
            route: None,
            image_pull: None,
            size: drydock_protocol::Size { cpus: 2.0, memory_bytes: 4 << 30, disk_bytes: 10 << 30 },
            image_digest: "image".into(),
            tools_digest: "tools".into(),
        };
        let first = i.provider.capabilities().platforms[0].clone();
        let prepared = i.call(Gate::Prepare, |p, c| async move { prepare_for_platform(&*p, request(None), &c).await }).await.unwrap();
        assert_eq!(prepared.platform, first);
        let undeclared = i
            .call(Gate::Prepare, |p, c| async move { prepare_for_platform(&*p, request(Some(Platform::new("linux", "s390x"))), &c).await })
            .await;
        assert!(matches!(
            undeclared,
            Err(ProtocolError::ImageRefused { refusal: ImageRefusal::UnsupportedPlatform { .. }, reason }) if reason.contains("cannot run linux/s390x; it offers")
        ));
        let undeclared_route = i
            .call(Gate::Prepare, |p, c| async move {
                prepare_for_platform(&*p, PrepareRequest { route: Some(ImageRouteKind::RemoteBuild), ..request(None) }, &c).await
            })
            .await;
        assert!(matches!(undeclared_route, Err(ProtocolError::Refused { reason }) if reason.contains("no remote_build image route")));
        let lying = Lying(i.provider.clone());
        let c = Credentials::new(CredentialMode::Direct { credential_reference: "test".into() });
        let error = prepare_for_platform(&lying, request(None), &c).await.unwrap_err();
        assert!(
            matches!(error, ProtocolError::Internal { ref reason, .. } if reason == &format!("module prepared linux/riscv64 for a {first} request")),
            "{error:?}"
        );
    }
    // One cache path is shared by provision, inspect and resume. Only explicit
    // evidence gets an age stamp; push providers retain no polling metadata.
    #[tokio::test(start_paused = true)]
    async fn measurement_cache_requires_evidence_and_polling() {
        for polling in [false, true] {
            let mut owner = instance("list").await;
            let i = Arc::get_mut(&mut owner).unwrap();
            i.poll_interval = polling.then_some(std::time::Duration::from_secs(30));
            let mut row = ObservedEnvironment {
                egress_policy: None,
                environment: Environment {
                    platform: None,
                    id: "e".into(),
                    provider: "a".into(),
                    label: None,
                    state: Observation::Running,
                    granted_size: None,
                    egress: Enforcement::Enforced,
                },
                timestamp: None,
                egress_measured: true,
            };
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            assert_eq!(i.egress_measured_at.recover().contains_key("e"), polling);
            tokio::time::advance(EGRESS_EVIDENCE_MAX_AGE).await;
            row.egress_measured = false;
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            assert!(!i.egress_measured_at.recover().contains_key("e"));
            let mut cheap = row.clone();
            cheap.environment.egress = Enforcement::Advisory;
            carry_egress(i, std::slice::from_mut(&mut cheap), generation);
            assert_eq!(cheap.environment.egress, Enforcement::Advisory);
            assert_eq!(i.inspected.recover().contains_key("e"), polling);
            row.egress_measured = true;
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            evict_observation(i, "e");
            assert!(i.inspected.recover().is_empty());
            assert!(i.egress_measured_at.recover().is_empty());
            // A response begun before deletion cannot repopulate either cache.
            cache_observation(i, &row, generation);
            assert!(i.inspected.recover().is_empty());
            assert!(i.egress_measured_at.recover().is_empty());
            let generation = *i.observation_generation.recover();
            cache_observation(i, &row, generation);
            assert_eq!(i.inspected.recover().contains_key("e"), polling);
            // A complete empty inventory also forgets out-of-band deletions.
            carry_egress(i, &mut [], generation);
            assert!(i.inspected.recover().is_empty());
            assert!(i.egress_measured_at.recover().is_empty());
        }
    }
    // Identical effective policies preserve evidence beyond the fallback TTL;
    // mutation, removal, and stop invalidate it until a new measurement occurs.
    #[tokio::test(start_paused = true)]
    async fn policy_identity_controls_egress_carry() {
        let mut owner = instance("list").await;
        let i = Arc::get_mut(&mut owner).unwrap();
        i.poll_interval = Some(std::time::Duration::from_secs(30));
        let row = ObservedEnvironment {
            environment: Environment {
                platform: None,
                id: "e".into(),
                provider: "a".into(),
                label: None,
                state: Observation::Running,
                granted_size: None,
                egress: Enforcement::Enforced,
            },
            timestamp: None,
            egress_measured: true,
            egress_policy: Some("policy-a".into()),
        };
        let generation = *i.observation_generation.recover();
        cache_observation(i, &row, generation);
        tokio::time::advance(std::time::Duration::from_secs(3600)).await;
        let mut cheap = row.clone();
        cheap.egress_measured = false;
        cheap.environment.egress = Enforcement::Advisory;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Enforced);
        cheap.egress_policy = Some("policy-b".into());
        cheap.environment.egress = Enforcement::Advisory;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
        cheap.egress_policy = row.egress_policy.clone();
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
        cache_observation(i, &row, generation);
        cheap.environment.state = Observation::Stopped { cause: StopCause::SuspendedByRequest };
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        cheap.environment.state = Observation::Running;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
        cache_observation(i, &row, generation);
        cheap.egress_policy = None;
        carry_egress(i, std::slice::from_mut(&mut cheap), generation);
        assert_eq!(cheap.environment.egress, Enforcement::Advisory);
    }
    // Credential delivery wakes a host poll immediately. Advancing a paused
    // clock while unready must not attempt a call or record a spurious error.
    #[tokio::test(start_paused = true)]
    async fn poll_waits_for_credential_without_spurious_failure() {
        let host = Runtime::new(reference::registry());
        let config = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"reference"}],
            "providers":[{"name":"a","module":"memory","settings":{"poll_interval_ms":3600000},
                "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        host.configure(&config).await.unwrap();
        let instance = host.instance("a").await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(7200)).await;
        tokio::task::yield_now().await;
        assert!(instance.poll_error.recover().is_none());
        assert!(!host.events.log.recover().inventories.contains_key("a"));
        let mut changes = host.events.changed.subscribe();
        host.credential("a", Secret::new("token")).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !host.events.log.recover().inventories.contains_key("a") {
                changes.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert!(instance.poll_error.recover().is_none());
        host.shutdown(async {}).await;
    }

    // Repeated configuration and several providers sharing a placeholder must
    // retain one diagnostic secret for delayed vendor echoes.
    #[tokio::test]
    async fn repeated_proxy_configuration_deduplicates_diagnostic_secret() {
        let host = Runtime::new(reference::registry());
        let config: HostConfiguration = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"reference"}],
            "providers":[{"name":"a","module":"memory","settings":{},
                "credential":{"mode":"proxied","placeholder_token":"placeholder","proxy_url":"http://127.0.0.1:1"}}]
        }))
        .unwrap();
        let mut config = config;
        for count in 1..=3 {
            let mut provider = config.providers[0].clone();
            provider.name = format!("provider-{count}");
            config.providers.push(provider);
            for _ in 0..2 {
                host.configure(&config.clone()).await.unwrap();
            }
        }
        {
            let secrets = host.diagnostic_secrets.recover();
            assert_eq!(secrets.current.values().map(Secret::expose).collect::<BTreeSet<_>>().len(), 1);
            assert!(secrets.recent.is_empty());
        }
        host.shutdown(async {}).await;
    }
    #[test]
    fn active_shared_values_do_not_consume_history() {
        let mut secrets = DiagnosticSecrets::default();
        secrets.remember("a", Secret::new("shared"));
        secrets.remember("b", Secret::new("shared"));
        secrets.remember("a", Secret::new("new-a"));
        assert!(secrets.recent.is_empty());
        secrets.remember("b", Secret::new("new-b"));
        assert_eq!(secrets.recent, VecDeque::from([Secret::new("shared")]));
    }

    #[test]
    fn readiness_reasons_mask_without_adding_context() {
        let mut masker = DiagnosticMasker::default();
        masker.remember("readiness-secret");
        for readiness in [
            Readiness::MissingCredential { reason: "missing readiness-secret".into() },
            Readiness::Unknown { reason: "unknown readiness-secret".into() },
        ] {
            let result = mask_readiness(readiness, &masker);
            let wire = serde_json::to_string(&result).unwrap();
            assert!(!wire.contains("readiness-secret"));
            assert!(wire.contains("<REDACTED>"));
            assert!(!wire.contains("operation"));
        }
    }

    #[tokio::test]
    async fn hello_masks_readiness_reasons_at_wire_boundary() {
        let host = Runtime::new(reference::registry());
        let config = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"reference"}],
            "providers":[{"name":"a","module":"memory","settings":{},
                "credential":{"mode":"direct","credential_reference":"test"}}]
        }))
        .unwrap();
        host.configure(&config).await.unwrap();
        host.diagnostic_secrets.recover().remember("a", Secret::new("readiness-secret"));
        {
            let config = host.config.read().await;
            let mut auth = config.providers["a"].auth.recover();
            auth.rejected = true;
            auth.rejection_error = Some(ProtocolError::CredentialRejected { reason: "readiness-secret rejected".into() });
        }
        let result = crate::api::ProviderApi::hello(&host).await.unwrap();
        let wire = serde_json::to_string(&result).unwrap();
        assert!(!wire.contains("readiness-secret"));
        assert!(wire.contains("<REDACTED>"));
        host.shutdown(async {}).await;
    }

    #[tokio::test]
    async fn configure_errors_mask_placeholder_and_include_context() {
        struct Failing;
        #[async_trait::async_trait]
        impl Module for Failing {
            fn version(&self) -> &str {
                "test"
            }
            async fn configure(&self, _: &ProviderConfiguration, _: Arc<dyn HttpClient>) -> Result<Arc<dyn Provider>> {
                Err(ProtocolError::Internal { reason: "configure-secret rejected".into(), provider_error: "configure-secret body".into() })
            }
        }
        let host = Runtime::new(Registry::from([("failing".into(), Arc::new(Failing) as Arc<dyn Module>)]));
        let config = serde_json::from_value(serde_json::json!({
            "modules":[{"name":"memory","entrypoint":"failing"}],
            "providers":[{"name":"a","module":"memory","settings":{},
                "credential":{"mode":"proxied","placeholder_token":"configure-secret","proxy_url":"http://127.0.0.1:1"}}]
        }))
        .unwrap();
        let error = host.configure(&config).await.err().unwrap();
        let wire = serde_json::to_string(&error).unwrap();
        assert!(!wire.contains("configure-secret"));
        assert!(wire.contains("<REDACTED>"));
        assert!(wire.contains("provider a operation configure:"));
        host.shutdown(async {}).await;
    }

    // Glue: a unique short credential emits a debug registration note without
    // its value; delivering that same credential again emits no duplicate note.
    #[test]
    fn short_credential_note_contains_length_without_value() {
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.recover().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured = Arc::new(Mutex::new(Vec::new()));
        let output = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_writer(move || Capture(output.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut secrets = DiagnosticSecrets::default();
            secrets.remember("provider", Secret::new("xyz"));
            secrets.remember("provider", Secret::new("xyz"));
        });
        let text = String::from_utf8(captured.recover().clone()).unwrap();
        assert_eq!(text.matches("short credential registered").count(), 1);
        assert!(text.contains("credential_bytes=3"));
        assert!(!text.contains("xyz"));
    }
    // Credential history is bounded independently of refresh count, while every
    // active provider and the recent replacement window remain masked.
    #[test]
    fn credential_history_is_bounded_and_active_values_remain_masked() {
        for rotations in [0, 1, RECENT_CREDENTIAL_LIMIT, RECENT_CREDENTIAL_LIMIT + 1, 100] {
            let mut secrets = DiagnosticSecrets::default();
            secrets.remember("other", Secret::new("other-active-token"));
            for generation in 0..=rotations {
                secrets.remember("rotating", Secret::new(format!("generation-{generation}-token")));
            }
            assert_eq!(secrets.recent.len(), rotations.min(RECENT_CREDENTIAL_LIMIT));
            assert_eq!(secrets.current.len(), 2);
            let current = format!("generation-{rotations}-token");
            let previous = format!("generation-{}-token", rotations.saturating_sub(1));
            let oldest_recent = format!("generation-{}-token", rotations.saturating_sub(RECENT_CREDENTIAL_LIMIT));
            let error = secrets.masker.context(
                ProtocolError::Internal {
                    reason: "validation".into(),
                    provider_error: format!("other-active-token {current} {previous} {oldest_recent} generation-0-token"),
                },
                "p",
                "list",
            );
            let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
            assert!(!provider_error.contains("other-active-token"));
            assert!(!provider_error.contains(&current));
            assert!(!provider_error.contains(&previous));
            assert!(!provider_error.contains(&oldest_recent));
            if rotations > RECENT_CREDENTIAL_LIMIT {
                assert!(provider_error.contains("generation-0-token"));
            }
        }
    }

    // A call masks its own credential even if many refreshes evict that value
    // before its vendor error returns; the retained history still stays bounded.
    #[tokio::test]
    async fn in_flight_error_masks_evicted_call_credential() {
        let instance = instance("list").await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let call = instance.clone();
        let started = entered.clone();
        let waiting = release.clone();
        let pending = tokio::spawn(async move {
            call.call(Gate::List, move |_, credentials| async move {
                started.notify_one();
                waiting.notified().await;
                Err::<(), _>(ProtocolError::Internal {
                    reason: "vendor failure".into(),
                    provider_error: credentials.token().unwrap().expose().into(),
                })
            })
            .await
        });
        entered.notified().await;
        for generation in 0..100 {
            instance.diagnostic_secrets.recover().remember("a", Secret::new(format!("new-{generation}")));
        }
        assert!(!instance.diagnostic_secrets.recover().contains(&Secret::new("token")));
        release.notify_one();
        let error = pending.await.unwrap().unwrap_err();
        let ProtocolError::Internal { provider_error, .. } = error else { unreachable!() };
        assert_eq!(provider_error, "<REDACTED>");
        assert!(instance.diagnostic_secrets.recover().recent.len() <= RECENT_CREDENTIAL_LIMIT);
    }
}
