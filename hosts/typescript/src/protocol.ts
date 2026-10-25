// Generated from openapi.json; run corepack pnpm generate.
export interface paths {
    "/v1/config": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put: operations["configure"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["observe"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/hello": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["hello"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/credential": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put: operations["refresh_credential"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["list"];
        put?: never;
        post: operations["provision"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["inspect"];
        put?: never;
        post?: never;
        delete: operations["destroy"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}/exec": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["exec"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}/export": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["export"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}/reach": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["reach"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}/relay": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["relay"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}/resume": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["resume"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/environments/{id}/suspend": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["suspend"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/prepare": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post: operations["prepare"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/quota": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["quota"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/v1/providers/{provider}/usage": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get: operations["usage"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** @enum {string} */
        BootstrapRoute: "bake" | "upload";
        Capabilities: {
            /**
             * @description Vessels run the drydock agent from the tools image. Launch reports
             *     success only after the agent's current hello over the SSH reach.
             */
            agent?: boolean;
            bootstrap: components["schemas"]["BootstrapRoute"];
            checkout_strategies: components["schemas"]["CheckoutStrategy"][];
            egress: components["schemas"]["EgressCapability"];
            export: boolean;
            fallback_runner: boolean;
            material_modes: components["schemas"]["MaterialMode"][];
            /**
             * @description Platforms this provider can run, preferred first. A prepare request
             *     that names none gets the first; one naming another is refused.
             */
            platforms?: components["schemas"]["Platform"][];
            quota: boolean;
            /** @description Whether suspend retains running processes/memory, when supported. */
            suspend_preserves_memory?: boolean | null;
            suspend_resume: boolean;
            usage: boolean;
            workspace_root: string;
        };
        /** @enum {string} */
        CheckoutStrategy: "host_worktree" | "host_clone" | "clone_in_vessel";
        /** @description A validated IPv4/IPv6 CIDR, preserving the caller's wire spelling. */
        Cidr: string;
        /**
         * @description Currency is explicit, e.g. USD or EUR; the field name fixes no currency.
         *     A missing cost is unknown, whereas an amount of zero is a known zero cost.
         */
        Cost: {
            amount: string;
            currency: string;
        };
        CredentialMode: {
            credential_reference: string;
            /** @enum {string} */
            mode: "direct";
        } | {
            /** @enum {string} */
            mode: "proxied";
            /** Format: password */
            placeholder_token: string;
            proxy_url: string;
        };
        /** @description Delivered in memory over the authenticated host connection; never persisted. */
        CredentialRefresh: {
            /** Format: password */
            value: string;
        };
        Destination: {
            host: components["schemas"]["HostAddress"];
            /** @enum {string} */
            kind: "host";
        } | {
            host: components["schemas"]["HostAddress"];
            /** @enum {string} */
            kind: "host_port";
            port: components["schemas"]["Port"];
        } | {
            cidr: components["schemas"]["Cidr"];
            /** @enum {string} */
            kind: "cidr";
        };
        EgressCapability: {
            enforcement: components["schemas"]["Enforcement"];
            routes: components["schemas"]["EgressRoute"][];
        };
        /** @description Deny all is the default. Providers must refuse unrepresentable destinations, never widen them. */
        EgressRequest: {
            direct?: components["schemas"]["Destination"][];
            /** @enum {string} */
            mode: "deny_all";
        } | {
            /** @enum {string} */
            mode: "open";
        };
        /** @enum {string} */
        EgressRoute: "none" | "explicit_proxy" | "transparent_proxy" | "open";
        /** @enum {string} */
        Enforcement: "enforced" | "advisory";
        Environment: {
            egress: components["schemas"]["Enforcement"];
            granted_size?: null | components["schemas"]["Size"];
            id: string;
            /** @description Unlabelled resources are listable, inspectable and destroyable. */
            label?: string | null;
            platform?: null | components["schemas"]["Platform"];
            provider: string;
            state: components["schemas"]["Observation"];
        };
        Event: {
            /** @description Opaque cursor to send as `since` on reconnect; resume is exclusive. */
            cursor: string;
            event: components["schemas"]["EventKind"];
            id: string;
            label?: string | null;
            provider: string;
            /** @description RFC 3339 timestamp. */
            timestamp: components["schemas"]["Timestamp"];
            timestamp_source: components["schemas"]["TimestampSource"];
        };
        EventKind: {
            /** @enum {string} */
            kind: "created";
        } | {
            granted_size: components["schemas"]["Size"];
            /** @enum {string} */
            kind: "running";
        } | {
            cause: components["schemas"]["StopCause"];
            /** @enum {string} */
            kind: "stopped";
        } | {
            cause: components["schemas"]["StopCause"];
            /** @enum {string} */
            kind: "paused";
        } | {
            /** @enum {string} */
            kind: "resumed";
        } | {
            cause: components["schemas"]["GoneCause"];
            /** @enum {string} */
            kind: "gone";
        };
        ExecRequest: {
            command: [
                string,
                ...string[]
            ];
        };
        Export: {
            reference: string;
        };
        GoneCause: {
            /** @enum {string} */
            kind: "lifetime_cap_reached";
        } | {
            /** @enum {string} */
            kind: "evicted_by_provider";
        } | {
            /** @enum {string} */
            kind: "host_out_of_memory";
        } | {
            /** Format: int32 */
            code: number;
            /** @enum {string} */
            kind: "vmm_exited";
        } | {
            /** @enum {string} */
            kind: "guest_powered_off";
        } | {
            /** @enum {string} */
            kind: "destroyed_at_provider";
        } | {
            /** @enum {string} */
            kind: "missing_on_list";
        } | {
            /** @enum {string} */
            kind: "destroyed_by_request";
        };
        Hello: {
            host_version: string;
            /** @description Modules the host can configure, including those not yet loaded. */
            loadable_modules?: components["schemas"]["LoadableModule"][];
            modules: components["schemas"]["LoadedModule"][];
            protocol_version: string;
            providers: components["schemas"]["ProviderDeclaration"][];
        };
        /** @description A validated DNS name or IP literal. Schema uses the exact decoder pattern. */
        HostAddress: string;
        HostConfiguration: {
            modules: components["schemas"]["ModuleConfiguration"][];
            providers: components["schemas"]["ProviderConfiguration"][];
        };
        LoadableModule: {
            name: string;
            /** @description Smallest supported resource request, used when the caller has no default. */
            smallest_size: components["schemas"]["Size"];
            version: string;
        };
        LoadedModule: {
            name: string;
            version: string;
        };
        /** @enum {string} */
        MaterialMode: "frozen" | "pushed" | "shared";
        ModuleConfiguration: {
            entrypoint: string;
            name: string;
        };
        Observation: {
            /** @enum {string} */
            state: "running";
        } | {
            cause: components["schemas"]["StopCause"];
            /** @enum {string} */
            state: "stopped";
        } | {
            cause: components["schemas"]["GoneCause"];
            /** @enum {string} */
            state: "gone";
        } | {
            phase: components["schemas"]["TransitionPhase"];
            /** @enum {string} */
            state: "transitioning";
        } | {
            reason: components["schemas"]["UnknownReason"];
            /** @enum {string} */
            state: "unknown";
        };
        /**
         * @description Hosts unable to replay emit a snapshot marking the gap. Inventory is complete
         *     only for providers absent from `unavailable_providers`.
         */
        ObserveRecord: {
            event: components["schemas"]["Event"];
            /** @enum {string} */
            type: "event";
        } | {
            cursor: string;
            environments: components["schemas"]["Environment"][];
            /** @enum {string} */
            type: "snapshot";
            /**
             * @description Providers omitted from this snapshot. Preserve their previous inventory;
             *     omission must not be interpreted as deletion or a billing transition.
             */
            unavailable_providers?: {
                [key: string]: components["schemas"]["ProtocolError"];
            };
        };
        /** @description RFC 3339 endpoints; start must be <= end (equal endpoints are an empty interval). */
        Period: {
            end: components["schemas"]["Timestamp"];
            start: components["schemas"]["Timestamp"];
        };
        /**
         * @description An OCI platform: `os` and `architecture` by OCI names (`linux`, `amd64`,
         *     `arm64`), each 1 to 32 lowercase letters or digits. They become agent build
         *     file and variable names, so decoding refuses anything else.
         */
        Platform: {
            architecture: string;
            os: string;
        };
        /**
         * Format: int32
         * @description Zero is not a destination port.
         */
        Port: number;
        /**
         * @description Preparation is look-up-or-build at the provider: append the tools image's
         *     files under /opt/drydock to the base, preserving its entrypoint, command and
         *     init. tools_digest is the build-selected bootstrap agent OCI index reference.
         *     Its checked-in pin can be older than the host, which upgrades on mismatched
         *     agent hello. Build at the provider where possible, otherwise append its layer;
         *     Upload bootstrap installs those same files under /opt/drydock.
         *     Modules choose their own provider-recorded key including both digests and any
         *     prepare-time constraints (Daytona also includes size); configuration is not a
         *     key. Provision must match the recorded prepared form. See ADR 0070 Vessel tools.
         */
        PrepareRequest: {
            image_digest: string;
            platform?: null | components["schemas"]["Platform"];
            size: components["schemas"]["Size"];
            tools_digest: string;
        };
        Prepared: {
            id: string;
            image_digest: string;
            /** @description The platform this prepared form was built for; part of the module's key. */
            platform: components["schemas"]["Platform"];
            provider: string;
            tools_digest: string;
        };
        /** @description Adaptors never retry. Internal preserves the vendor's raw error text. */
        ProtocolError: {
            /** @enum {string} */
            kind: "not_found";
            reason: string;
        } | {
            /** @enum {string} */
            kind: "method_not_allowed";
            reason: string;
        } | {
            /** @enum {string} */
            kind: "refused";
            reason: string;
        } | {
            /** @enum {string} */
            kind: "unavailable";
            /** @description Bounded provider/transport detail, masked for credentials by the host. */
            provider_error?: string | null;
            reason: string;
            /** Format: int64 */
            retry_after?: number | null;
        } | {
            /** @enum {string} */
            kind: "rate_limited";
            reason: string;
            /** Format: int64 */
            retry_after?: number | null;
        } | {
            /** @enum {string} */
            kind: "quota_exhausted";
            reason: string;
        } | {
            /** @enum {string} */
            kind: "credential_rejected";
            reason: string;
        } | {
            /** Format: int32 */
            exit_code: number;
            /** @enum {string} */
            kind: "command_failed";
            /** @description Vendor-merged guest output. Sensitive diagnostics; never log it. */
            output: components["schemas"]["Secret"];
            reason: string;
        } | {
            /** @enum {string} */
            kind: "internal";
            /** @description Provider explanation, masked for credentials before leaving the host. */
            provider_error: string;
            reason: string;
        };
        ProviderConfiguration: {
            credential: components["schemas"]["CredentialMode"];
            module: string;
            name: string;
            /** @description Non-secret vendor-specific configuration only. */
            settings: {
                [key: string]: unknown;
            };
        };
        ProviderDeclaration: {
            capabilities: components["schemas"]["Capabilities"];
            module: string;
            provider: string;
            rate_limits: components["schemas"]["RateLimit"][];
            readiness: components["schemas"]["Readiness"];
        };
        /**
         * @description Repeated creation with the same label returns the existing environment (200).
         *     Prepared forms belong to one provider; cross-provider use is Refused.
         */
        ProvisionRequest: {
            egress?: components["schemas"]["EgressRequest"];
            label: string;
            prepared: components["schemas"]["Prepared"];
            size: components["schemas"]["Size"];
            ssh_public_key?: string | null;
        };
        Quantity: {
            /** Format: double */
            amount: number;
            unit: components["schemas"]["String"];
        };
        Quota: {
            /** Format: int64 */
            concurrency_in_use?: number | null;
            /** Format: int64 */
            concurrency_limit?: number | null;
            credit_unit?: string | null;
            /** Format: double */
            credits_remaining?: number | null;
            resources?: components["schemas"]["ResourceQuota"][];
        };
        /**
         * @description Scope is data, never an opaque "region/class/resource" string. Missing scope
         *     components mean the provider reports the resource at a broader scope.
         */
        QuotaKey: {
            class?: string | null;
            region?: string | null;
            resource: components["schemas"]["ResourceKind"];
        };
        RateLimit: {
            operation: string;
            /** Format: int64 */
            period_seconds: number;
            /** Format: int32 */
            requests: number;
        };
        Reach: {
            endpoint: string;
            host_key: string;
            /** @enum {string} */
            kind: "ssh";
            /**
             * @description Whether this SSH server accepts remote (reverse) Unix-socket forwards.
             *     When it does, guest-to-host streams get their own SSH channels; when it
             *     doesn't (Daytona's gateway), they share a link through the local forward.
             */
            reverse_forwards?: boolean;
            /** @description May contain a short-lived gateway token; always redact diagnostics. */
            user: components["schemas"]["Secret"];
        } | {
            expires_at: components["schemas"]["Timestamp"];
            /** @enum {string} */
            kind: "dial";
            token: components["schemas"]["Secret"];
            url: string;
        } | {
            /** @enum {string} */
            kind: "relay";
            path: string;
        };
        Readiness: {
            /** @enum {string} */
            status: "ready";
        } | {
            reason: string;
            /** @enum {string} */
            status: "missing_tool";
        } | {
            reason: string;
            /** @enum {string} */
            status: "missing_credential";
        } | {
            reason: string;
            /** @enum {string} */
            status: "version_mismatch";
        } | {
            reason: string;
            /** @enum {string} */
            status: "unknown";
        };
        /**
         * @description Initial provider-neutral vocabulary. Adding a resource is a protocol change,
         *     rather than inventing provider-specific encodings inside resource names.
         * @enum {string}
         */
        ResourceKind: "cpu" | "memory" | "disk" | "gpu" | "snapshot_storage" | "volume_storage" | "environments";
        /**
         * @description The same unit applies to current use and limit. Unknown limits stay unknown.
         *     A vector of these rows keeps structured keys representable as ordinary JSON.
         */
        ResourceQuota: {
            /** Format: double */
            in_use: number;
            key: components["schemas"]["QuotaKey"];
            /** Format: double */
            limit?: number | null;
            unit: components["schemas"]["String"];
        };
        ResumeToken: {
            token: components["schemas"]["Secret"];
        };
        /**
         * @description Secret wire string. Debug output is redacted; serialization deliberately exposes the value.
         *     PartialEq is for wire-value comparisons, NOT constant-time authentication.
         *     Authentication belongs to hosts, which must use constant-time token comparison.
         *     This type does not promise secure erasure of strings or serialization buffers.
         */
        Secret: string;
        Size: {
            /** Format: double */
            cpus: number;
            /** Format: int64 */
            disk_bytes: number;
            /** Format: int64 */
            memory_bytes: number;
        };
        SizeUsage: {
            /** Format: double */
            hours: number;
            size: components["schemas"]["Size"];
        };
        /** @enum {string} */
        StopCause: "suspended_by_request" | "paused_by_provider" | "guest_halted";
        String: string;
        /**
         * Format: date-time
         * @description A typed UTC instant, encoded as RFC3339. Equivalent offsets compare equally.
         */
        Timestamp: string;
        /** @enum {string} */
        TimestampSource: "provider" | "adaptor";
        /**
         * @description Generic phases describe progress, not billing transitions. The host retains
         *     its last stable billing observation until another stable observation arrives.
         * @enum {string}
         */
        TransitionPhase: "preparing" | "starting" | "stopping" | "reconfiguring" | "destroying";
        /** @enum {string} */
        UnknownReason: "provider_state_unknown" | "host_unreachable" | "provider_api_error" | "guest_unresponsive";
        /**
         * @description Retain the original sandbox-hours-by-size slice. Optional measurements can
         *     reconcile other provider data without fabricating a distribution over sizes.
         */
        Usage: {
            environment_hours: components["schemas"]["SizeUsage"][];
            measurements?: null | components["schemas"]["UsageMeasurements"];
            period: components["schemas"]["Period"];
        };
        UsageMeasurements: {
            cost?: null | components["schemas"]["Cost"];
            resources: {
                [key: string]: components["schemas"]["Quantity"];
            };
            scope: components["schemas"]["UsageScope"];
        };
        /**
         * @description Aggregated usage must say what population it measured. In particular,
         *     organisation totals cannot prove that one suspended environment stopped billing.
         *     Organization and environment IDs are provider-opaque; consumers only compare them.
         */
        UsageScope: {
            /** @enum {string} */
            kind: "provider";
        } | {
            id: string;
            /** @enum {string} */
            kind: "organization";
        } | {
            id: string;
            /** @enum {string} */
            kind: "environment";
        };
    };
    responses: {
        /** @description QuotaExhausted */
        Error402: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "quota_exhausted";
                    reason: string;
                };
            };
        };
        /** @description NotFound: route, provider or environment does not exist */
        Error404: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "not_found";
                    reason: string;
                };
            };
        };
        /** @description MethodNotAllowed */
        Error405: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "method_not_allowed";
                    reason: string;
                };
            };
        };
        /** @description Refused: request cannot be met */
        Error422: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "refused";
                    reason: string;
                };
            };
        };
        /** @description CommandFailed: completed guest command failed; includes exit code and sensitive merged output */
        Error424: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** Format: int32 */
                    exit_code: number;
                    /** @enum {string} */
                    kind: "command_failed";
                    /** @description Vendor-merged guest output. Sensitive diagnostics; never log it. */
                    output: components["schemas"]["Secret"];
                    reason: string;
                };
            };
        };
        /** @description RateLimited: retry_after is whole seconds */
        Error429: {
            headers: {
                /** @description Optional whole seconds until retry; adaptors do not retry automatically */
                "Retry-After"?: number;
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "rate_limited";
                    reason: string;
                    /** Format: int64 */
                    retry_after?: number | null;
                };
            };
        };
        /** @description Internal: sensitive provider error for supervisor diagnostics */
        Error500: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "internal";
                    /** @description Provider explanation, masked for credentials before leaving the host. */
                    provider_error: string;
                    reason: string;
                };
            };
        };
        /** @description CredentialRejected: vendor rejected delivered credentials */
        Error502: {
            headers: {
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "credential_rejected";
                    reason: string;
                };
            };
        };
        /** @description Unavailable: provider not ready or temporarily unavailable */
        Error503: {
            headers: {
                /** @description Optional whole seconds until retry; adaptors do not retry automatically */
                "Retry-After"?: number;
                [name: string]: unknown;
            };
            content: {
                "application/json": {
                    /** @enum {string} */
                    kind: "unavailable";
                    /** @description Bounded provider/transport detail, masked for credentials by the host. */
                    provider_error?: string | null;
                    reason: string;
                    /** Format: int64 */
                    retry_after?: number | null;
                };
            };
        };
    };
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    configure: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HostConfiguration"];
            };
        };
        responses: {
            /** @description Success */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    observe: {
        parameters: {
            query?: {
                /** @description Exclusive last-seen cursor; absent starts with a snapshot */
                since?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/x-ndjson": components["schemas"]["ObserveRecord"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    hello: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Hello"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    refresh_credential: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CredentialRefresh"];
            };
        };
        responses: {
            /** @description Success */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    list: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Environment"][];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    provision: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ProvisionRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Environment"];
                };
            };
            /** @description Created; repeats by label return 200 */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Environment"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    inspect: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Environment"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    destroy: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success; destroying an already absent resource succeeds */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    exec: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ExecRequest"];
            };
        };
        responses: {
            /** @description Raw byte-stream upgrade; request Connection: Upgrade and Upgrade: drydock-stream */
            101: {
                headers: {
                    /** @description Upgrade */
                    Connection?: string;
                    /** @description drydock-stream */
                    Upgrade?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    export: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Export"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    reach: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Reach"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    relay: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Raw byte-stream upgrade; request Connection: Upgrade and Upgrade: drydock-relay */
            101: {
                headers: {
                    /** @description Upgrade */
                    Connection?: string;
                    /** @description drydock-relay */
                    Upgrade?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    resume: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ResumeToken"];
            };
        };
        responses: {
            /** @description Success */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    suspend: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
                /** @description Opaque id */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ResumeToken"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    prepare: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PrepareRequest"];
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Prepared"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    quota: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Quota"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
    usage: {
        parameters: {
            query: {
                /** @description RFC 3339 period start */
                start: components["schemas"]["Timestamp"];
                /** @description RFC 3339 period end */
                end: components["schemas"]["Timestamp"];
            };
            header?: never;
            path: {
                /** @description Opaque provider */
                provider: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Usage"];
                };
            };
            402: components["responses"]["Error402"];
            404: components["responses"]["Error404"];
            405: components["responses"]["Error405"];
            422: components["responses"]["Error422"];
            424: components["responses"]["Error424"];
            429: components["responses"]["Error429"];
            500: components["responses"]["Error500"];
            502: components["responses"]["Error502"];
            503: components["responses"]["Error503"];
        };
    };
}
