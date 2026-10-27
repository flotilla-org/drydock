//! Typed provider operations: the single implementation of server policy.
use super::*;
use crate::{
    api::{ObservationStream, ProviderApi, Provisioned},
    client::Error,
};
use module::{ByteStream, Connection, resolve_platform, resolve_route};
type ApiResult<T> = std::result::Result<T, Error>;

/// Modules always receive a declared platform and image route: the requested
/// ones, or the first of each.
pub(super) async fn prepare_for_platform(p: &dyn Provider, mut r: PrepareRequest, c: &Credentials) -> Result<Prepared> {
    let capabilities = p.capabilities();
    let platform = resolve_platform(r.platform.take(), &capabilities.platforms)?;
    r.route = Some(resolve_route(r.route.take(), &capabilities.image_routes)?);
    r.platform = Some(platform.clone());
    let prepared = p.prepare(r, c).await?;
    // The prepared form names what was built; a different platform is a module bug.
    if prepared.platform != platform {
        return Err(ProtocolError::Internal {
            reason: format!("module prepared {} for a {platform} request", prepared.platform),
            provider_error: String::new(),
        });
    }
    Ok(prepared)
}

#[async_trait::async_trait]
impl ProviderApi for Runtime {
    async fn hello(&self) -> ApiResult<Hello> {
        let registry = self.registry.recover().clone();
        let instances: Vec<_> = self.config.read().await.providers.values().cloned().collect();
        futures::future::join_all(instances.iter().map(|instance| instance.refresh_readiness())).await;
        let config = self.config.read().await;
        let masker = self.diagnostic_secrets.recover().masker.clone();
        Ok(Hello {
            protocol_version: PROTOCOL_VERSION.into(),
            host_version: env!("CARGO_PKG_VERSION").into(),
            modules: config.modules.clone(),
            loadable_modules: registry
                .iter()
                .map(|(name, module)| LoadableModule {
                    name: name.clone(),
                    version: module.version().into(),
                    smallest_size: module.smallest_size(),
                })
                .collect(),
            providers: config
                .providers
                .iter()
                .map(|(name, i)| ProviderDeclaration {
                    provider: name.clone(),
                    module: i.config.module.clone(),
                    capabilities: i.capabilities.clone(),
                    readiness: mask_readiness(i.readiness(&i.auth.recover()), &masker),
                    rate_limits: i.rate_limits.clone(),
                })
                .collect(),
        })
    }
    async fn observe(&self, since: Option<&str>) -> ApiResult<ObservationStream> {
        Ok(self.observation(since).await?)
    }
    async fn prepare(&self, p: &str, r: &PrepareRequest) -> ApiResult<Prepared> {
        let r = r.clone();
        Ok(self.instance(p).await?.call(Gate::Prepare, |p, c| async move { prepare_for_platform(&*p, r, &c).await }).await?)
    }
    async fn provision(&self, p: &str, r: &ProvisionRequest) -> ApiResult<Provisioned<Environment>> {
        if r.prepared.provider != p {
            return Err(refused("invalid size, label or prepared provider").into());
        }
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let r = r.clone();
        let result = instance.call(Gate::Provision, |p, c| async move { p.provision(r, &c).await }).await?;
        let (Provisioned::Created(row) | Provisioned::Existing(row)) = &result;
        cache_observation(&instance, row, generation);
        Ok(result.map(|row| row.environment))
    }
    async fn list(&self, p: &str) -> ApiResult<Vec<Environment>> {
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let mut rows = instance.call(Gate::List, |p, c| async move { p.list(&c).await }).await?;
        carry_egress(&instance, &mut rows, generation);
        Ok(rows.into_iter().map(|r| r.environment).collect())
    }
    async fn inspect(&self, p: &str, id: &str) -> ApiResult<Environment> {
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let id = id.to_owned();
        let row = instance.call(Gate::Inspect, |p, c| async move { p.inspect(&id, &c).await }).await?;
        cache_observation(&instance, &row, generation);
        Ok(row.environment)
    }
    async fn destroy(&self, p: &str, id: &str) -> ApiResult<()> {
        let instance = self.instance(p).await?;
        let mut attempt = DestroyAttempt::begin(instance.clone(), id.to_owned());
        let target = id.to_owned();
        let result = instance.call(Gate::Destroy, |p, c| async move { p.destroy(&target, &c).await }).await;
        attempt.finish(result.is_ok());
        result?;
        evict_observation(&instance, id);
        Ok(())
    }
    async fn reach(&self, p: &str, id: &str) -> ApiResult<Reach> {
        let target = id.to_owned();
        let connection = self.instance(p).await?.call(Gate::Reach, |p, c| async move { p.reach(&target, &c).await }).await?;
        Ok(match connection {
            Connection::Relay => {
                let mut url = url::Url::parse("http://localhost").expect("static URL");
                url.path_segments_mut().expect("base URL").extend(["v1", "providers", p, "environments", id, "relay"]);
                Reach::Relay { path: url.path().into() }
            }
            Connection::Ssh { endpoint, user, host_key, reverse_forwards } => Reach::Ssh { endpoint, user, host_key, reverse_forwards },
            Connection::Dial { url, token, expires_at } => Reach::Dial { url, token, expires_at },
        })
    }
    async fn suspend(&self, p: &str, id: &str) -> ApiResult<ResumeToken> {
        let id = id.to_owned();
        let instance = self.instance(p).await?;
        Ok(instance
            .call(Gate::Suspend, |p, c| async move { operation_port(p.operations().suspend_resume)?.suspend(&id, &c).await })
            .await?)
    }
    async fn resume(&self, p: &str, id: &str, token: &ResumeToken) -> ApiResult<()> {
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let (target, token) = (id.to_owned(), token.clone());
        instance
            .call(Gate::Resume, |p, c| async move { operation_port(p.operations().suspend_resume)?.resume(&target, token, &c).await })
            .await?;
        // The resume happened. A failed cache refresh is left for the observer.
        let target = id.to_owned();
        match instance.call(Gate::Inspect, |p, c| async move { p.inspect_after_lifecycle(&target, &c).await }).await {
            Ok(row) => cache_observation(&instance, &row, generation),
            Err(error) => tracing::warn!(provider = %p, environment = %id, %error, "post-resume inspect failed"),
        }
        Ok(())
    }
    async fn export(&self, p: &str, id: &str) -> ApiResult<Export> {
        let id = id.to_owned();
        let instance = self.instance(p).await?;
        Ok(instance.call(Gate::Export, |p, c| async move { operation_port(p.operations().export)?.export(&id, &c).await }).await?)
    }
    async fn quota(&self, p: &str) -> ApiResult<Quota> {
        Ok(self.instance(p).await?.call(Gate::Quota, |p, c| async move { operation_port(p.operations().quota)?.quota(&c).await }).await?)
    }
    async fn usage(&self, p: &str, period: &Period) -> ApiResult<Usage> {
        let period = period.clone();
        let instance = self.instance(p).await?;
        Ok(instance.call(Gate::Usage, |p, c| async move { operation_port(p.operations().usage)?.usage(period, &c).await }).await?)
    }
    async fn relay(&self, p: &str, id: &str) -> ApiResult<ByteStream> {
        let id = id.to_owned();
        Ok(self.instance(p).await?.call(Gate::Relay, |p, c| async move { p.relay(&id, &c).await }).await?)
    }
    async fn exec(&self, p: &str, id: &str, command: &ExecRequest) -> ApiResult<ByteStream> {
        let (id, command) = (id.to_owned(), command.clone());
        let instance = self.instance(p).await?;
        Ok(instance.call(Gate::Exec, |p, c| async move { operation_port(p.operations().exec)?.exec(&id, command, &c).await }).await?)
    }
}
