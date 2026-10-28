//! Typed provider operations: the single implementation of server policy.
use super::*;
use crate::{
    api::{ConfigUpdate, ObservationStream, ProviderApi, Provisioned},
    client::Error,
};
use module::{ByteStream, prepare_for_platform};
type ApiResult<T> = std::result::Result<T, Error>;

impl Runtime {
    fn declaration(&self, name: &str, i: &Instance, masker: &DiagnosticMasker) -> ProviderDeclaration {
        ProviderDeclaration {
            provider: name.to_owned(),
            module: i.config.module.clone(),
            capabilities: i.capabilities.clone(),
            readiness: mask_readiness(i.readiness(&i.auth.recover()), masker),
            rate_limits: i.rate_limits.clone(),
            ports: i.provider.operations().into(),
            observation: i.observation,
        }
    }
}

#[async_trait::async_trait]
impl ProviderApi for Runtime {
    async fn hello(&self) -> ApiResult<Hello> {
        let registry = self.registry.recover().clone();
        Ok(Hello {
            protocol_version: PROTOCOL_VERSION.into(),
            host_version: env!("CARGO_PKG_VERSION").into(),
            loadable_modules: registry
                .iter()
                .map(|(name, module)| LoadableModule {
                    name: name.clone(),
                    version: module.version().into(),
                    smallest_size: module.smallest_size(),
                })
                .collect(),
        })
    }
    async fn configure(&self, update: ConfigUpdate) -> ApiResult<()> {
        Ok(Runtime::configure(self, update).await?)
    }
    async fn providers(&self) -> ApiResult<Vec<ProviderDeclaration>> {
        let instances: Vec<_> = self.config.read().await.providers.clone().into_iter().collect();
        futures::future::join_all(instances.iter().map(|(_, instance)| instance.refresh_readiness())).await;
        let masker = self.diagnostic_secrets.recover().masker.clone();
        Ok(instances.iter().map(|(name, i)| self.declaration(name, i, &masker)).collect())
    }
    async fn provider(&self, p: &str) -> ApiResult<ProviderDeclaration> {
        let instance = self.instance(p).await?;
        instance.refresh_readiness().await;
        let masker = self.diagnostic_secrets.recover().masker.clone();
        Ok(self.declaration(p, &instance, &masker))
    }
    async fn credential(&self, p: &str, value: Secret) -> ApiResult<()> {
        Ok(Runtime::credential(self, p, value).await?)
    }
    fn with_credential(&self, credential: Secret) -> Arc<dyn ProviderApi> {
        Arc::new(self.credentialed(Some(credential)))
    }
    async fn observe(&self, since: Option<&str>) -> ApiResult<ObservationStream> {
        Ok(self.observation(since).await?)
    }
    async fn prepare(&self, p: &str, r: &PrepareRequest) -> ApiResult<Prepared> {
        let r = r.clone();
        Ok(self
            .instance(p)
            .await?
            .call(Gate::Prepare, self.credential.clone(), |p, c| async move { prepare_for_platform(&*p, r, &c).await })
            .await?)
    }
    async fn provision(&self, p: &str, r: &ProvisionRequest) -> ApiResult<Provisioned<Environment>> {
        if r.prepared.provider != p {
            return Err(refused("invalid size, label or prepared provider").into());
        }
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let r = r.clone();
        let result = instance.call(Gate::Provision, self.credential.clone(), |p, c| async move { p.provision(r, &c).await }).await?;
        let (Provisioned::Created(row) | Provisioned::Existing(row)) = &result;
        cache_observation(&instance, row, generation);
        Ok(result)
    }
    async fn list(&self, p: &str) -> ApiResult<Vec<Environment>> {
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let mut rows = instance.call(Gate::List, self.credential.clone(), |p, c| async move { p.list(&c).await }).await?;
        carry_egress(&instance, &mut rows, generation);
        Ok(rows)
    }
    async fn inspect(&self, p: &str, id: &str) -> ApiResult<Environment> {
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let id = id.to_owned();
        let row = instance.call(Gate::Inspect, self.credential.clone(), |p, c| async move { p.inspect(&id, &c).await }).await?;
        cache_observation(&instance, &row, generation);
        Ok(row)
    }
    async fn destroy(&self, p: &str, id: &str) -> ApiResult<()> {
        let instance = self.instance(p).await?;
        let mut attempt = DestroyAttempt::begin(instance.clone(), id.to_owned());
        let target = id.to_owned();
        let result = instance.call(Gate::Destroy, self.credential.clone(), |p, c| async move { p.destroy(&target, &c).await }).await;
        attempt.finish(result.is_ok());
        result?;
        evict_observation(&instance, id);
        Ok(())
    }
    async fn reach(&self, p: &str, id: &str) -> ApiResult<Reach> {
        let target = id.to_owned();
        Ok(self.instance(p).await?.call(Gate::Reach, self.credential.clone(), |p, c| async move { p.reach(&target, &c).await }).await?)
    }
    async fn suspend(&self, p: &str, id: &str) -> ApiResult<ResumeToken> {
        let id = id.to_owned();
        let instance = self.instance(p).await?;
        Ok(instance
            .call(Gate::Suspend, self.credential.clone(), |p, c| async move {
                operation_port(p.operations().suspend_resume)?.suspend(&id, &c).await
            })
            .await?)
    }
    async fn resume(&self, p: &str, id: &str, token: &ResumeToken) -> ApiResult<()> {
        let instance = self.instance(p).await?;
        let generation = *instance.observation_generation.recover();
        let (target, token) = (id.to_owned(), token.clone());
        instance
            .call(Gate::Resume, self.credential.clone(), |p, c| async move {
                operation_port(p.operations().suspend_resume)?.resume(&target, token, &c).await
            })
            .await?;
        // The resume happened. A failed cache refresh is left for the observer.
        let target = id.to_owned();
        match instance.call(Gate::Inspect, self.credential.clone(), |p, c| async move { p.inspect(&target, &c).await }).await {
            Ok(row) => cache_observation(&instance, &row, generation),
            Err(error) => tracing::warn!(provider = %p, environment = %id, %error, "post-resume inspect failed"),
        }
        Ok(())
    }
    async fn export(&self, p: &str, id: &str) -> ApiResult<Export> {
        let id = id.to_owned();
        let instance = self.instance(p).await?;
        Ok(instance
            .call(Gate::Export, self.credential.clone(), |p, c| async move { operation_port(p.operations().export)?.export(&id, &c).await })
            .await?)
    }
    async fn quota(&self, p: &str) -> ApiResult<Quota> {
        Ok(self
            .instance(p)
            .await?
            .call(Gate::Quota, self.credential.clone(), |p, c| async move { operation_port(p.operations().quota)?.quota(&c).await })
            .await?)
    }
    async fn usage(&self, p: &str, period: &Period) -> ApiResult<Usage> {
        let period = period.clone();
        let instance = self.instance(p).await?;
        Ok(instance
            .call(Gate::Usage, self.credential.clone(), |p, c| async move { operation_port(p.operations().usage)?.usage(period, &c).await })
            .await?)
    }
    async fn relay(&self, p: &str, id: &str) -> ApiResult<ByteStream> {
        let id = id.to_owned();
        Ok(self.instance(p).await?.call(Gate::Relay, self.credential.clone(), |p, c| async move { p.relay(&id, &c).await }).await?)
    }
    async fn exec(&self, p: &str, id: &str, command: &ExecRequest) -> ApiResult<ByteStream> {
        let (id, command) = (id.to_owned(), command.clone());
        let instance = self.instance(p).await?;
        Ok(instance
            .call(
                Gate::Exec,
                self.credential.clone(),
                |p, c| async move { operation_port(p.operations().exec)?.exec(&id, command, &c).await },
            )
            .await?)
    }
}
