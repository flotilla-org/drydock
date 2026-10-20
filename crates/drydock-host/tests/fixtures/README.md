# Daytona analytics schemas

To refresh `daytona-analytics-schemas.json`, fetch
<https://www.daytona.io/docs/analytics-openapi.json>, extract the definitions
`models.AggregatedUsage`, `models.SandboxUsage`, and `models.UsagePeriod` into
`schemas`, and update `retrieved` to the UTC retrieval date. Preserve the vendor
field types and optionality. Review the schema diff before running the Daytona
stand-in suite; its response validator checks these pinned object schemas.
