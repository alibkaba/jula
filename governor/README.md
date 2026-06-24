# Jula Governor

The **Jula Governor** is the policy authoring engine of the Jula compliance platform. It transforms compliance controls into executable OPA Rego policies through an AI-powered pipeline.

## Capabilities

- Ingests compliance catalogs and extracts technical requirements via AI
- Generates Rego translator modules from raw cloud API responses
- Produces standalone OPA policy files per compliance requirement
- Validates generated Rego via OPA AST compilation
- Self-heals translator drift when provider APIs change

## Directory Structure

```
governor/
├── workspace.yaml        # Provider configuration
├── catalog.csv           # Compliance controls (input)
├── requirements.csv      # Extracted requirements (output)
├── engine/
│   ├── integrations/     # Provider API endpoint definitions
│   ├── translators/      # Rego normalization modules
│   └── prompts/          # AI prompt templates
├── policies/
│   └── rules/            # Generated OPA Rego policies
└── cmd/                  # CLI tools (import, translate, build, validate)
```

## Configuration

The Governor requires an OpenAI-compatible chat completions endpoint. Set `JULA_PRIMARY_ENDPOINT`, `JULA_PRIMARY_KEY`, and `JULA_PRIMARY_MODEL` in your environment. An optional fallback tier provides automatic failover on rate limits.

## Full Documentation

For architecture and licensing details, see the [Root README](../README.md).
