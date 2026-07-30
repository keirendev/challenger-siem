#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

dotnet test tests/Siem.Api.Tests/Siem.Api.Tests.csproj \
  --filter 'FullyQualifiedName~ContractV2Tests|FullyQualifiedName~McpContractTests' \
  --property:TreatWarningsAsErrors=true
