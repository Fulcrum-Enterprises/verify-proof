# Container image for the verify-proof MCP server.
#
# Glama builds this to run its automated safety and quality checks, and it is
# a working way to run the server anywhere Docker is. The package itself has
# no runtime dependencies; only the [mcp] extra pulls anything in.
FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY verify_proof.py verify_proof_mcp.py proofledger_api.py ./
COPY examples ./examples

RUN pip install --no-cache-dir ".[mcp]"

# Verification is offline by design, so the server never needs the network.
# Run it as an unprivileged user.
RUN useradd --create-home --uid 10001 verifier
USER verifier

# stdio transport: the MCP host speaks JSON-RPC over stdin/stdout.
ENTRYPOINT ["verify-proof-mcp"]
