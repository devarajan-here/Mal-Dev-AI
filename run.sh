#!/usr/bin/env bash

set -eo pipefail

REPO_URL="https://github.com/devarajan-here/Mal-Dev-AI.git"
# Determine if running inside the repo or standalone
if [ -f "docker-compose.yml" ] && [ -d ".git" ]; then
  log "Running inside existing repository."
  PROJECT_DIR="$(pwd)"
else
  # Standalone mode: Clone into subdirectory
  PROJECT_DIR="$(pwd)/Mal-Dev-AI"
  
  # Remove existing project directory if it already exists
  if [ -d "$PROJECT_DIR" ]; then
    log "Removing existing directory at $PROJECT_DIR..."
    rm -rf "$PROJECT_DIR"
  fi

  # Clone repository
  log "Cloning repository..."
  git clone --branch main --depth 1 "$REPO_URL" "$PROJECT_DIR"
fi

# Create .env from template if not exists
if [ ! -f "$PROJECT_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  log ".env file created from .env.example"
fi

# Ask for API Keys
read -rp "Enter your GEMINI_API_KEY: " GEMINI_API_KEY
read -rp "Enter your VT_API_KEY: " VT_API_KEY
read -rp "Enter your OTX_API_KEY: " OTX_API_KEY
read -rp "Enter your HA_API_KEY: " HA_API_KEY
read -rp "Enter your ABUSE_API_KEY: " ABUSE_API_KEY

# Update .env with credentials
sed -i "s/^GEMINI_API_KEY=.*/GEMINI_API_KEY=$GEMINI_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^VT_API_KEY=.*/VT_API_KEY=$VT_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^OTX_API_KEY=.*/OTX_API_KEY=$OTX_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^HA_API_KEY=.*/HA_API_KEY=$HA_API_KEY/" "$PROJECT_DIR/.env"
sed -i "s/^ABUSE_API_KEY=.*/ABUSE_API_KEY=$ABUSE_API_KEY/" "$PROJECT_DIR/.env"

log "API keys saved in $PROJECT_DIR/.env"

# Extract capa-rules.zip
log "Extracting capa-rules.zip..."
unzip -o "$PROJECT_DIR/rules/capa-rules.zip" -d "$PROJECT_DIR/rules/" >/dev/null

# Build + start containers
cd "$PROJECT_DIR"
log "Building containers..."
docker compose -f "$COMPOSE_FILE" build --pull
log "Starting containers..."
docker compose -f "$COMPOSE_FILE" up -d

cat <<EOF

==========================================
✅ Setup completed

Addresses:
- API: http://localhost:8000/
- API Docs (Swagger): http://localhost:8000/docs
- UI: http://localhost:8501/

📁 Project: $PROJECT_DIR
📄 Compose file: $COMPOSE_FILE

Useful commands:
- Status:  (cd "$PROJECT_DIR" && docker compose ps)
- Logs:    (cd "$PROJECT_DIR" && docker compose logs -f --tail=200)
- Start:   (cd "$PROJECT_DIR" && docker compose up -d)
- Stop:    (cd "$PROJECT_DIR" && docker compose down)
==========================================
EOF
