<div align="center">
<img src="assets/logo_malops.png" alt="Mal-Dev AI" width="120" />

# Mal-Dev AI

**Autonomous Malware Analysis & Triage**
</div>

Mal-Dev AI is your private, automated malware analyst. It takes a suspicious file, runs it through a gauntlet of static analysis tools (YARA, CAPA, Strings, PE headers), checks it against global threat intelligence (VirusTotal, MalwareBazaar), and uses an AI Supervisor to synthesize all this data into a clear, actionable report.

## 🚀 Features
- **One-Click Analysis**: Upload a file and get a complete report.
- **Deep Static Analysis**: Extracts imports, sections, capabilities (CAPA), signatures, and more.
- **Threat Intelligence**: Checks hashes against VirusTotal, MalwareBazaar, Hybrid Analysis, and OTX.
- **AI Supervisor**: An LLM reviews all technical findings to judge risk and explain *why* a file is malicious.
- **Privacy-Ready**: Default support for Google Gemini, with easy switching to **Local LLMs (Ollama/Llama)** for zero-data-leakage environments.

## 🏗️ Architecture

![Architecture](assets/architecture_v2.png)

## 🛠️ Quick Start

### Pre-requisites
- Docker & Docker Compose
- Git
- (Optional) [Ollama](https://ollama.com/) for local AI

### Installation over Private Repo

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/devarajan-here/Mal-Dev-AI.git
    cd Mal-Dev-AI
    ```

2.  **Run Setup**:
    ```bash
    bash run.sh
    ```
    *This script will ask for your API keys, set up the environment, and start the Docker containers.*

3.  **Manual Start (Alternative)**:
    If you prefer manual setup:
    ```bash
    cp .env.example .env  # Edit .env with keys
    unzip -o rules/capa-rules.zip -d rules/
    docker compose up -d --build
    ```

- **UI**: [http://localhost:8501](http://localhost:8501)
- **API**: [http://localhost:8000](http://localhost:8000)

## 🧠 AI Configuration

### Option 1: Google Gemini (Default)
By default, Mal-Dev AI uses Google's **Gemini 2.5 Flash**. It is fast, accurate, and has a large context window.
- **Setup**: Put your key in `.env` (`GEMINI_API_KEY`).
- **Privacy**: File *summaries* (not the file itself) are sent to Google for analysis.

### Option 2: Local LLM (Ollama / HuggingFace) 🔒
For **maximum privacy** and **unlimited usage**, you can replace Gemini with a local model like Llama 3 running on Ollama. This ensures **no analysis data leaves your network**.

#### How to Switch to Ollama

1.  **Install & Run Ollama**: [Download Ollama](https://ollama.com/) and run `ollama run llama3`.
2.  **Modify Supervisor**: Edit `src/agent/nodes/supervisor.py`.

```python
# src/agent/nodes/supervisor.py

# 1. Import ChatOllama
from langchain_community.chat_models import ChatOllama

# 2. In supervisor_node function, replace the Gemini LLM definition:
# DELETE this line:
# llm = ChatLLM(model=model, temperature=0, google_api_key=gemini_api_key)

# REPLACE with this:
llm = ChatOllama(
    model="llama3",  # Or any model you pulled (e.g., "mistral", "gemma")
    temperature=0,
    base_url="http://host.docker.internal:11434" # Access host Ollama from Docker container
)
```

3.  **Rebuild**:
    ```bash
    docker compose up -d --build
    ```

Now your AI Supervisor runs entirely on your local machine!

## 📜 License
MIT License.
