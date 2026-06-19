# Model Compatibility Guide

ARES works with any LLM provider that supports OpenAI-compatible chat completions or one of the native APIs (Ollama, Anthropic, Gemini). Unlike some pentesting tools, ARES does **not** require native function/tool calling support from the model — it parses tool calls from plain-text output using pattern matching.

## How ARES handles tool calling

ARES uses a **parser-based approach** rather than relying on native function calling. The `parser.go` module recognizes tool calls in three formats:

| Format | Example |
|---|---|
| **JSON** | `{"tool_calls":[{"function":{"name":"nmap","arguments":"{\"target\":\"example.com\"}"}}]}` |
| **XML invoke** | `<invoke name="nmap"><parameter name="target">example.com</parameter></invoke>` |
| **Function tag** | `<function=nmap><parameter=target>example.com</parameter></function>` |

Since ARES parses these from text output, **models without native function calling still work** — they just need to produce structured text in one of these formats.

> **Note for Ollama v0.5.0+**: ARES also sends native tool definitions alongside requests. Models that support native function calling (Qwen 2.5, Llama 3.1+) will use the native tool format, while others fall back to the parser.

## Provider Support

| Provider | Config Value | API Format | API Key Required |
|---|---|---|---|
| **Ollama** (local) | `ollama` | Native `/api/chat` | No |
| **OpenAI** | `openai` | Chat Completions | Yes |
| **Anthropic** | `anthropic` | Messages API | Yes |
| **Google Gemini** | `gemini` / `google` | Generate Content | Yes |
| **Azure OpenAI** | `azure` | Azure OpenAI | Yes |
| **Any OpenAI-compatible** | *any* | Chat Completions | Varies |

## Recommended Models

### Ollama Models (Local)

| Model | Pull Command | VRAM | Quality | Notes |
|---|---|---|---|---|
| **Qwen3.5 122B** | `ollama pull qwen3.5:122b` | 48+ GB | ⭐⭐⭐⭐⭐ | Best quality, most reliable |
| **Llama 3.1 70B** | `ollama pull llama3.1:70b` | 35-40 GB | ⭐⭐⭐⭐⭐ | Default model, excellent tool calling |
| **Qwen3.5 35B** | `ollama pull qwen3.5:35b` | 20 GB | ⭐⭐⭐⭐ | Recommended for most users |
| **Qwen3.5 35b MoE** | `ollama pull qwen3.5:35b-a3b` | 16 GB | ⭐⭐⭐⭐ | Lower VRAM via MoE |
| **Mistral Small 3.1 24B** | `ollama pull mistral-small:24b` | 14 GB | ⭐⭐⭐⭐ | Good tool calling |
| **Llama 3.1 8B** | `ollama pull llama3.1:8b` | 6 GB | ⭐⭐⭐ | Usable, frequent errors |
| **Qwen3.5 9B** | `ollama pull qwen3.5:9b` | 6 GB | ⭐⭐⭐ | Minimum viable |
| **Phi-4 14B** | `ollama pull phi-4:14b` | 8 GB | ⭐⭐⭐ | Good for its size |
| **DeepSeek R1** | `ollama pull deepseek-r1:7b` | 4-6 GB | ⭐⭐ | Known: incomplete function calls |
| **< 8B models** | *various* | < 4 GB | ⭐ | Not recommended for serious testing |

### Cloud Models

| Model | Provider | Quality | Notes |
|---|---|---|---|
| **GPT-4o** | OpenAI | ⭐⭐⭐⭐⭐ | Excellent tool calling |
| **GPT-4o-mini** | OpenAI | ⭐⭐⭐⭐ | Good balance of speed/cost |
| **Claude 3.5 Sonnet** | Anthropic | ⭐⭐⭐⭐⭐ | Excellent reasoning |
| **Claude 3 Haiku** | Anthropic | ⭐⭐⭐⭐ | Fast, cheaper |
| **Gemini 1.5 Pro** | Google | ⭐⭐⭐⭐ | Large context window |
| **Gemini 1.5 Flash** | Google | ⭐⭐⭐ | Good for simple tasks |
| **DeepSeek V3** | DeepSeek | ⭐⭐⭐⭐ | Good open-source alternative |
| **Llama 3.1 70B** | Groq/Together | ⭐⭐⭐⭐ | Fast inference |

## VRAM Guidance

| Model Size | Minimum VRAM | Recommended VRAM | Expected Reliability |
|---|---|---|---|
| **≥ 70B** | 40 GB | 48+ GB | ⭐⭐⭐⭐⭐ Reliable for full pipelines |
| **32B - 70B** | 20 GB | 24 GB | ⭐⭐⭐⭐ Good tool calling accuracy |
| **8B - 14B** | 6 GB | 8 GB | ⭐⭐⭐ Usable, 20-40% error rate |
| **< 8B** | 4 GB | 6 GB | ⭐ High hallucination rate, not recommended |

## Known Issues

| Model | Issue |
|---|---|
| **DeepSeek R1** | Produces incomplete function calls / JSON truncation. ARES's parser mitigates this but results may be unreliable. |
| **Models < 8B** | Frequently hallucinate tool output, invent CVEs, skip scope rules, and produce unreliable tool calls. |
| **Phi-3 / Phi-3.5** | Poor structured output quality for multi-turn tool calling. |
| **QWen 2.5 7B** | Has native tool call support but sometimes produces partial JSON. |

## Configuration

Set the model via environment variables:

```bash
export ARES_LLM_PROVIDER=ollama     # ollama, openai, anthropic, gemini, azure
export ARES_LLM_BASE_URL=http://localhost:11434/v1
export ARES_LLM_MODEL=llama3.1:70b
export ARES_LLM_API_KEY=sk-...      # Not needed for local providers
```

Or via command-line flags:

```bash
ares -target example.com -provider ollama -model llama3.1:70b
```
