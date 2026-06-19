package llm_test

import (
	"context"
	"testing"

	"github.com/ares/engine/internal/llm"
)

func BenchmarkCountTokens(b *testing.B) {
	inputs := []struct {
		name string
		text string
	}{
		{"short", "hello world"},
		{"long_english", "The quick brown fox jumps over the lazy dog. This is a longer English text that simulates a typical LLM response with multiple sentences and varied vocabulary."},
		{"code", `func main() { fmt.Println("hello world") for i := 0; i < 10; i++ { logger.Info(fmt.Sprintf("iteration %d", i)) } }`},
		{"cjk", "你好世界，这是一个测试消息。中文文本需要不同的分词策略。"},
		{"attack_payload", "' OR '1'='1' UNION SELECT * FROM users -- <script>alert(1)</script> $(cat /etc/shadow)"},
		{"empty", ""},
	}
	b.ResetTimer()
	for _, in := range inputs {
		b.Run(in.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = llm.CountTokens(in.text)
			}
		})
	}
}

func BenchmarkComplete(b *testing.B) {
	messages := []llm.Message{
		{Role: "user", Content: "Hello, how are you?"},
		{Role: "assistant", Content: "I'm doing well, thank you for asking!"},
		{Role: "user", Content: "What can you help me with today?"},
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = llm.SummarizeMessages(context.Background(), nil, messages)
	}
}

func BenchmarkParseToolCalls(b *testing.B) {
	inputs := []struct {
		name string
		text string
	}{
		{"simple", `<function=test><parameter=foo>bar</parameter></function>`},
		{"nested", `<function=scan><parameter=target>example.com</parameter><parameter=ports>80,443</parameter><parameter=timeout>30</parameter></function>`},
		{"invoke_format", `<invoke name="nmap"><parameter name="target">10.0.0.1</parameter><parameter name="flags">-sV -sC</parameter></invoke>`},
		{"json_format", `{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"terminal_execute","arguments":"{\"command\":\"nmap -sV target.com\"}"}}]}`},
		{"attack", `<function=sql_injection><parameter=query>' OR '1'='1' UNION SELECT * FROM users --</parameter></function>`},
	}
	b.ResetTimer()
	for _, in := range inputs {
		b.Run(in.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = llm.ParseToolCalls(in.text)
			}
		})
	}
}
