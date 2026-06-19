package webshell

import (
	"math"
)

const entropySampleSize = 4096

func shannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	freq := make([]float64, 256)
	for _, b := range data {
		freq[b]++
	}
	length := float64(len(data))
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func highEntropyScore(data []byte, threshold float64) (float64, bool) {
	score := shannonEntropy(data)
	return score, score > threshold
}

func sampleForEntropy(data []byte) []byte {
	if len(data) <= entropySampleSize {
		return data
	}
	return data[:entropySampleSize]
}

func isHighEntropyFile(content []byte, threshold float64) (float64, bool) {
	sample := sampleForEntropy(content)
	return highEntropyScore(sample, threshold)
}
