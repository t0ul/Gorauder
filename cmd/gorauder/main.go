// Command gorauder runs the default attack corpus against a target and prints a
// report. With -dry it just prints the generated attacks (no target needed).
//
//	gorauder -dry
//	gorauder -url http://127.0.0.1:4000/v1/chat/completions -model planner
//	gorauder -url ... -model planner -canary ZX9-CANARY-7Q
//
// Exit code is 2 when any attack succeeded (ASR > 0), so it fails CI if a
// regression reopens a hole.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/t0ul/gorauder"
)

func main() {
	dry := flag.Bool("dry", false, "print generated attacks and exit (no target)")
	url := flag.String("url", "", "OpenAI-compatible chat/completions endpoint")
	model := flag.String("model", "", "model name to send in the request body")
	canary := flag.String("canary", "", "score prompt-leak seeds with this canary")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout")
	flag.Parse()

	seeds := gorauder.DefaultSeeds()

	if *dry {
		for _, s := range seeds {
			for _, c := range gorauder.AllConverters() {
				fmt.Printf("── %s / %s (%s)\n%s\n\n", s.ID, c.Name(), s.Technique, c.Convert(s.Prompt))
			}
		}
		return
	}
	if *url == "" || *model == "" {
		fmt.Fprintln(os.Stderr, "gorauder: -url and -model are required (or use -dry)")
		os.Exit(1)
	}

	target := httpTarget(*url, *model, *timeout)

	var scorer gorauder.Scorer = gorauder.MarkerScorer{}
	if *canary != "" {
		// Marker seeds still score by marker; leak seeds (no marker) need canary.
		scorer = canaryOrMarker{canary: *canary}
	}

	runner := gorauder.NewRunner(target,
		gorauder.WithConverters(gorauder.AllConverters()...),
		gorauder.WithScorer(scorer),
	)
	rep := runner.Run(context.Background(), seeds)
	fmt.Print(rep.Summary())

	if rep.Succeeded > 0 {
		os.Exit(2)
	}
}

// canaryOrMarker scores marker seeds by marker and leak seeds by canary.
type canaryOrMarker struct{ canary string }

func (c canaryOrMarker) Score(seed gorauder.Seed, response string) (bool, string) {
	if seed.Marker != "" {
		return gorauder.MarkerScorer{}.Score(seed, response)
	}
	return gorauder.CanaryScorer{Canary: c.canary}.Score(seed, response)
}

func httpTarget(url, model string, timeout time.Duration) gorauder.Target {
	client := &http.Client{Timeout: timeout}
	return gorauder.TargetFunc(func(ctx context.Context, prompt string) (string, error) {
		body, _ := json.Marshal(map[string]any{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": prompt}},
		})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return extractContent(raw), nil
	})
}

// extractContent pulls the assistant text from an OpenAI-style response, falling
// back to the raw body so scorers still have something to match.
func extractContent(raw []byte) string {
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(raw, &r) == nil && len(r.Choices) > 0 && r.Choices[0].Message.Content != "" {
		return r.Choices[0].Message.Content
	}
	return string(raw)
}
