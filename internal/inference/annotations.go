package inference

import (
	"context"
	"fmt"

	"github.com/theworker02/wiretap/internal/project"
	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// AnnotationPass boosts hypotheses that agree with trusted human annotations
// and warns (via observations) when evidence contradicts an annotation.
// Annotations are never overwritten.
type AnnotationPass struct {
	Annotations []project.Annotation
}

func (a AnnotationPass) Name() string { return "annotations" }

func (a AnnotationPass) Run(ctx context.Context, in *wt.PassInput) (*wt.PassOutput, error) {
	out := &wt.PassOutput{}
	if len(a.Annotations) == 0 {
		return out, nil
	}
	for _, ann := range a.Annotations {
		out.Observations = append(out.Observations, wt.Observation{
			Kind: "annotation", Offset: ann.Offset, Length: ann.Length,
			Description: fmt.Sprintf("trusted annotation %s kind=%s label=%q", ann.ID, ann.Kind, ann.Label),
			Metrics: map[string]any{
				"id": ann.ID, "kind": ann.Kind, "label": ann.Label, "note": ann.Note,
			},
		})
	}
	if in == nil {
		return out, nil
	}
	// Boost matching prior hypotheses by rewriting with extra evidence (emit updated copies).
	var boosted []wt.Hypothesis
	for _, h := range in.Hypotheses {
		for _, ann := range a.Annotations {
			if !overlaps(h.Offset, h.Length, ann.Offset, ann.Length) {
				continue
			}
			ev := append([]wt.EvidenceItem(nil), h.Confidence.Evidence...)
			kindMatch := ann.Kind == "" || ann.Kind == "field" || ann.Kind == h.Kind ||
				(ann.Kind == "length" && h.Kind == "length") ||
				(ann.Kind == "checksum" && h.Kind == "checksum")
			if kindMatch || ann.Label != "" {
				ev = append(ev, wt.EvidenceItem{
					Kind: "support", Description: fmt.Sprintf("matches trusted annotation %s (%s)", ann.ID, ann.Label),
					Weight: 3, Metric: "annotation", Value: 1,
				})
				h2 := h
				h2.Confidence = wt.DeriveConfidence(ev)
				if ann.Label != "" {
					if h2.Params == nil {
						h2.Params = map[string]any{}
					}
					h2.Params["annotation_label"] = ann.Label
					h2.Params["annotation_id"] = ann.ID
				}
				boosted = append(boosted, h2)
			}
			// Contradiction: annotation claims a kind that conflicts with a high-confidence hyp of different kind
			if ann.Kind != "" && ann.Kind != "field" && ann.Kind != h.Kind &&
				(h.Confidence.Level == wt.ConfidenceHigh || h.Confidence.Level == wt.ConfidenceMedium) {
				out.Observations = append(out.Observations, wt.Observation{
					Kind: "annotation_conflict", Offset: ann.Offset, Length: ann.Length,
					Description: fmt.Sprintf("WARNING: hypothesis %s (%s) conflicts with annotation %s kind=%s — annotation preserved", h.ID, h.Kind, ann.ID, ann.Kind),
					Metrics: map[string]any{
						"hypothesis_id": h.ID, "annotation_id": ann.ID,
					},
				})
			}
		}
	}
	out.Hypotheses = boosted
	return out, nil
}

func overlaps(o1, l1, o2, l2 int) bool {
	if l1 <= 0 {
		l1 = 1
	}
	if l2 <= 0 {
		l2 = 1
	}
	if o1 < 0 || o2 < 0 {
		return false
	}
	return o1 < o2+l2 && o2 < o1+l1
}

// ApplyAnnotationWarnings appends CLI-facing warnings when observations note conflicts.
func ApplyAnnotationWarnings(res *wt.Result) {
	if res == nil {
		return
	}
	for _, o := range res.Observations {
		if o.Kind == "annotation_conflict" {
			res.Warnings = append(res.Warnings, o.Description)
		}
	}
}
