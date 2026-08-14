package wiretap

import "errors"

// Sentinel errors for callers. Messages remain actionable; wrap with fmt.Errorf("%w: ...") as needed.
var (
	ErrInvalidHex      = errors.New("invalid hex")
	ErrEmptyDataset    = errors.New("empty dataset")
	ErrNoMessages      = errors.New("no messages")
	ErrNotFound        = errors.New("not found")
	ErrBudgetExceeded  = errors.New("analysis budget exceeded")
	ErrCanceled        = errors.New("analysis canceled")
	ErrInvalidConfig   = errors.New("invalid config")
	ErrInvalidLabel    = errors.New("invalid label")
	ErrProjectExists   = errors.New("project already exists")
	ErrNoProject       = errors.New("not a wiretap project")
	ErrSchemaInvalid   = errors.New("schema invalid")
	ErrInsufficientEv  = errors.New("insufficient evidence")
	ErrTruncated       = errors.New("record truncated")
	ErrUnsupportedFmt  = errors.New("unsupported format")
	ErrDuplicateID     = errors.New("duplicate message id")
	ErrNotRegistered   = errors.New("backend not registered; blank-import github.com/theworker02/wiretap/internal/analysis and/or internal/capture")
	ErrUnsupportedPCAP = errors.New("unsupported or malformed pcap")
)
