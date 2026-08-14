package report

import (
	"path/filepath"

	wt "github.com/theworker02/wiretap/pkg/wiretap"
)

// CacheReport writes a result under dir keyed by dataset+config fingerprints.
func CacheReport(dir, datasetFP, configFP string, res *wt.Result) error {
	if dir == "" || res == nil {
		return nil
	}
	path := filepath.Join(dir, datasetFP[:16]+"_"+configFP[:16]+".json")
	return WriteJSON(path, res)
}

// LoadCachedReport loads a previously cached report if present.
func LoadCachedReport(dir, datasetFP, configFP string) (*wt.Result, bool, error) {
	if dir == "" || len(datasetFP) < 16 || len(configFP) < 16 {
		return nil, false, nil
	}
	path := filepath.Join(dir, datasetFP[:16]+"_"+configFP[:16]+".json")
	var res wt.Result
	if err := ReadJSON(path, &res); err != nil {
		return nil, false, nil
	}
	return &res, true, nil
}
