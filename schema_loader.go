// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package spec

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"

	"github.com/go-openapi/swag"
)

type schemaLoader struct {
	root    interface{}
	options *ExpandOptions
	cache   ResolutionCache
	loadDoc func(string) (json.RawMessage, error)
}

// PathLoader function to use when loading remote refs
var PathLoader func(string) (json.RawMessage, error)

func init() {
	PathLoader = func(path string) (json.RawMessage, error) {
		data, err := swag.LoadFromFileOrHTTP(path)
		if err != nil {
			return nil, err
		}
		return json.RawMessage(data), nil
	}
}

func defaultSchemaLoader(
	root interface{},
	expandOptions *ExpandOptions,
	cache ResolutionCache) (*schemaLoader, error) {

	if cache == nil {
		cache = resCache
	}
	if expandOptions == nil {
		expandOptions = &ExpandOptions{}
	}

	return &schemaLoader{
		root:    root,
		options: expandOptions,
		cache:   cache,
		loadDoc: func(path string) (json.RawMessage, error) {
			debugLog("fetching document at %q", path)
			return PathLoader(path)
		},
	}, nil
}

func (r *schemaLoader) resolveRef(ref *Ref, target interface{}, basePath string) error {
	tgt := reflect.ValueOf(target)
	if tgt.Kind() != reflect.Ptr {
		return fmt.Errorf("resolve ref: target needs to be a pointer")
	}

	refURL := ref.GetURL()
	if refURL == nil {
		return nil
	}

	var res interface{}
	var data interface{}
	var err error
	// Resolve against the root if it isn't nil, and if ref is pointing at the root, or has a fragment only which means
	// it is pointing somewhere in the root.
	root := r.root
	if (ref.IsRoot() || ref.HasFragmentOnly) && root == nil && basePath != "" {
		if baseRef, erb := NewRef(basePath); erb == nil {
			root, _, _, _ = r.load(baseRef.GetURL())
		}
	}
	if (ref.IsRoot() || ref.HasFragmentOnly) && root != nil {
		data = root
	} else {
		baseRef := normalizeFileRef(ref, basePath)
		debugLog("current ref is: %s", ref.String())
		debugLog("current ref normalized file: %s", baseRef.String())
		data, _, _, err = r.load(baseRef.GetURL())
		if err != nil {
			return err
		}
	}

	res = data
	if ref.String() != "" {
		res, _, err = ref.GetPointer().Get(data)
		if err != nil {
			return err
		}
	}
	if err := swag.DynamicJSONToStruct(res, target); err != nil {
		return err
	}

	return nil
}

func (r *schemaLoader) load(refURL *url.URL) (interface{}, url.URL, bool, error) {
	debugLog("loading schema from url: %s", refURL)
	toFetch := *refURL
	toFetch.Fragment = ""

	normalized := normalizeAbsPath(toFetch.String())

	data, fromCache := r.cache.Get(normalized)
	if !fromCache {
		b, err := r.loadDoc(normalized)
		if err != nil {
			return nil, url.URL{}, false, err
		}

		if err := json.Unmarshal(b, &data); err != nil {
			return nil, url.URL{}, false, err
		}
		r.cache.Set(normalized, data)
	}

	return data, toFetch, fromCache, nil
}

// Resolve resolves a reference against basePath and stores the result in target
// Resolve is not in charge of following references, it only resolves ref by following its URL
// if the schema that ref is referring to has more refs in it. Resolve doesn't resolve them
// if basePath is an empty string, ref is resolved against the root schema stored in the schemaLoader struct
func (r *schemaLoader) Resolve(ref *Ref, target interface{}, basePath string) error {
	return r.resolveRef(ref, target, basePath)
}
