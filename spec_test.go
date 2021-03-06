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

package spec_test

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-openapi/spec"
	"github.com/go-openapi/swag"
	"github.com/stretchr/testify/assert"
)

// mimics what the go-openapi/load does
var yamlLoader func(string) (json.RawMessage, error) = swag.YAMLDoc

func loadOrFail(t *testing.T, path string) *spec.Swagger {
	raw, erl := yamlLoader(path)
	if erl != nil {
		t.Logf("can't load fixture %s: %v", path, erl)
		t.FailNow()
		return nil
	}
	swspec := new(spec.Swagger)
	if err := json.Unmarshal(raw, swspec); err != nil {
		t.FailNow()
		return nil
	}
	return swspec
}

// Test unitary fixture for dev and bug fixing
func Test_Issue1429(t *testing.T) {
	prevPathLoader := spec.PathLoader
	defer func() {
		spec.PathLoader = prevPathLoader
	}()
	spec.PathLoader = yamlLoader
	path := filepath.Join("fixtures", "bugs", "1429", "swagger.yaml")

	// load and full expand
	sp := loadOrFail(t, path)
	err := spec.ExpandSpec(sp, &spec.ExpandOptions{RelativeBase: path, SkipSchemas: false})
	if !assert.NoError(t, err) {
		t.FailNow()
		return
	}

	// assert well expanded
	if !assert.Truef(t, (sp.Paths != nil && sp.Paths.Paths != nil), "expected paths to be available in fixture") {
		t.FailNow()
		return
	}
	for _, pi := range sp.Paths.Paths {
		for _, param := range pi.Get.Parameters {
			if assert.NotNilf(t, param.Schema, "expected param schema not to be nil") {
				// all param fixtures are body param with schema
				// all $ref expanded
				assert.Equal(t, "", param.Schema.Ref.String())
			}
		}
		for code, response := range pi.Get.Responses.StatusCodeResponses {
			// all response fixtures are with StatusCodeResponses, but 200
			if code == 200 {
				assert.Nilf(t, response.Schema, "expected response schema to be nil")
				continue
			}
			if assert.NotNilf(t, response.Schema, "expected response schema not to be nil") {
				assert.Equal(t, "", response.Schema.Ref.String())
			}
		}
	}
	for _, def := range sp.Definitions {
		assert.Equal(t, "", def.Ref.String())
	}

	// reload and SkipSchemas: true
	sp = loadOrFail(t, path)
	err = spec.ExpandSpec(sp, &spec.ExpandOptions{RelativeBase: path, SkipSchemas: true})
	if !assert.NoError(t, err) {
		t.FailNow()
		return
	}

	// assert well resolved
	if !assert.Truef(t, (sp.Paths != nil && sp.Paths.Paths != nil), "expected paths to be available in fixture") {
		t.FailNow()
		return
	}
	for _, pi := range sp.Paths.Paths {
		for _, param := range pi.Get.Parameters {
			if assert.NotNilf(t, param.Schema, "expected param schema not to be nil") {
				// all param fixtures are body param with schema
				if param.Name == "plainRequest" {
					// this one is expanded
					assert.Equal(t, "", param.Schema.Ref.String())
					continue
				}
				if param.Name == "nestedBody" {
					// this one is local
					assert.True(t, strings.HasPrefix(param.Schema.Ref.String(), "#/definitions/"))
					continue
				}
				if param.Name == "remoteRequest" {
					assert.Contains(t, param.Schema.Ref.String(), "remote/remote.yaml#/")
					continue
				}
				assert.Contains(t, param.Schema.Ref.String(), "responses.yaml#/")
			}
		}
		for code, response := range pi.Get.Responses.StatusCodeResponses {
			// all response fixtures are with StatusCodeResponses, but 200
			if code == 200 {
				assert.Nilf(t, response.Schema, "expected response schema to be nil")
				continue
			}
			if code == 204 {
				assert.Contains(t, response.Schema.Ref.String(), "remote/remote.yaml#/")
				continue
			}
			if code == 404 {
				assert.Equal(t, "", response.Schema.Ref.String())
				continue
			}
			assert.Containsf(t, response.Schema.Ref.String(), "responses.yaml#/", "expected remote ref at resp. %d", code)
		}
	}
	for _, def := range sp.Definitions {
		assert.Contains(t, def.Ref.String(), "responses.yaml#/")
	}
}
