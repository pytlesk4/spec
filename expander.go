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
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-openapi/swag"
)

// ExpandOptions provides options for expand.
type ExpandOptions struct {
	RelativeBase    string
	SkipSchemas     bool
	ContinueOnError bool
}

// ResolveRefWithBase resolves a reference against a context root with preservation of base path
func ResolveRefWithBase(root interface{}, ref *Ref, opts *ExpandOptions) (*Schema, error) {
	resolver, err := defaultSchemaLoader(root, opts, nil)
	if err != nil {
		return nil, err
	}
	specBasePath := ""
	if opts != nil && opts.RelativeBase != "" {
		specBasePath, _ = absPath(opts.RelativeBase)
	}

	result := new(Schema)
	if err := resolver.Resolve(ref, result, specBasePath); err != nil {
		return nil, err
	}
	return result, nil
}

// ResolveRef resolves a reference against a context root
// ref is guaranteed to be in root (no need to go to external files)
// ResolveRef is ONLY called from the code generation module
func ResolveRef(root interface{}, ref *Ref) (*Schema, error) {
	res, _, err := ref.GetPointer().Get(root)
	if err != nil {
		panic(err)
	}
	switch sch := res.(type) {
	case Schema:
		return &sch, nil
	case *Schema:
		return sch, nil
	case map[string]interface{}:
		b, _ := json.Marshal(sch)
		newSch := new(Schema)
		_ = json.Unmarshal(b, newSch)
		return newSch, nil
	default:
		return nil, fmt.Errorf("unknown type for the resolved reference")
	}
}

// ResolveParameter resolves a parameter reference against a context root
func ResolveParameter(root interface{}, ref Ref) (*Parameter, error) {
	return ResolveParameterWithBase(root, ref, nil)
}

// ResolveParameterWithBase resolves a parameter reference against a context root and base path
func ResolveParameterWithBase(root interface{}, ref Ref, opts *ExpandOptions) (*Parameter, error) {
	resolver, err := defaultSchemaLoader(root, opts, nil)
	if err != nil {
		return nil, err
	}

	result := new(Parameter)
	if err := resolver.Resolve(&ref, result, ""); err != nil {
		return nil, err
	}
	return result, nil
}

// ResolveResponse resolves response a reference against a context root
func ResolveResponse(root interface{}, ref Ref) (*Response, error) {
	return ResolveResponseWithBase(root, ref, nil)
}

// ResolveResponseWithBase resolves response a reference against a context root and base path
func ResolveResponseWithBase(root interface{}, ref Ref, opts *ExpandOptions) (*Response, error) {
	resolver, err := defaultSchemaLoader(root, opts, nil)
	if err != nil {
		return nil, err
	}

	result := new(Response)
	if err := resolver.Resolve(&ref, result, ""); err != nil {
		return nil, err
	}
	return result, nil
}

// ResolveItems resolves header and parameter items reference against a context root and base path
func ResolveItems(root interface{}, ref Ref, opts *ExpandOptions) (*Items, error) {
	resolver, err := defaultSchemaLoader(root, opts, nil)
	if err != nil {
		return nil, err
	}
	basePath := ""
	if opts.RelativeBase != "" {
		basePath = opts.RelativeBase
	}
	result := new(Items)
	if err := resolver.Resolve(&ref, result, basePath); err != nil {
		return nil, err
	}
	return result, nil
}

// ResolvePathItem resolves response a path item against a context root and base path
func ResolvePathItem(root interface{}, ref Ref, opts *ExpandOptions) (*PathItem, error) {
	resolver, err := defaultSchemaLoader(root, opts, nil)
	if err != nil {
		return nil, err
	}
	basePath := ""
	if opts.RelativeBase != "" {
		basePath = opts.RelativeBase
	}
	result := new(PathItem)
	if err := resolver.Resolve(&ref, result, basePath); err != nil {
		return nil, err
	}
	return result, nil
}

// normalize absolute path for cache.
// on Windows, drive letters should be converted to lower as scheme in net/url.URL
func normalizeAbsPath(path string) string {
	u, err := url.Parse(path)
	if err != nil {
		debugLog("normalize absolute path failed: %s", err)
		return path
	}
	return u.String()
}

// base or refPath could be a file path or a URL
// given a base absolute path and a ref path, return the absolute path of refPath
// 1) if refPath is absolute, return it
// 2) if refPath is relative, join it with basePath keeping the scheme, hosts, and ports if exists
// base could be a directory or a full file path
func normalizePaths(refPath, base string) string {
	refURL, _ := url.Parse(refPath)
	if path.IsAbs(refURL.Path) || filepath.IsAbs(refPath) {
		// refPath is actually absolute
		if refURL.Host != "" {
			return refPath
		}
		parts := strings.Split(refPath, "#")
		result := filepath.FromSlash(parts[0])
		if len(parts) == 2 {
			result += "#" + parts[1]
		}
		return result
	}

	// relative refPath
	baseURL, _ := url.Parse(base)
	if !strings.HasPrefix(refPath, "#") {
		// combining paths
		if baseURL.Host != "" {
			baseURL.Path = path.Join(path.Dir(baseURL.Path), refURL.Path)
		} else { // base is a file
			newBase := fmt.Sprintf("%s#%s", filepath.Join(filepath.Dir(base), filepath.FromSlash(refURL.Path)), refURL.Fragment)
			return newBase
		}

	}
	// copying fragment from ref to base
	baseURL.Fragment = refURL.Fragment
	return baseURL.String()
}

// relativeBase could be an ABSOLUTE file path or an ABSOLUTE URL
func normalizeFileRef(ref *Ref, relativeBase string) *Ref {
	// This is important for when the reference is pointing to the root schema
	if ref.String() == "" {
		r, _ := NewRef(relativeBase)
		return &r
	}

	refURL := ref.GetURL()
	debugLog("normalizing %s against %s (%s)", ref.String(), relativeBase, refURL.String())

	s := normalizePaths(ref.String(), relativeBase)
	r, _ := NewRef(s)
	return &r
}

// absPath returns the absolute path of a file
func absPath(fname string) (string, error) {
	if strings.HasPrefix(fname, "http") {
		return fname, nil
	}
	if filepath.IsAbs(fname) {
		return fname, nil
	}
	wd, err := os.Getwd()
	return filepath.Join(wd, fname), err
}

// ExpandSpec expands the references in a swagger spec
func ExpandSpec(spec *Swagger, options *ExpandOptions) error {
	resolver, err := defaultSchemaLoader(spec, options, nil)
	// Just in case this ever returns an error.
	if shouldStopOnError(err, resolver.options) {
		return err
	}

	// getting the base path of the spec to adjust all subsequent reference resolutions
	specBasePath := ""
	if options != nil && options.RelativeBase != "" {
		specBasePath, _ = absPath(options.RelativeBase)
	}

	if options == nil || !options.SkipSchemas {
		for key, definition := range spec.Definitions {
			var def *Schema
			var err error
			if def, err = expandSchema(definition, []string{fmt.Sprintf("#/definitions/%s", key)},
				resolver, specBasePath); shouldStopOnError(err, resolver.options) {
				return err
			}
			if def != nil {
				spec.Definitions[key] = *def
			}
		}
	}

	for key, parameter := range spec.Parameters {
		if err := expandParameter(&parameter, resolver, specBasePath); shouldStopOnError(err, resolver.options) {
			return err
		}
		spec.Parameters[key] = parameter
	}

	for key, response := range spec.Responses {
		if err := expandResponse(&response, resolver, specBasePath); shouldStopOnError(err, resolver.options) {
			return err
		}
		spec.Responses[key] = response
	}

	if spec.Paths != nil {
		for key, path := range spec.Paths.Paths {
			if err := expandPathItem(&path, resolver, specBasePath); shouldStopOnError(err, resolver.options) {
				return err
			}
			spec.Paths.Paths[key] = path
		}
	}

	return nil
}

func shouldStopOnError(err error, opts *ExpandOptions) bool {
	if err != nil && !opts.ContinueOnError {
		return true
	}

	if err != nil {
		log.Println(err)
	}

	return false
}

// ExpandSchema expands the refs in the schema object with reference to the root object
// go-openapi/validate uses this function
// notice that it is impossible to reference a json scema in a different file other than root
func ExpandSchema(schema *Schema, root interface{}, cache ResolutionCache) error {
	// Only save the root to a tmp file if it isn't nil.
	var base string
	if root != nil {
		base, _ = absPath("root")
		if cache == nil {
			cache = resCache
		}
		cache.Set(normalizeAbsPath(base), root)
		base = "root"
	}

	opts := &ExpandOptions{
		RelativeBase:    base,
		SkipSchemas:     false,
		ContinueOnError: false,
	}
	return ExpandSchemaWithBasePath(schema, cache, opts)
}

// ExpandSchemaWithBasePath expands the refs in the schema object, base path configured through expand options
func ExpandSchemaWithBasePath(schema *Schema, cache ResolutionCache, opts *ExpandOptions) error {
	if schema == nil {
		return nil
	}

	var basePath string
	if opts.RelativeBase != "" {
		basePath, _ = absPath(opts.RelativeBase)
	}

	resolver, err := defaultSchemaLoader(nil, opts, cache)
	if err != nil {
		return err
	}

	refs := []string{""}
	var s *Schema
	if s, err = expandSchema(*schema, refs, resolver, basePath); err != nil {
		return err
	}
	*schema = *s
	return nil
}

func expandItems(target Schema, parentRefs []string, resolver *schemaLoader, basePath string) (*Schema, error) {
	if target.Items != nil {
		if target.Items.Schema != nil {
			t, err := expandSchema(*target.Items.Schema, parentRefs, resolver, basePath)
			if err != nil {
				return nil, err
			}
			*target.Items.Schema = *t
		}
		for i := range target.Items.Schemas {
			t, err := expandSchema(target.Items.Schemas[i], parentRefs, resolver, basePath)
			if err != nil {
				return nil, err
			}
			target.Items.Schemas[i] = *t
		}
	}
	return &target, nil
}

func isCircular(ref *Ref, basePath string, parentRefs ...string) bool {
	return basePath != "" && swag.ContainsStringsCI(parentRefs, ref.String())
}

func expandSchema(target Schema, parentRefs []string, resolver *schemaLoader, basePath string) (*Schema, error) {
	if target.Ref.String() == "" && target.Ref.IsRoot() {
		// normalizing is important
		newRef := normalizeFileRef(&target.Ref, basePath)
		target.Ref = *newRef
		return &target, nil

	}

	/* change the base path of resolution when an ID is encountered
	   otherwise the basePath should inherit the parent's */
	// important: ID can be relative path
	if target.ID != "" {
		// handling the case when id is a folder
		// remember that basePath has to be a file
		refPath := target.ID
		if strings.HasSuffix(target.ID, "/") {
			// path.Clean here would not work correctly if basepath is http
			refPath = fmt.Sprintf("%s%s", refPath, "placeholder.json")
		}
		basePath = normalizePaths(refPath, basePath)
	}

	var t *Schema
	/* if Ref is found, everything else doesn't matter */
	/* Ref also changes the resolution scope of children expandSchema */
	if target.Ref.String() != "" {
		/* Here the resolution scope is changed because a $ref was encountered */
		normalizedRef := normalizeFileRef(&target.Ref, basePath)
		normalizedBasePath := normalizedRef.RemoteURI()

		/* this means there is a circle in the recursion tree */
		/* return the Ref */
		if isCircular(normalizedRef, basePath, parentRefs...) {
			target.Ref = *normalizedRef
			return &target, nil
		}

		debugLog("basePath: %s", basePath)
		if Debug {
			b, _ := json.Marshal(target)
			debugLog("calling Resolve with target: %s", string(b))
		}
		if err := resolver.Resolve(&target.Ref, &t, basePath); shouldStopOnError(err, resolver.options) {
			return nil, err
		}

		if t != nil {
			parentRefs = append(parentRefs, normalizedRef.String())
			var err error
			resolver, err = transitiveResolver(basePath, target.Ref, resolver)
			if shouldStopOnError(err, resolver.options) {
				return nil, err
			}

			return expandSchema(*t, parentRefs, resolver, normalizedBasePath)
		}
	}

	t, err := expandItems(target, parentRefs, resolver, basePath)
	if shouldStopOnError(err, resolver.options) {
		return &target, err
	}
	if t != nil {
		target = *t
	}

	for i := range target.AllOf {
		t, err := expandSchema(target.AllOf[i], parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		target.AllOf[i] = *t
	}
	for i := range target.AnyOf {
		t, err := expandSchema(target.AnyOf[i], parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		target.AnyOf[i] = *t
	}
	for i := range target.OneOf {
		t, err := expandSchema(target.OneOf[i], parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			target.OneOf[i] = *t
		}
	}
	if target.Not != nil {
		t, err := expandSchema(*target.Not, parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			*target.Not = *t
		}
	}
	for k := range target.Properties {
		t, err := expandSchema(target.Properties[k], parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			target.Properties[k] = *t
		}
	}
	if target.AdditionalProperties != nil && target.AdditionalProperties.Schema != nil {
		t, err := expandSchema(*target.AdditionalProperties.Schema, parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			*target.AdditionalProperties.Schema = *t
		}
	}
	for k := range target.PatternProperties {
		t, err := expandSchema(target.PatternProperties[k], parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			target.PatternProperties[k] = *t
		}
	}
	for k := range target.Dependencies {
		if target.Dependencies[k].Schema != nil {
			t, err := expandSchema(*target.Dependencies[k].Schema, parentRefs, resolver, basePath)
			if shouldStopOnError(err, resolver.options) {
				return &target, err
			}
			if t != nil {
				*target.Dependencies[k].Schema = *t
			}
		}
	}
	if target.AdditionalItems != nil && target.AdditionalItems.Schema != nil {
		t, err := expandSchema(*target.AdditionalItems.Schema, parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			*target.AdditionalItems.Schema = *t
		}
	}
	for k := range target.Definitions {
		t, err := expandSchema(target.Definitions[k], parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return &target, err
		}
		if t != nil {
			target.Definitions[k] = *t
		}
	}
	return &target, nil
}

func expandPathItem(pathItem *PathItem, resolver *schemaLoader, basePath string) error {
	if pathItem == nil {
		return nil
	}

	parentRefs := []string{}
	if err := derefPathItem(pathItem, parentRefs, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if pathItem.Ref.String() != "" {
		var err error
		resolver, err = transitiveResolver(basePath, pathItem.Ref, resolver)
		if shouldStopOnError(err, resolver.options) {
			return err
		}
	}
	pathItem.Ref = Ref{}

	for idx := range pathItem.Parameters {
		if err := expandParameter(&(pathItem.Parameters[idx]), resolver, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}
	}
	// TODO: funcs to get all methods in a range
	if err := expandOperation(pathItem.Get, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if err := expandOperation(pathItem.Head, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if err := expandOperation(pathItem.Options, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if err := expandOperation(pathItem.Put, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if err := expandOperation(pathItem.Post, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if err := expandOperation(pathItem.Patch, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if err := expandOperation(pathItem.Delete, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	return nil
}

func expandOperation(op *Operation, resolver *schemaLoader, basePath string) error {
	if op == nil {
		return nil
	}

	for i, param := range op.Parameters {
		if err := expandParameter(&param, resolver, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}
		op.Parameters[i] = param
	}

	if op.Responses != nil {
		responses := op.Responses
		if err := expandResponse(responses.Default, resolver, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}
		for code, response := range responses.StatusCodeResponses {
			if err := expandResponse(&response, resolver, basePath); shouldStopOnError(err, resolver.options) {
				return err
			}
			responses.StatusCodeResponses[code] = response
		}
	}
	return nil
}

func transitiveResolver(basePath string, ref Ref, resolver *schemaLoader) (*schemaLoader, error) {
	if ref.IsRoot() || ref.HasFragmentOnly {
		return resolver, nil
	}

	baseRef, _ := NewRef(basePath)
	currentRef := normalizeFileRef(&ref, basePath)
	// Set a new root to resolve against
	if !strings.HasPrefix(currentRef.String(), baseRef.String()) {
		rootURL := currentRef.GetURL()
		rootURL.Fragment = ""
		root, _ := resolver.cache.Get(rootURL.String())
		var err error
		resolver, err = defaultSchemaLoader(root, resolver.options, resolver.cache)
		if err != nil {
			return nil, err
		}
	}

	return resolver, nil
}

// ExpandResponse expands a response based on a basepath
// This is the exported version of expandResponse
// all refs inside response will be resolved relative to basePath
func ExpandResponse(response *Response, basePath string) error {
	opts := &ExpandOptions{
		RelativeBase: basePath,
	}
	resolver, err := defaultSchemaLoader(nil, opts, nil)
	if err != nil {
		return err
	}

	return expandResponse(response, resolver, basePath)
}

func expandResponse(response *Response, resolver *schemaLoader, basePath string) error {
	if response == nil {
		return nil
	}

	parentRefs := []string{}
	if err := derefResponse(response, parentRefs, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if response.Ref.String() != "" {
		var err error
		resolver, err = transitiveResolver(basePath, response.Ref, resolver)
		if shouldStopOnError(err, resolver.options) {
			return err
		}
	}
	response.Ref = Ref{}

	parentRefs = parentRefs[0:]
	if !resolver.options.SkipSchemas && response.Schema != nil {
		parentRefs = append(parentRefs, response.Schema.Ref.String())
		s, err := expandSchema(*response.Schema, parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return err
		}
		*response.Schema = *s
	}

	return nil
}

// ExpandParameter expands a parameter based on a basepath
// This is the exported version of expandParameter
// all refs inside parameter will be resolved relative to basePath
func ExpandParameter(parameter *Parameter, basePath string) error {
	opts := &ExpandOptions{
		RelativeBase: basePath,
	}
	resolver, err := defaultSchemaLoader(nil, opts, nil)
	if err != nil {
		return err
	}

	return expandParameter(parameter, resolver, basePath)
}

func expandParameter(parameter *Parameter, resolver *schemaLoader, basePath string) error {
	if parameter == nil {
		return nil
	}

	parentRefs := []string{}
	if err := derefParameter(parameter, parentRefs, resolver, basePath); shouldStopOnError(err, resolver.options) {
		return err
	}
	if parameter.Ref.String() != "" {
		var err error
		resolver, err = transitiveResolver(basePath, parameter.Ref, resolver)
		if shouldStopOnError(err, resolver.options) {
			return err
		}
	}
	parameter.Ref = Ref{}

	parentRefs = parentRefs[0:]
	if !resolver.options.SkipSchemas && parameter.Schema != nil {
		parentRefs = append(parentRefs, parameter.Schema.Ref.String())
		s, err := expandSchema(*parameter.Schema, parentRefs, resolver, basePath)
		if shouldStopOnError(err, resolver.options) {
			return err
		}
		*parameter.Schema = *s
	}
	return nil
}

func derefPathItem(pathItem *PathItem, parentRefs []string, resolver *schemaLoader, basePath string) error {
	curRef := pathItem.Ref.String()
	if curRef != "" {
		normalizedRef := normalizeFileRef(&pathItem.Ref, basePath)
		normalizedBasePath := normalizedRef.RemoteURI()

		if isCircular(normalizedRef, basePath, parentRefs...) {
			return nil
		}

		if err := resolver.Resolve(&pathItem.Ref, pathItem, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}

		if pathItem.Ref.String() != "" && pathItem.Ref.String() != curRef && basePath != normalizedBasePath {
			parentRefs = append(parentRefs, normalizedRef.String())
			return derefPathItem(pathItem, parentRefs, resolver, normalizedBasePath)
		}
	}

	return nil
}

func derefResponse(response *Response, parentRefs []string, resolver *schemaLoader, basePath string) error {
	curRef := response.Ref.String()
	if curRef != "" {
		/* Here the resolution scope is changed because a $ref was encountered */
		normalizedRef := normalizeFileRef(&response.Ref, basePath)
		normalizedBasePath := normalizedRef.RemoteURI()

		if isCircular(normalizedRef, basePath, parentRefs...) {
			return nil
		}

		if err := resolver.Resolve(&response.Ref, response, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}

		if response.Ref.String() != "" && response.Ref.String() != curRef && basePath != normalizedBasePath {
			parentRefs = append(parentRefs, normalizedRef.String())
			return derefResponse(response, parentRefs, resolver, normalizedBasePath)
		}
	}

	return nil
}

func derefParameter(parameter *Parameter, parentRefs []string, resolver *schemaLoader, basePath string) error {
	curRef := parameter.Ref.String()
	if curRef != "" {
		normalizedRef := normalizeFileRef(&parameter.Ref, basePath)
		normalizedBasePath := normalizedRef.RemoteURI()

		if isCircular(normalizedRef, basePath, parentRefs...) {
			return nil
		}

		if err := resolver.Resolve(&parameter.Ref, parameter, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}

		if parameter.Ref.String() != "" && parameter.Ref.String() != curRef && basePath != normalizedBasePath {
			parentRefs = append(parentRefs, normalizedRef.String())
			return derefParameter(parameter, parentRefs, resolver, normalizedBasePath)
		}
	}

	return nil
}

// derefRefable dereferences a Refable type, i.e replaces its $ref by its resolved content
func derefRefable(refable *Refable, parentRefs []string, resolver *schemaLoader, basePath string) error {
	curRef := refable.Ref.String()
	if curRef != "" {
		normalizedRef := normalizeFileRef(&refable.Ref, basePath)
		normalizedBasePath := normalizedRef.RemoteURI()

		if isCircular(normalizedRef, basePath, parentRefs...) {
			return nil
		}

		if err := resolver.Resolve(&refable.Ref, refable, basePath); shouldStopOnError(err, resolver.options) {
			return err
		}

		if refable.Ref.String() != "" && refable.Ref.String() != curRef && basePath != normalizedBasePath {
			parentRefs = append(parentRefs, normalizedRef.String())
			return derefRefable(refable, parentRefs, resolver, normalizedBasePath)
		}
	}

	return nil
}
