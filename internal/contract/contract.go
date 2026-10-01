package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Endpoint struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	OperationID string `json:"operation_id"`
}

type Document struct {
	Version   string
	JSON      []byte
	Endpoints []Endpoint
}

func Parse(content []byte) (Document, error) {
	var value map[string]any
	if json.Unmarshal(content, &value) != nil {
		var yamlValue any
		if err := yaml.Unmarshal(content, &yamlValue); err != nil {
			return Document{}, fmt.Errorf("parse OpenAPI document: %w", err)
		}
		normalized, err := normalizeYAML(yamlValue)
		if err != nil {
			return Document{}, err
		}
		value, _ = normalized.(map[string]any)
	}
	version, _ := value["openapi"].(string)
	if version == "" {
		if swagger, _ := value["swagger"].(string); swagger != "" {
			version = swagger
		}
	}
	if version == "" {
		return Document{}, errors.New("document is not an OpenAPI or Swagger contract")
	}
	var endpoints []Endpoint
	paths, _ := value["paths"].(map[string]any)
	for path, rawOperations := range paths {
		operations, _ := rawOperations.(map[string]any)
		for method, rawOperation := range operations {
			method = strings.ToUpper(method)
			if !isHTTPMethod(method) {
				continue
			}
			operation, _ := rawOperation.(map[string]any)
			operationID, _ := operation["operationId"].(string)
			endpoints = append(endpoints, Endpoint{Method: method, Path: path, OperationID: operationID})
		}
	}
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path == endpoints[j].Path {
			return endpoints[i].Method < endpoints[j].Method
		}
		return endpoints[i].Path < endpoints[j].Path
	})
	canonical, err := json.Marshal(value)
	if err != nil {
		return Document{}, fmt.Errorf("encode OpenAPI document: %w", err)
	}
	return Document{Version: version, JSON: canonical, Endpoints: endpoints}, nil
}

func ValidateSourceURL(raw string, allowPrivate bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, errors.New("source URL must be an absolute HTTP(S) URL")
	}
	if allowPrivate {
		return parsed, nil
	}
	addresses, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve source host: %w", err)
	}
	for _, address := range addresses {
		if address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
			return nil, errors.New("private source URLs are disabled")
		}
	}
	return parsed, nil
}

func normalizeYAML(value any) (any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			result[key] = normalized
		}
		return result, nil
	case map[any]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			stringKey, ok := key.(string)
			if !ok {
				return nil, errors.New("OpenAPI object contains a non-string key")
			}
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			result[stringKey] = normalized
		}
		return result, nil
	case []any:
		result := make([]any, len(typed))
		for i, item := range typed {
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			result[i] = normalized
		}
		return result, nil
	default:
		return typed, nil
	}
}

func isHTTPMethod(method string) bool {
	return bytes.Contains([]byte(" GET PUT POST DELETE PATCH HEAD OPTIONS TRACE "), []byte(" "+method+" "))
}
