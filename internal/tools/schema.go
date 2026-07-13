package tools

import (
	"errors"
	"fmt"
	"math"
	"strconv"
)

func ValidateInput(def Definition, args map[string]any) error {
	return ValidateSchema(def.InputSchema, args)
}

func ValidateOutput(def Definition, output map[string]any) error {
	return ValidateSchema(def.OutputSchema, output)
}

func ValidateSchema(schema map[string]any, value map[string]any) error {
	if schemaType, _ := schema["type"].(string); schemaType != "" && schemaType != "object" {
		return fmt.Errorf("unsupported root schema type %q", schemaType)
	}
	properties, _ := schema["properties"].(map[string]any)
	required := stringSlice(schema["required"])
	var errs []error
	for _, field := range required {
		if _, ok := value[field]; !ok {
			errs = append(errs, fmt.Errorf("required field %q is missing", field))
		}
	}
	if additional, ok := schema["additionalProperties"].(bool); ok && !additional {
		for key := range value {
			if _, ok := properties[key]; !ok {
				errs = append(errs, fmt.Errorf("unknown field %q is not allowed", key))
			}
		}
	}
	for key, rawPropertySchema := range properties {
		fieldValue, ok := value[key]
		if !ok {
			continue
		}
		propertySchema, ok := rawPropertySchema.(map[string]any)
		if !ok {
			continue
		}
		if err := validateField(key, propertySchema, fieldValue); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func validateField(name string, schema map[string]any, value any) error {
	if expected, ok := schema["const"]; ok && expected != value {
		return fmt.Errorf("field %q must equal %v", name, expected)
	}
	if rawType, ok := schema["type"].(string); ok {
		switch rawType {
		case "string":
			s, ok := value.(string)
			if !ok {
				return fmt.Errorf("field %q must be a string", name)
			}
			if min, ok := number(schema["minLength"]); ok && len(s) < int(min) {
				return fmt.Errorf("field %q is shorter than minimum length", name)
			}
			if max, ok := number(schema["maxLength"]); ok && len(s) > int(max) {
				return fmt.Errorf("field %q is longer than maximum length", name)
			}
		case "integer":
			n, ok := integer(value)
			if !ok {
				return fmt.Errorf("field %q must be an integer", name)
			}
			if min, ok := number(schema["minimum"]); ok && float64(n) < min {
				return fmt.Errorf("field %q is below minimum", name)
			}
			if max, ok := number(schema["maximum"]); ok && float64(n) > max {
				return fmt.Errorf("field %q is above maximum", name)
			}
		case "array":
			items, ok := arrayLen(value)
			if !ok {
				return fmt.Errorf("field %q must be an array", name)
			}
			if min, ok := number(schema["minItems"]); ok && items < int(min) {
				return fmt.Errorf("field %q has too few items", name)
			}
		default:
			return fmt.Errorf("field %q uses unsupported schema type %q", name, rawType)
		}
	}
	return nil
}

func arrayLen(value any) (int, bool) {
	switch typed := value.(type) {
	case []any:
		return len(typed), true
	case []string:
		return len(typed), true
	default:
		return 0, false
	}
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
}

func integer(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		if math.Trunc(typed) != typed {
			return 0, false
		}
		return int64(typed), true
	case jsonNumber:
		n, err := strconv.ParseInt(typed.String(), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

type jsonNumber interface {
	String() string
}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float64:
		return typed, true
	case jsonNumber:
		n, err := strconv.ParseFloat(typed.String(), 64)
		return n, err == nil
	default:
		return 0, false
	}
}
