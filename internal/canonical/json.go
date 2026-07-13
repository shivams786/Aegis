package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
)

func Hash(value any) (string, error) {
	canonical, err := Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func Marshal(value any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeValue(&buf, normalize(value)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Decode(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("canonical json contains more than one value")
	}
	return value, nil
}

func HashJSON(data []byte) (string, error) {
	value, err := Decode(data)
	if err != nil {
		return "", err
	}
	return Hash(value)
}

func writeValue(buf *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if typed {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		encoded, _ := json.Marshal(typed)
		buf.Write(encoded)
	case json.Number:
		if !typed.Valid() {
			return fmt.Errorf("invalid json number %q", typed)
		}
		buf.WriteString(typed.String())
	case int:
		buf.WriteString(strconv.FormatInt(int64(typed), 10))
	case int8:
		buf.WriteString(strconv.FormatInt(int64(typed), 10))
	case int16:
		buf.WriteString(strconv.FormatInt(int64(typed), 10))
	case int32:
		buf.WriteString(strconv.FormatInt(int64(typed), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(typed, 10))
	case uint:
		buf.WriteString(strconv.FormatUint(uint64(typed), 10))
	case uint8:
		buf.WriteString(strconv.FormatUint(uint64(typed), 10))
	case uint16:
		buf.WriteString(strconv.FormatUint(uint64(typed), 10))
	case uint32:
		buf.WriteString(strconv.FormatUint(uint64(typed), 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(typed, 10))
	case float32:
		return writeFloat(buf, float64(typed), 32)
	case float64:
		return writeFloat(buf, typed, 64)
	case []any:
		buf.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			encodedKey, _ := json.Marshal(key)
			buf.Write(encodedKey)
			buf.WriteByte(':')
			if err := writeValue(buf, typed[key]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return fmt.Errorf("marshal value for canonicalization: %w", err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			return err
		}
		return writeValue(buf, decoded)
	}
	return nil
}

func writeFloat(buf *bytes.Buffer, value float64, bits int) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return errors.New("non-finite numbers are not valid canonical json")
	}
	buf.WriteString(strconv.FormatFloat(value, 'f', -1, bits))
	return nil
}

func normalize(value any) any {
	if value == nil {
		return nil
	}
	typed := reflect.ValueOf(value)
	if typed.Kind() == reflect.Map && typed.Type().Key().Kind() == reflect.String {
		result := make(map[string]any, typed.Len())
		iter := typed.MapRange()
		for iter.Next() {
			result[iter.Key().String()] = normalize(iter.Value().Interface())
		}
		return result
	}
	if typed.Kind() == reflect.Slice || typed.Kind() == reflect.Array {
		result := make([]any, typed.Len())
		for i := 0; i < typed.Len(); i++ {
			result[i] = normalize(typed.Index(i).Interface())
		}
		return result
	}
	return value
}
