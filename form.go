package ax50

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

type FormMarshaler interface {
	MarshalForm() ([]byte, error)
}

func MarshalForm(obj interface{}) ([]byte, error) {
	switch x := obj.(type) {
	case FormMarshaler:
		return x.MarshalForm()
	case url.Values:
		return []byte(x.Encode()), nil
	case map[string]string:
		values := url.Values{}
		for k, v := range x {
			values.Set(k, v)
		}
		return []byte(values.Encode()), nil
	case map[string][]string:
		return MarshalForm(url.Values(x))
	case string:
		return []byte(x), nil
	case []byte:
		return x, nil
	}
	rv := reflect.ValueOf(obj)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	if rv.Kind() == reflect.Struct {
		rt := rv.Type()
		n := rt.NumField()
		pairs := make([]string, 0, n)
		for i := 0; i < n; i++ {
			rf := rt.Field(i)
			if rf.PkgPath != "" {
				continue
			}
			tag := strings.Split(rf.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = strings.ToLower(rf.Name)
			}
			val := rv.Field(i)
			if val.Kind() == reflect.Ptr {
				if val.IsNil() {
					continue
				}
				val = val.Elem()
			}
			pair := fmt.Sprintf("%s=%s", url.QueryEscape(tag), url.QueryEscape(asString(val)))
			pairs = append(pairs, pair)
		}
		return []byte(strings.Join(pairs, "&")), nil
	}
	if rv.Kind() == reflect.Map {
		values := url.Values{}
		iter := rv.MapRange()
		for iter.Next() {
			values.Set(asString(iter.Key()), asString(iter.Value()))
		}
		return []byte(values.Encode()), nil
	}
	return []byte(asString(rv)), nil
}

func asString(val reflect.Value) string {
	switch val.Kind() {
	case reflect.String:
		return val.String()
	case reflect.Bool:
		return strconv.FormatBool(val.Bool())
	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8:
		return strconv.FormatInt(val.Int(), 10)
	case reflect.Uint, reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8:
		return strconv.FormatUint(val.Uint(), 10)
	case reflect.Float64, reflect.Float32:
		return strconv.FormatFloat(val.Float(), 'f', -1, 64)
	}
	ival := val.Interface()
	sval, ok := ival.(fmt.Stringer)
	if ok {
		return sval.String()
	}
	return fmt.Sprintf("%#v", ival)
}
