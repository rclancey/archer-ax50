package ax50

import (
	"encoding/json"
	"errors"
)

type ResponseWrapper[T any] struct {
	Success   bool    `json:"success"`
	ErrorCode *string `json:"errorcode"`
	Data      *T      `json:"data"`
}

func ReadResponse[T any](data []byte) (*T, error) {
	obj := &ResponseWrapper[T]{}
	err := json.Unmarshal(data, obj)
	if err != nil {
		return nil, err
	}
	if !obj.Success {
		if obj.ErrorCode == nil {
			return obj.Data, errors.New("fail")
		}
		return obj.Data, errors.New(*obj.ErrorCode)
	}
	return obj.Data, nil
}
