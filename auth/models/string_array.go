package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Scan implements sql.Scanner for reading JSON arrays from the database.
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = StringArray{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("StringArray.Scan: expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, s)
}

// Value implements driver.Valuer for writing JSON arrays to the database.
func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return string(bytes), nil
}
