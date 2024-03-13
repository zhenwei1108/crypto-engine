package util

func BytesIsEmpty(data []byte) bool {
	if data == nil || len(data) == 0 {
		return true
	}
	return false
}
