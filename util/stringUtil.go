package util

func StringIsEmpty(data string) bool {
	if data == "" || len(data) == 0 {
		return true
	}
	return false
}

func StringNotEmpty(data string) bool {
	return !StringIsEmpty(data)
}
