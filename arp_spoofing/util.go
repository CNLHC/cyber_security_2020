package main

// force to quit when any error detected
func checkError(err error) {
	if err != nil {
		panic(err)
	}
}
