# hookingo k2 changes
Go library for monkey patching
This library has been forked from : https://github.com/fengyoulin/hookingo and contains changes with are proprietary to K2 Cyber Security Inc. 
## Compatibility
- **Go version:** tested from `go1.14` and above
- **Architectures:**  `amd64`
- **Operating systems:** tested in `macos`, `linux`

### Example
```go
package main

import (
	"fmt"
	"github.com/k2io/hookingo"
)

func say1() {
	fmt.Printf("Hello k2\n")
}

func saywrap() {
	fmt.Printf("Hello k2 cyber\n")
	saywrap_s()
}
func saywrap_s() {
	fmt.Printf("Hello k2 cyber by _s\n")
}
func main() {
	h, e := hookingo.ApplyWrap(say1, saywrap,saywrap_s)
	if e != nil {
	fmt.Println("Unable to Hook ",e)
	}else if h == nil {
	    fmt.Println("Unable to Hook nil hookingo result")
	}
    say1()
}
```
Build the example with gcflags to prevent inline optimization:
```shell script
go build -gcflags '-l' 
```
The example should output:
```shell script
Hello k2 cyber
Hello k2
```