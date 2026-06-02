package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func main() {
	r := rego.New(rego.Module("test.rego", `package compliance.controls.err3
import rego.v1
evaluation = x if {
    x := 1 / 0
}`), rego.Query("data.compliance.controls[rule].evaluation.control_id"))

	pq, err := r.PrepareForEval(context.Background())
	if err != nil {
		fmt.Println("Prepare err:", err)
		return
	}
	res, err := pq.Eval(context.Background())
	if err != nil {
		fmt.Println("Eval err:", err)
	} else {
		fmt.Println("Res:", res)
	}
}
