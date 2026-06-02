package main

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func main() {
	r := rego.New(
		rego.Module("test.rego", `package a
import rego.v1
evaluation := 1`),
		rego.Query("data.a.evaluation"),
		rego.Input(make(chan int)), // Invalid input type should cause error on eval?
	)

	ctx := context.Background()
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		fmt.Println("Prepare err:", err)
		return
	}
	res, err := pq.Eval(ctx)
	if err != nil {
		fmt.Println("Eval err:", err)
	} else {
		fmt.Println("Res:", res)
	}
}
