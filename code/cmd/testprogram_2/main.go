package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

const methodsObjectID = "ns=1;s=Methods"

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://127.0.0.1:4842", "OPC UA endpoint of the central server")
	value := flag.Int("value", 5, "input value for the EnrollTest OPC UA method")
	flag.Parse()

	ctx := context.Background()

	log.Println("TESTPROGRAM_2 START")
	log.Printf("connect to OPC UA server at %s", *endpoint)
	log.Printf("call EnrollTest with Value=%d", *value)

	ch, err := client.Dial(ctx, *endpoint, client.WithInsecureSkipVerify())
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	defer func() {
		if err := ch.Close(ctx); err != nil {
			ch.Abort(ctx)
		}
	}()

	result, err := callEnrollTest(ctx, ch, int32(*value))
	if err != nil {
		log.Fatalf("EnrollTest failed: %v", err)
	}

	log.Printf("EnrollTest returned ValuePlusOne=%d", result)
	log.Println("TESTPROGRAM_2 END")
}

func callEnrollTest(ctx context.Context, ch *client.Client, value int32) (int32, error) {
	res, err := ch.Call(ctx, &ua.CallRequest{
		MethodsToCall: []ua.CallMethodRequest{{
			ObjectID: ua.ParseNodeID(methodsObjectID),
			MethodID: ua.ParseNodeID("ns=2;s=Methods.EnrollTest"),
			InputArguments: []ua.Variant{
				value,
			},
		}},
	})
	if err != nil {
		return 0, err
	}
	if len(res.Results) != 1 {
		return 0, fmt.Errorf("expected 1 call result, got %d", len(res.Results))
	}
	if res.Results[0].StatusCode != ua.Good {
		return 0, fmt.Errorf("EnrollTest status %v", res.Results[0].StatusCode)
	}
	if len(res.Results[0].OutputArguments) != 1 {
		return 0, fmt.Errorf("expected 1 output argument, got %d", len(res.Results[0].OutputArguments))
	}

	result, ok := res.Results[0].OutputArguments[0].(int32)
	if !ok {
		return 0, fmt.Errorf("unexpected ValuePlusOne type %T", res.Results[0].OutputArguments[0])
	}

	return result, nil
}
