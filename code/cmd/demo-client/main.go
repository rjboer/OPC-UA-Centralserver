package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"opc-ua-centralserver/centralserver"

	"github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"
)

func main() {
	endpoint := flag.String("endpoint", "opc.tcp://127.0.0.1:4842", "OPC UA endpoint")
	root := flag.String("root", "ns=1;s=Backend", "Root folder to inspect")
	group := flag.String("group", "Compressors", "Group folder to inspect")
	flag.Parse()

	centralserver.RegisterBinaryEncodings()

	ctx := context.Background()
	ch, err := client.Dial(ctx, *endpoint, client.WithInsecureSkipVerify())
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	defer func() {
		if err := ch.Close(ctx); err != nil {
			ch.Abort(ctx)
		}
	}()

	groupNodeID, err := findChildNodeID(ctx, ch, *root, *group)
	if err != nil {
		log.Fatalf("browse group failed: %v", err)
	}
	dataNodeID, err := findChildNodeID(ctx, ch, groupNodeID, "Data")
	if err != nil {
		log.Fatalf("browse data node failed: %v", err)
	}

	res, err := ch.Read(ctx, &ua.ReadRequest{
		NodesToRead: []ua.ReadValueID{{
			NodeID:      ua.ParseNodeID(dataNodeID),
			AttributeID: ua.AttributeIDValue,
		}},
	})
	if err != nil {
		log.Fatalf("read failed: %v", err)
	}

	fmt.Printf("Node: %s\n", dataNodeID)
	fmt.Printf("Status: %v\n", res.Results[0].StatusCode)
	fmt.Printf("Value type: %T\n", res.Results[0].Value)

	switch values := res.Results[0].Value.(type) {
	case []ua.ExtensionObject:
		fmt.Printf("Array length: %d\n", len(values))
		if len(values) == 0 {
			return
		}
		fmt.Printf("First element type: %T\n", values[0])
		switch first := values[0].(type) {
		case centralserver.BackendCompressorModuleType:
			fmt.Printf("First compressor serial: %d\n", first.Identity.SerialNumber)
			fmt.Printf("First compressor inlet pressure: %.2f bar\n", first.InletPressureBar)
		case centralserver.BackendCoolmarkModuleType:
			fmt.Printf("First coolmark serial: %d\n", first.Identity.SerialNumber)
		case centralserver.BackendSmartSwitchModuleType:
			fmt.Printf("First smartswitch serial: %d\n", first.Identity.SerialNumber)
		case centralserver.BackendStorageModuleType:
			fmt.Printf("First storage serial: %d\n", first.Identity.SerialNumber)
		case centralserver.BackendSupplyConnectionSkidModuleType:
			fmt.Printf("First supply skid serial: %d\n", first.Identity.SerialNumber)
		case centralserver.SCADACompressorType:
			fmt.Printf("First SCADA compressor serial: %d\n", first.Identity.SerialNumber)
		case centralserver.SCADAStorageType:
			fmt.Printf("First SCADA storage serial: %d\n", first.Identity.SerialNumber)
		case centralserver.SCADADispenserType:
			fmt.Printf("First SCADA dispenser serial: %d\n", first.Identity.SerialNumber)
		case centralserver.SCADACoolerType:
			fmt.Printf("First SCADA cooler serial: %d\n", first.Identity.SerialNumber)
		default:
			fmt.Printf("First element: %#v\n", first)
		}
	default:
		fmt.Printf("Raw value: %#v\n", values)
	}
}

func findChildNodeID(ctx context.Context, ch *client.Client, parentNodeID string, browseName string) (string, error) {
	res, err := ch.Browse(ctx, &ua.BrowseRequest{
		NodesToBrowse: []ua.BrowseDescription{{
			NodeID:          ua.ParseNodeID(parentNodeID),
			BrowseDirection: ua.BrowseDirectionForward,
			ReferenceTypeID: ua.ReferenceTypeIDHierarchicalReferences,
			IncludeSubtypes: true,
			ResultMask:      uint32(ua.BrowseResultMaskTargetInfo),
		}},
	})
	if err != nil {
		return "", err
	}
	for _, ref := range res.Results[0].References {
		if ref.BrowseName.Name == browseName {
			return fmt.Sprintf("%v", ref.NodeID.NodeID), nil
		}
	}
	return "", fmt.Errorf("child %q not found under %s", browseName, parentNodeID)
}
