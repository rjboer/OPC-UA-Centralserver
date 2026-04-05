package centralserver

import (
	"reflect"
	"strings"

	"github.com/awcullen/opcua/ua"
)

// RegisterBinaryEncodings registers the custom struct encodings used by the central server.
// Clients need the same registrations to decode ExtensionObject values back into Go structs.
func RegisterBinaryEncodings() {
	registerBinaryEncoding(IdentityType{})
	registerBinaryEncoding(SemVerType{})
	registerBinaryEncoding(BackupEnrollmentState{})
	registerBinaryEncoding(AnalogPointType{})
	registerBinaryEncoding(DigitalPointType{})
	registerBinaryEncoding(StageStatusType{})

	registerBinaryEncoding(BackendCompressorModuleType{})
	registerBinaryEncoding(BackendCoolmarkModuleType{})
	registerBinaryEncoding(BackendTorusModuleType{})
	registerBinaryEncoding(BackendDispenserModuleType{})
	registerBinaryEncoding(BackendCommunicationModuleType{})
	registerBinaryEncoding(BackendDispenserLineModuleType{})
	registerBinaryEncoding(BackendFeedCommunicationModuleType{})
	registerBinaryEncoding(BackendTowerModuleType{})
	registerBinaryEncoding(BackendPrioritySelectionModuleType{})
	registerBinaryEncoding(BackendPriorityStatusModuleType{})
	registerBinaryEncoding(BackendSmartSwitchModuleType{})
	registerBinaryEncoding(BackendStorageModuleType{})
	registerBinaryEncoding(BackendStorageMasterModuleType{})
	registerBinaryEncoding(BackendStorageSourceModuleType{})
	registerBinaryEncoding(BackendSupplyConnectionSkidModuleType{})
	registerBinaryEncoding(BackendRefuelingSessionType{})
	registerBinaryEncoding(BackendAlarmType{})
	registerBinaryEncoding(BackendPowerType{})
	registerBinaryEncoding(BackendControlledFunctionsType{})

	registerBinaryEncoding(SCADAHydrogenSupplyType{})
	registerBinaryEncoding(SCADACompressorType{})
	registerBinaryEncoding(SCADAStorageType{})
	registerBinaryEncoding(SCADADispenserType{})
	registerBinaryEncoding(SCADACoolerType{})
}

func registerBinaryEncoding(v any) {
	typ := reflect.TypeOf(v)
	id := strings.ReplaceAll(typ.String(), ".", "_") + "_Enc"
	ua.RegisterBinaryEncodingID(typ, ua.ExpandedNodeID{
		NodeID: ua.NodeIDString{NamespaceIndex: 2, ID: id},
	})
}
