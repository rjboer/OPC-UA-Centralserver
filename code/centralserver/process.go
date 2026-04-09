package centralserver

import (
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

type ProcessConfig struct {
	Host        string
	GeneralPort int
	SCADAPort   int
	HTTPPort    int
	DemoMode    bool
}

type Process struct {
	Config  ProcessConfig
	Memory  *System
	General *RuntimeOPCUAServer
	SCADA   *RuntimeOPCUAServer

	generalNodes map[string]string
	scadaNodes   map[string]string
	methodNodes  map[string]string
	onEnroll     func(EnrollmentContext)
	onIdentify   func(IdentifyContext)
	stopCh       chan struct{}
	httpServer   *http.Server
	statusMu     sync.RWMutex
	startedAt    time.Time
	lastPublish  time.Time
	lastError    string
}

func NewProcess(cfg ProcessConfig) *Process {
	return &Process{
		Config:       cfg,
		Memory:       NewSystem(),
		General:      NewRuntimeOPCUAServer(ServerSettings{Host: cfg.Host, Port: cfg.GeneralPort}),
		SCADA:        NewRuntimeOPCUAServer(ServerSettings{Host: cfg.Host, Port: cfg.SCADAPort}),
		generalNodes: map[string]string{},
		scadaNodes:   map[string]string{},
		methodNodes:  map[string]string{},
		onEnroll:     func(EnrollmentContext) {},
		onIdentify:   func(IdentifyContext) {},
		stopCh:       make(chan struct{}),
	}
}

func (p *Process) Start() error {
	log.Printf("process start: host=%s general_port=%d scada_port=%d http_port=%d demo_mode=%t", p.Config.Host, p.Config.GeneralPort, p.Config.SCADAPort, p.Config.HTTPPort, p.Config.DemoMode)
	if p.Config.DemoMode {
		SeedGeneralServerDemoMode(p.Memory, GeneralServerDemoConfig{Enabled: true, SiteID: "demo"})
	}

	if err := p.General.Start(); err != nil {
		log.Printf("process start failed: general server start: %v", err)
		return err
	}
	if err := p.SCADA.Start(); err != nil {
		log.Printf("process start failed: scada server start: %v", err)
		p.General.Stop()
		return err
	}

	if err := p.setupGeneralNodes(); err != nil {
		log.Printf("process start failed: setup general nodes: %v", err)
		p.Stop()
		return err
	}
	if err := p.setupSCADANodes(); err != nil {
		log.Printf("process start failed: setup scada nodes: %v", err)
		p.Stop()
		return err
	}

	if err := p.refreshPublishedState(); err != nil {
		log.Printf("process start failed: initial publish: %v", err)
		p.Stop()
		return err
	}

	if err := p.startHTTPServer(); err != nil {
		log.Printf("process start failed: http server: %v", err)
		p.Stop()
		return err
	}

	p.startedAt = time.Now().UTC()

	go p.run()
	log.Printf("process started")
	return nil
}

func (p *Process) Stop() {
	log.Printf("process stopping")
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
	p.SCADA.Stop()
	p.General.Stop()
	if p.httpServer != nil {
		_ = p.httpServer.Close()
	}
}

func (p *Process) run() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if p.Config.DemoMode {
				StepGeneralServerDemoMode(p.Memory, time.Now().UTC())
			}
			_ = p.refreshPublishedState()
		case <-p.stopCh:
			return
		}
	}
}

func (p *Process) refreshPublishedState() error {
	if !p.Config.DemoMode || p.Memory.HasModules() {
		PopulateBackendFromModules(p.Memory)
	}
	err := p.publishSnapshot()
	if err != nil {
		log.Printf("publish snapshot failed: %v", err)
	}
	p.recordPublishResult(err)
	return err
}

func (p *Process) recordPublishResult(err error) {
	p.statusMu.Lock()
	defer p.statusMu.Unlock()

	if err != nil {
		p.lastError = err.Error()
		return
	}

	p.lastPublish = time.Now().UTC()
	p.lastError = ""
}

func (p *Process) setupGeneralNodes() error {
	if err := p.General.AddFolderNode("Methods", "Methods", "i=85"); err != nil {
		log.Printf("setup general nodes failed: folder Methods: %v", err)
		return err
	}
	if err := p.General.AddFolderNode("Backend", "Backend", "i=85"); err != nil {
		log.Printf("setup general nodes failed: folder Backend: %v", err)
		return err
	}
	if err := p.installMethods(); err != nil {
		log.Printf("setup general nodes failed: install methods: %v", err)
		return err
	}
	groups := []string{
		"Compressors",
		"CoolmarkModules",
		"SmartSwitches",
		"StorageModules",
		"SupplyConnectionSkids",
	}
	for _, group := range groups {
		if err := p.General.AddFolderNode(group, group, "ns=1;s=Backend"); err != nil {
			log.Printf("setup general nodes failed: folder %s: %v", group, err)
			return err
		}
		dataNode, err := p.General.AddStructArrayNode("Data", group, generalGroupElemSample(group))
		if err != nil {
			log.Printf("setup general nodes failed: data node for %s: %v", group, err)
			return err
		}
		countNode, err := p.General.AddValueNode("Count", group, int32(0))
		if err != nil {
			log.Printf("setup general nodes failed: count node for %s: %v", group, err)
			return err
		}
		p.generalNodes[group+".Data"] = dataNode
		p.generalNodes[group+".Count"] = countNode
	}
	lastUpdateNode, err := p.General.AddValueNode("LastUpdateUTC", "Backend", "")
	if err != nil {
		log.Printf("setup general nodes failed: Backend.LastUpdateUTC: %v", err)
		return err
	}
	p.generalNodes["Backend.LastUpdateUTC"] = lastUpdateNode

	if err := p.General.AddFolderNode("BackupEnrollment", "BackupEnrollment", "ns=1;s=Backend"); err != nil {
		log.Printf("setup general nodes failed: folder BackupEnrollment: %v", err)
		return err
	}
	backupDataNode, err := p.General.AddValueNode("Data", "BackupEnrollment", BackupEnrollmentState{})
	if err != nil {
		log.Printf("setup general nodes failed: BackupEnrollment.Data: %v", err)
		return err
	}
	p.generalNodes["BackupEnrollment.Data"] = backupDataNode

	backupFieldDefaults := map[string]any{
		"SerialNumber":  uint32(0),
		"ModuleType":    uint16(0),
		"VendorID":      uint16(0),
		"ArrayName":     "",
		"Index":         int32(-1),
		"Applied":       false,
		"LastMethod":    "",
		"LastUpdateUTC": "",
	}
	for field, initVal := range backupFieldDefaults {
		nodeID, nodeErr := p.General.AddValueNode(field, "BackupEnrollment", initVal)
		if nodeErr != nil {
			log.Printf("setup general nodes failed: BackupEnrollment.%s: %v", field, nodeErr)
			return nodeErr
		}
		p.generalNodes["BackupEnrollment."+field] = nodeID
	}
	return nil
}

func (p *Process) setupSCADANodes() error {
	if err := p.SCADA.AddFolderNode("SCADA", "SCADA", "i=85"); err != nil {
		log.Printf("setup scada nodes failed: folder SCADA: %v", err)
		return err
	}
	groups := []string{
		"HydrogenSupplies",
		"Compressors",
		"StorageUnits",
		"Dispensers",
		"Coolers",
		"RefuelingSessions",
		"ActiveAlarms",
		"PowerMeters",
		"ControlledFunctions",
	}
	for _, group := range groups {
		if err := p.SCADA.AddFolderNode(group, group, "ns=1;s=SCADA"); err != nil {
			log.Printf("setup scada nodes failed: folder %s: %v", group, err)
			return err
		}
		dataNode, err := p.SCADA.AddStructArrayNode("Data", group, scadaGroupElemSample(group))
		if err != nil {
			log.Printf("setup scada nodes failed: data node for %s: %v", group, err)
			return err
		}
		countNode, err := p.SCADA.AddValueNode("Count", group, int32(0))
		if err != nil {
			log.Printf("setup scada nodes failed: count node for %s: %v", group, err)
			return err
		}
		p.scadaNodes[group+".Data"] = dataNode
		p.scadaNodes[group+".Count"] = countNode
	}
	lastUpdateNode, err := p.SCADA.AddValueNode("LastUpdateUTC", "SCADA", "")
	if err != nil {
		log.Printf("setup scada nodes failed: SCADA.LastUpdateUTC: %v", err)
		return err
	}
	p.scadaNodes["SCADA.LastUpdateUTC"] = lastUpdateNode
	return nil
}

func (p *Process) publishSnapshot() error {
	general := &GeneralOPCUAServerState{}
	scada := &CustomerSCADAState{}

	ForwardToGeneralOPCUA(p.Memory, general)
	ForwardToCustomerSCADA(p.Memory, scada)

	generalValues := map[string]struct {
		count int
		data  any
	}{
		"Compressors":           {count: len(general.Plant.Compressors), data: general.Plant.Compressors},
		"CoolmarkModules":       {count: len(general.Plant.CoolmarkModules), data: general.Plant.CoolmarkModules},
		"SmartSwitches":         {count: len(general.Plant.SmartSwitches), data: general.Plant.SmartSwitches},
		"StorageModules":        {count: len(general.Plant.StorageModules), data: general.Plant.StorageModules},
		"SupplyConnectionSkids": {count: len(general.Plant.SupplyConnectionSkids), data: general.Plant.SupplyConnectionSkids},
	}
	for group, value := range generalValues {
		if err := p.General.SetNodeValue(p.generalNodes[group+".Data"], toExtensionObjectArray(value.data)); err != nil {
			log.Printf("publish general group failed: %s.Data: %v", group, err)
			return err
		}
		if err := p.General.SetNodeValue(p.generalNodes[group+".Count"], int32(value.count)); err != nil {
			log.Printf("publish general group failed: %s.Count: %v", group, err)
			return err
		}
	}
	if err := p.General.SetNodeValue(p.generalNodes["Backend.LastUpdateUTC"], general.LastForward.Format(time.RFC3339)); err != nil {
		log.Printf("publish general failed: Backend.LastUpdateUTC: %v", err)
		return err
	}
	backup := p.Memory.ReadBackupEnrollment()
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.Data"], backup); err != nil {
		log.Printf("publish general failed: BackupEnrollment.Data: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.SerialNumber"], backup.Identity.SerialNumber); err != nil {
		log.Printf("publish general failed: BackupEnrollment.SerialNumber: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.ModuleType"], uint16(backup.Identity.ModuleType)); err != nil {
		log.Printf("publish general failed: BackupEnrollment.ModuleType: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.VendorID"], backup.Identity.VendorID); err != nil {
		log.Printf("publish general failed: BackupEnrollment.VendorID: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.ArrayName"], backup.ArrayName); err != nil {
		log.Printf("publish general failed: BackupEnrollment.ArrayName: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.Index"], backup.Index); err != nil {
		log.Printf("publish general failed: BackupEnrollment.Index: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.Applied"], backup.Applied); err != nil {
		log.Printf("publish general failed: BackupEnrollment.Applied: %v", err)
		return err
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.LastMethod"], backup.LastMethod); err != nil {
		log.Printf("publish general failed: BackupEnrollment.LastMethod: %v", err)
		return err
	}
	backupLastUpdate := ""
	if !backup.LastUpdateUTC.IsZero() {
		backupLastUpdate = backup.LastUpdateUTC.Format(time.RFC3339)
	}
	if err := p.General.SetNodeValue(p.generalNodes["BackupEnrollment.LastUpdateUTC"], backupLastUpdate); err != nil {
		log.Printf("publish general failed: BackupEnrollment.LastUpdateUTC: %v", err)
		return err
	}

	scadaValues := map[string]struct {
		count int
		data  any
	}{
		"HydrogenSupplies":    {count: len(scada.HydrogenSupplies), data: scada.HydrogenSupplies},
		"Compressors":         {count: len(scada.Compressors), data: scada.Compressors},
		"StorageUnits":        {count: len(scada.StorageUnits), data: scada.StorageUnits},
		"Dispensers":          {count: len(scada.Dispensers), data: scada.Dispensers},
		"Coolers":             {count: len(scada.Coolers), data: scada.Coolers},
		"RefuelingSessions":   {count: len(scada.RefuelingSessions), data: scada.RefuelingSessions},
		"ActiveAlarms":        {count: len(scada.ActiveAlarms), data: scada.ActiveAlarms},
		"PowerMeters":         {count: len(scada.PowerMeters), data: scada.PowerMeters},
		"ControlledFunctions": {count: len(scada.ControlledFunctions), data: scada.ControlledFunctions},
	}
	for group, value := range scadaValues {
		if err := p.SCADA.SetNodeValue(p.scadaNodes[group+".Data"], toExtensionObjectArray(value.data)); err != nil {
			log.Printf("publish scada group failed: %s.Data: %v", group, err)
			return err
		}
		if err := p.SCADA.SetNodeValue(p.scadaNodes[group+".Count"], int32(value.count)); err != nil {
			log.Printf("publish scada group failed: %s.Count: %v", group, err)
			return err
		}
	}
	if err := p.SCADA.SetNodeValue(p.scadaNodes["SCADA.LastUpdateUTC"], scada.LastForward.Format(time.RFC3339)); err != nil {
		log.Printf("publish scada failed: SCADA.LastUpdateUTC: %v", err)
		return err
	}
	return nil
}

func (p *Process) installMethods() error {
	methodsNode := ua.NodeIDString{NamespaceIndex: 1, ID: "Methods"}
	parseIdentity := func(req ua.CallMethodRequest) (IdentityType, ua.CallMethodResult, bool) {
		if len(req.InputArguments) < 3 {
			return IdentityType{}, ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}, false
		}
		if len(req.InputArguments) > 3 {
			return IdentityType{}, ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}, false
		}

		var statusCode ua.StatusCode = ua.Good
		results := make([]ua.StatusCode, 3)

		serial, ok := req.InputArguments[0].(uint32)
		if !ok {
			statusCode = ua.BadInvalidArgument
			results[0] = ua.BadTypeMismatch
		}
		moduleType, ok := req.InputArguments[1].(uint16)
		if !ok {
			statusCode = ua.BadInvalidArgument
			results[1] = ua.BadTypeMismatch
		}
		vendorID, ok := req.InputArguments[2].(uint16)
		if !ok {
			statusCode = ua.BadInvalidArgument
			results[2] = ua.BadTypeMismatch
		}
		if statusCode != ua.Good {
			return IdentityType{}, ua.CallMethodResult{StatusCode: statusCode, InputArgumentResults: results}, false
		}

		return IdentityType{
			SerialNumber: serial,
			ModuleType:   uint8(moduleType),
			VendorID:     vendorID,
		}, ua.CallMethodResult{}, true
	}

	install := func(id, name string, outputArgs []ua.Argument, handler func(IdentityType) ua.CallMethodResult) error {
		methodNodeID, err := p.General.AddMethodNode(id, name, methodsNode, func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
			identity, result, ok := parseIdentity(req)
			if !ok {
				return result
			}
			return handler(identity)
		})
		if err != nil {
			return err
		}
		p.methodNodes[id] = methodNodeID
		methodNode := ua.ParseNodeID(methodNodeID)
		if _, err := p.General.AddMethodArgumentsNode(methodNode, "InputArguments", []ua.Argument{
			{Name: "SerialNumber", DataType: ua.DataTypeIDUInt32, ValueRank: ua.ValueRankScalar},
			{Name: "ModuleType", DataType: ua.DataTypeIDUInt16, ValueRank: ua.ValueRankScalar},
			{Name: "VendorID", DataType: ua.DataTypeIDUInt16, ValueRank: ua.ValueRankScalar},
		}); err != nil {
			return err
		}
		if _, err := p.General.AddMethodArgumentsNode(methodNode, "OutputArguments", outputArgs); err != nil {
			return err
		}
		return nil
	}

	if err := install(
		"Methods.IdentifyModule",
		"IdentifyModule",
		[]ua.Argument{
			{Name: "Found", DataType: ua.DataTypeIDBoolean, ValueRank: ua.ValueRankScalar},
			{Name: "ArrayName", DataType: ua.DataTypeIDString, ValueRank: ua.ValueRankScalar},
			{Name: "Index", DataType: ua.DataTypeIDInt32, ValueRank: ua.ValueRankScalar},
		},
		func(identity IdentityType) ua.CallMethodResult {
			enrollment, found := p.Memory.Resolve(identity)
			p.onIdentify(IdentifyContext{
				Identity:   identity,
				Enrollment: enrollment,
				Found:      found,
				Method:     "IdentifyModule",
				At:         time.Now().UTC(),
			})
			if !found {
				return ua.CallMethodResult{
					StatusCode:      ua.Good,
					OutputArguments: []ua.Variant{false, "", int32(-1)},
				}
			}
			return ua.CallMethodResult{
				StatusCode:      ua.Good,
				OutputArguments: []ua.Variant{true, string(enrollment.Kind), int32(enrollment.Index)},
			}
		},
	); err != nil {
		return err
	}
	if err := install(
		"Methods.EnrollModule",
		"EnrollModule",
		[]ua.Argument{
			{Name: "ArrayName", DataType: ua.DataTypeIDString, ValueRank: ua.ValueRankScalar},
			{Name: "Index", DataType: ua.DataTypeIDInt32, ValueRank: ua.ValueRankScalar},
		},
		func(identity IdentityType) ua.CallMethodResult {
			enrollment, err := p.Memory.AddModule(identity)
			if err != nil {
				return ua.CallMethodResult{StatusCode: ua.BadInvalidArgument}
			}
			p.onEnroll(EnrollmentContext{
				Identity:   identity,
				Enrollment: enrollment,
				Method:     "EnrollModule",
				At:         time.Now().UTC(),
			})
			_ = p.refreshPublishedState()
			return ua.CallMethodResult{
				StatusCode:      ua.Good,
				OutputArguments: []ua.Variant{string(enrollment.Kind), int32(enrollment.Index)},
			}
		},
	); err != nil {
		return err
	}
	testMethodNodeID, err := p.General.AddMethodNode("Methods.EnrollTest", "EnrollTest", methodsNode, func(session *server.Session, req ua.CallMethodRequest) ua.CallMethodResult {
		if len(req.InputArguments) < 1 {
			return ua.CallMethodResult{StatusCode: ua.BadArgumentsMissing}
		}
		if len(req.InputArguments) > 1 {
			return ua.CallMethodResult{StatusCode: ua.BadTooManyArguments}
		}

		input, ok := req.InputArguments[0].(int32)
		if !ok {
			return ua.CallMethodResult{
				StatusCode:           ua.BadInvalidArgument,
				InputArgumentResults: []ua.StatusCode{ua.BadTypeMismatch},
			}
		}

		return ua.CallMethodResult{
			StatusCode:      ua.Good,
			OutputArguments: []ua.Variant{input + 1},
		}
	})
	if err != nil {
		return err
	}
	p.methodNodes["Methods.EnrollTest"] = testMethodNodeID
	testMethodNode := ua.ParseNodeID(testMethodNodeID)
	if _, err := p.General.AddMethodArgumentsNode(testMethodNode, "InputArguments", []ua.Argument{
		{Name: "Value", DataType: ua.DataTypeIDInt32, ValueRank: ua.ValueRankScalar},
	}); err != nil {
		return err
	}
	if _, err := p.General.AddMethodArgumentsNode(testMethodNode, "OutputArguments", []ua.Argument{
		{Name: "ValuePlusOne", DataType: ua.DataTypeIDInt32, ValueRank: ua.ValueRankScalar},
	}); err != nil {
		return err
	}
	return install(
		"Methods.BackupEnrollModule",
		"BackupEnrollModule",
		[]ua.Argument{
			{Name: "ArrayName", DataType: ua.DataTypeIDString, ValueRank: ua.ValueRankScalar},
			{Name: "Index", DataType: ua.DataTypeIDInt32, ValueRank: ua.ValueRankScalar},
		},
		func(identity IdentityType) ua.CallMethodResult {
			enrollment, err := p.Memory.AddModule(identity)
			if err != nil {
				return ua.CallMethodResult{StatusCode: ua.BadInvalidArgument}
			}
			p.Memory.RecordBackupEnrollment(identity, enrollment, true, "BackupEnrollModule")
			p.onEnroll(EnrollmentContext{
				Identity:   identity,
				Enrollment: enrollment,
				Method:     "BackupEnrollModule",
				At:         time.Now().UTC(),
			})
			_ = p.refreshPublishedState()
			return ua.CallMethodResult{
				StatusCode:      ua.Good,
				OutputArguments: []ua.Variant{string(enrollment.Kind), int32(enrollment.Index)},
			}
		},
	)
}

func (p *Process) String() string {
	return fmt.Sprintf("general=%s:%d scada=%s:%d", p.Config.Host, p.Config.GeneralPort, p.Config.Host, p.Config.SCADAPort)
}

func generalGroupElemSample(group string) any {
	switch group {
	case "Compressors":
		return BackendCompressorModuleType{}
	case "CoolmarkModules":
		return BackendCoolmarkModuleType{}
	case "SmartSwitches":
		return BackendSmartSwitchModuleType{}
	case "StorageModules":
		return BackendStorageModuleType{}
	case "SupplyConnectionSkids":
		return BackendSupplyConnectionSkidModuleType{}
	default:
		return nil
	}
}

func scadaGroupElemSample(group string) any {
	switch group {
	case "HydrogenSupplies":
		return SCADAHydrogenSupplyType{}
	case "Compressors":
		return SCADACompressorType{}
	case "StorageUnits":
		return SCADAStorageType{}
	case "Dispensers":
		return SCADADispenserType{}
	case "Coolers":
		return SCADACoolerType{}
	case "RefuelingSessions":
		return BackendRefuelingSessionType{}
	case "ActiveAlarms":
		return BackendAlarmType{}
	case "PowerMeters":
		return BackendPowerType{}
	case "ControlledFunctions":
		return BackendControlledFunctionsType{}
	default:
		return nil
	}
}

func toExtensionObjectArray(items any) []ua.ExtensionObject {
	value := reflect.ValueOf(items)
	if !value.IsValid() || value.Kind() != reflect.Slice {
		return []ua.ExtensionObject{}
	}

	result := make([]ua.ExtensionObject, 0, value.Len())
	for i := 0; i < value.Len(); i++ {
		result = append(result, ua.ExtensionObject(value.Index(i).Interface()))
	}
	return result
}
