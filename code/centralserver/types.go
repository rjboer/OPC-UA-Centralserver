package centralserver

import (
	"bytes"
	"log"
	"sync"
	"time"
)

const (
	ModuleTypeStorage      uint8 = 2
	ModuleTypeCompressor   uint8 = 3
	ModuleTypeDispenserH35 uint8 = 4
	ModuleTypeDispenserH70 uint8 = 5
	ModuleTypeCoolmark     uint8 = 6
	ModuleTypeTorus        uint8 = 7
)

type ModuleKind string

const (
	ModuleKindStorage    ModuleKind = "storage"
	ModuleKindCompressor ModuleKind = "compressor"
	ModuleKindDispenser  ModuleKind = "dispenser"
	ModuleKindCooler     ModuleKind = "cooler"
)

type StateType struct {
	FSSModules  FSSmodsType
	ScadaServer OPCUAServerType
	ServiceHMI  OPCUAServerType
	DataExport  DataExportType
}

type FSSmodsType struct {
	Storage     []StorageType
	Compressors []CompressorType
	Dispensers  []DispenserType
	Coolers     []CoolerType
}

type DataExportType struct{}

type OPCUAServerType struct{}

type OPCUAcomType struct{}

type FSSModuleType struct {
	Identity       IdentityType
	Active         bool
	OPCUAcom       OPCUAcomType
	NetworkEq      SubNetworkConType
	ModuleErrorlog []ErrorlogType
	ELog           *log.Logger
	buf            *bytes.Buffer
}

type IdentityType struct {
	SerialNumber      uint32
	ModuleType        uint8
	VendorID          uint16
	SoftwareVersion   SemVerType
	ElectricalVersion SemVerType
	MechanicalVersion SemVerType
}

type SemVerType struct {
	Major uint16
	Minor uint16
	Patch uint16
}

type CredentialsType struct {
	Username string
	Password string
}

type SubNetworkConType struct {
	Installed bool
	SSHcon    SSHSettingsType
	Type      int
}

type SSHSettingsType struct {
	IpAddress   string
	Port        int
	Credentials CredentialsType
}

type ErrorlogType struct {
	ErrorCode   uint32
	Info1       uint32
	Info2       uint32
	Info3       uint32
	Info4       uint32
	Info5       uint32
	ErrorType   uint32
	ackRequired uint32
	Count       uint32
}

type CompressorType struct {
	FSSModuleType
	StopPub chan bool
}

type StorageType struct {
	FSSModuleType
	StopPub chan bool
}

type DispenserType struct {
	FSSModuleType
	FuelLog         FuelLog
	FuelLogCustomer FuelLogCustomer
	StopPub         chan bool
	DispenserNr     int
}

type CoolerType struct {
	FSSModuleType
	StopPub chan bool
}

type StorageProcessDataFeed struct {
	SupplyPressure int
	Cmd            uint8
}

type StorageProcessDataDispenser struct {
	SupplyPressure int
	Status         uint8
}

type DispenserRequest struct {
	Pressure int
	Flow     int
}

type FuelLog struct {
	OrganizationID uint
	UserID         uint
	StartTime      time.Time
	StopTime       time.Time
	FilledMass     any
	SOC            any
	DispenserType  int
	NoStarts       int
}

type FuelLogCustomer struct {
	StartTime          time.Time
	StopTime           time.Time
	StartPressure      any
	StopPressure       any
	StartTemperature   any
	StopTemperature    any
	AmbientTemperature any
	StopType           int
	FilledMass         any
	SOC                any
	DispenserNumber    uint
	Protocol           uint
	UserID             uint
	OrganizationID     uint
	CarID              uint
}

type Enrollment struct {
	Kind  ModuleKind
	Index int
}

type BackupEnrollmentState struct {
	Identity      IdentityType
	ArrayName     string
	Index         int32
	Applied       bool
	LastMethod    string
	LastUpdateUTC time.Time
}

type AnalogPointType struct {
	Name  string
	Value float64
	Unit  string
}

type DigitalPointType struct {
	Name   string
	Active bool
}

type StageStatusType struct {
	StageNr int
	Status  string
}

type BackendPlantState struct {
	LastUpdate                  time.Time
	Compressors                 []BackendCompressorModuleType
	CoolmarkModules             []BackendCoolmarkModuleType
	CoolingTorusUnits           []BackendTorusModuleType
	DispensersH35               []BackendDispenserModuleType
	DispensersH70               []BackendDispenserModuleType
	DispenserLineCommunications []BackendCommunicationModuleType
	DispenserLines              []BackendDispenserLineModuleType
	FeedCommunications          []BackendFeedCommunicationModuleType
	H35Towers                   []BackendTowerModuleType
	H70Towers                   []BackendTowerModuleType
	PrioritySelections          []BackendPrioritySelectionModuleType
	PriorityStatuses            []BackendPriorityStatusModuleType
	SmartSwitches               []BackendSmartSwitchModuleType
	StorageModules              []BackendStorageModuleType
	StorageMasters              []BackendStorageMasterModuleType
	StorageSources              []BackendStorageSourceModuleType
	SupplyConnectionSkids       []BackendSupplyConnectionSkidModuleType

	RefuelingSessions   []BackendRefuelingSessionType
	ActiveAlarms        []BackendAlarmType
	PowerMeters         []BackendPowerType
	ControlledFunctions []BackendControlledFunctionsType
}

type BackendCompressorModuleType struct {
	Identity                  IdentityType
	FilteredSupplyPressureBar float64
	InletPressureBar          float64
	StageInletPressuresBar    []float64
	StageOutletPressuresBar   []float64
	PressureSetpointsBar      []float64
	HydraulicPressuresBar     []float64
	HydraulicSetpointsBar     []float64
	CompressedAirPressureBar  float64
}

type BackendCoolmarkModuleType struct {
	Identity          IdentityType
	ProcessSignals    []AnalogPointType
	TemperaturePoints []AnalogPointType
	PressurePoints    []AnalogPointType
	AlarmSignals      []DigitalPointType
}

type BackendTorusModuleType struct {
	Identity          IdentityType
	SpeedPoints       []AnalogPointType
	ValvePositions    []AnalogPointType
	TemperaturePoints []AnalogPointType
	PressurePoints    []AnalogPointType
}

type BackendDispenserModuleType struct {
	Identity          IdentityType
	PressureBar       float64
	MassFlowKgPerMin  float64
	TemperaturePoints []AnalogPointType
	StatusPoints      []DigitalPointType
}

type BackendCommunicationModuleType struct {
	Identity IdentityType
	Signals  []DigitalPointType
}

type BackendDispenserLineModuleType struct {
	Identity           IdentityType
	LineNr             int
	PressureRequestBar float64
	NewSource          int
	ActualSource       int
}

type BackendFeedCommunicationModuleType struct {
	Identity          IdentityType
	FeedNr            int
	ActualPriority    int
	ChosenDestination int
	ChosenSupply      int
	Command           int
	SupplyPressureBar float64
}

type BackendTowerModuleType struct {
	Identity             IdentityType
	BankPressuresBar     []float64
	StoragePressureBar   float64
	DispenserPressureBar float64
	BypassPressureBar    float64
	NitrogenPressureBar  float64
}

type BackendPrioritySelectionModuleType struct {
	Identity IdentityType
	Feeds    []BackendFeedCommunicationModuleType
}

type BackendPriorityStatusModuleType struct {
	Identity       IdentityType
	H70950ToBeFull bool
	H70950Full     bool
	H70520ToBeFull bool
	H70520Full     bool
	H35520ToBeFull bool
	H35520Full     bool
	SupplyToBeFull bool
	SupplyFull     bool
}

type BackendSmartSwitchModuleType struct {
	Identity               IdentityType
	PositionSignals        []AnalogPointType
	SpeedSignals           []AnalogPointType
	StateOfChargePercent   float64
	LastMessage            string
	StrokeCounters         []AnalogPointType
	HydrogenValveSignals   []DigitalPointType
	HydraulicValveSignals  []DigitalPointType
	GasDetectionSignals    []DigitalPointType
	PowerConsumptionPoints []AnalogPointType
}

type BackendStorageModuleType struct {
	Identity         IdentityType
	BankPressuresBar []float64
	SourceCount      int
	TowerCount       int
}

type BackendStorageMasterModuleType struct {
	Identity IdentityType
	Signals  []AnalogPointType
}

type BackendStorageSourceModuleType struct {
	Identity     IdentityType
	SourceNr     int
	Stepper      int
	LeakDetected bool
	Enabled      bool
	NeedFilling  bool
	Drainable    bool
}

type BackendSupplyConnectionSkidModuleType struct {
	Identity          IdentityType
	SupplyPressureBar float64
}

type BackendRefuelingSessionType struct {
	Identity            IdentityType
	StartPressureBar    float64
	StopPressureBar     float64
	StartTemperatureC   float64
	StopTemperatureC    float64
	OverallMassRefueled float64
	StartTime           time.Time
	StopTime            time.Time
}

type BackendAlarmType struct {
	Identity    IdentityType
	Alarm       bool
	WarningCode uint32
	ExtraInfo   string
}

type BackendPowerType struct {
	Identity       IdentityType
	EnergyUsageKWh float64
}

type BackendControlledFunctionsType struct {
	Identity            IdentityType
	DispensersActive    bool
	CompressorActive    bool
	BuffersDisabled     bool
	SupplySourcesActive bool
	SystemActive        bool
	UnlockDispensers    bool
}

type GeneralOPCUAServerState struct {
	LastForward time.Time
	Plant       BackendPlantState
}

type CustomerSCADAState struct {
	LastForward time.Time

	HydrogenSupplies    []SCADAHydrogenSupplyType
	Compressors         []SCADACompressorType
	StorageUnits        []SCADAStorageType
	Dispensers          []SCADADispenserType
	Coolers             []SCADACoolerType
	RefuelingSessions   []BackendRefuelingSessionType
	ActiveAlarms        []BackendAlarmType
	PowerMeters         []BackendPowerType
	ControlledFunctions []BackendControlledFunctionsType
}

type SCADAHydrogenSupplyType struct {
	Identity                 IdentityType
	SupplyPressureBar        float64
	TubetrailerPressureBar   float64
	ConsolidationPressureBar float64
}

type SCADACompressorType struct {
	Identity                 IdentityType
	InletPressureBar         float64
	HydraulicStages          []StageStatusType
	BoosterOutletPressureBar []float64
}

type SCADAStorageType struct {
	Identity            IdentityType
	BankPressuresBar    []float64
	AmbientTemperatureC float64
	Status              string
}

type SCADADispenserType struct {
	Identity     IdentityType
	PressureBar  float64
	TemperatureC float64
	Status       string
}

type SCADACoolerType struct {
	Identity           IdentityType
	TemperatureValuesC []float64
	Status             string
}

type ModuleStatusView struct {
	Key          string
	Kind         ModuleKind
	Index        int
	Active       bool
	SerialNumber uint32
	ModuleType   uint8
	VendorID     uint16
}

type System struct {
	mu sync.RWMutex

	Modules FSSmodsType
	Backend BackendPlantState

	BackupEnrollment BackupEnrollmentState

	identityIndex map[string]Enrollment
}

func NewSystem() *System {
	return &System{
		Modules:          FSSmodsType{},
		Backend:          NewBackendPlantState(),
		BackupEnrollment: BackupEnrollmentState{},
		identityIndex:    make(map[string]Enrollment),
	}
}

func NewBackendPlantState() BackendPlantState {
	return BackendPlantState{
		Compressors:                 []BackendCompressorModuleType{},
		CoolmarkModules:             []BackendCoolmarkModuleType{},
		CoolingTorusUnits:           []BackendTorusModuleType{},
		DispensersH35:               []BackendDispenserModuleType{},
		DispensersH70:               []BackendDispenserModuleType{},
		DispenserLineCommunications: []BackendCommunicationModuleType{},
		DispenserLines:              []BackendDispenserLineModuleType{},
		FeedCommunications:          []BackendFeedCommunicationModuleType{},
		H35Towers:                   []BackendTowerModuleType{},
		H70Towers:                   []BackendTowerModuleType{},
		PrioritySelections:          []BackendPrioritySelectionModuleType{},
		PriorityStatuses:            []BackendPriorityStatusModuleType{},
		SmartSwitches:               []BackendSmartSwitchModuleType{},
		StorageModules:              []BackendStorageModuleType{},
		StorageMasters:              []BackendStorageMasterModuleType{},
		StorageSources:              []BackendStorageSourceModuleType{},
		SupplyConnectionSkids:       []BackendSupplyConnectionSkidModuleType{},
		RefuelingSessions:           []BackendRefuelingSessionType{},
		ActiveAlarms:                []BackendAlarmType{},
		PowerMeters:                 []BackendPowerType{},
		ControlledFunctions:         []BackendControlledFunctionsType{},
	}
}
