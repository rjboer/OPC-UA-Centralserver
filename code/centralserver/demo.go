package centralserver

import (
	"math"
	"time"
)

type GeneralServerDemoConfig struct {
	Enabled bool
	SiteID  string
}

func SeedGeneralServerDemoMode(state *CentralServerState, cfg GeneralServerDemoConfig) {
	if state == nil || !cfg.Enabled {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	state.Backend.Compressors = []BackendCompressorModuleType{
		{Identity: demoIdentity(1, ModuleTypeCompressor)},
		{Identity: demoIdentity(2, ModuleTypeCompressor)},
	}
	state.Backend.CoolmarkModules = []BackendCoolmarkModuleType{
		{Identity: demoIdentity(10, ModuleTypeCoolmark)},
	}
	state.Backend.CoolingTorusUnits = []BackendTorusModuleType{
		{Identity: demoIdentity(11, ModuleTypeTorus)},
	}
	state.Backend.DispensersH35 = []BackendDispenserModuleType{
		{Identity: demoIdentity(20, ModuleTypeDispenserH35)},
		{Identity: demoIdentity(21, ModuleTypeDispenserH35)},
	}
	state.Backend.DispensersH70 = []BackendDispenserModuleType{
		{Identity: demoIdentity(22, ModuleTypeDispenserH70)},
	}
	state.Backend.H35Towers = []BackendTowerModuleType{
		{Identity: demoIdentity(30, ModuleTypeStorage)},
		{Identity: demoIdentity(31, ModuleTypeStorage)},
	}
	state.Backend.H70Towers = []BackendTowerModuleType{
		{Identity: demoIdentity(32, ModuleTypeStorage)},
	}
	state.Backend.StorageModules = []BackendStorageModuleType{
		{Identity: demoIdentity(33, ModuleTypeStorage)},
	}
	state.Backend.StorageSources = []BackendStorageSourceModuleType{
		{Identity: demoIdentity(40, ModuleTypeStorage), SourceNr: 1, Enabled: true},
		{Identity: demoIdentity(41, ModuleTypeStorage), SourceNr: 2, Enabled: true},
	}
	state.Backend.SupplyConnectionSkids = []BackendSupplyConnectionSkidModuleType{
		{Identity: demoIdentity(50, ModuleTypeStorage)},
	}
	state.Backend.StorageMasters = []BackendStorageMasterModuleType{
		{Identity: demoIdentity(60, ModuleTypeStorage)},
	}
	state.Backend.SmartSwitches = []BackendSmartSwitchModuleType{
		{Identity: demoIdentity(70, ModuleTypeStorage)},
	}
	state.Backend.PrioritySelections = []BackendPrioritySelectionModuleType{
		{Identity: demoIdentity(80, ModuleTypeStorage)},
	}
	state.Backend.PriorityStatuses = []BackendPriorityStatusModuleType{
		{Identity: demoIdentity(81, ModuleTypeStorage)},
	}
	state.Backend.DispenserLines = []BackendDispenserLineModuleType{
		{Identity: demoIdentity(90, ModuleTypeStorage), LineNr: 1},
		{Identity: demoIdentity(91, ModuleTypeStorage), LineNr: 2},
	}
	state.Backend.FeedCommunications = []BackendFeedCommunicationModuleType{
		{Identity: demoIdentity(100, ModuleTypeStorage), FeedNr: 1},
		{Identity: demoIdentity(101, ModuleTypeStorage), FeedNr: 2},
	}
	state.Backend.DispenserLineCommunications = []BackendCommunicationModuleType{
		{Identity: demoIdentity(110, ModuleTypeStorage)},
	}

	stepGeneralServerDemoLocked(&state.Backend, time.Now().UTC())
}

func StepGeneralServerDemoMode(state *CentralServerState, now time.Time) {
	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	stepGeneralServerDemoLocked(&state.Backend, now.UTC())
}

func stepGeneralServerDemoLocked(plant *BackendPlantState, now time.Time) {
	phase := float64(now.Unix()%600) / 600.0
	swing := math.Sin(phase * 2 * math.Pi)

	for i := range plant.Compressors {
		plant.Compressors[i].FilteredSupplyPressureBar = 18 + float64(i) + swing
		plant.Compressors[i].InletPressureBar = 16 + float64(i) + swing*0.5
		plant.Compressors[i].StageInletPressuresBar = []float64{18 + swing, 220 + swing*3, 450 + swing*5, 720 + swing*5}
		plant.Compressors[i].StageOutletPressuresBar = []float64{200 + swing*3, 430 + swing*5, 700 + swing*5, 930 + swing*6}
		plant.Compressors[i].PressureSetpointsBar = []float64{200, 430, 700, 930}
		plant.Compressors[i].HydraulicPressuresBar = []float64{110, 112, 114, 116}
		plant.Compressors[i].HydraulicSetpointsBar = []float64{115, 115, 115, 115}
		plant.Compressors[i].CompressedAirPressureBar = 7.5 + swing*0.2
	}

	for i := range plant.CoolmarkModules {
		plant.CoolmarkModules[i].ProcessSignals = []AnalogPointType{
			{Name: "operatingModeChiller", Value: 1, Unit: ""},
			{Name: "circuit1CompressorValue", Value: 55 + swing*10, Unit: "%"},
		}
		plant.CoolmarkModules[i].TemperaturePoints = []AnalogPointType{
			{Name: "outsideTemperature", Value: 12 + swing*6, Unit: "C"},
			{Name: "setpointCooling", Value: -20, Unit: "C"},
			{Name: "commonEvaporatorWaterInput", Value: 8 + swing*0.4, Unit: "C"},
			{Name: "commonEvaporatorWaterOutput", Value: 7 + swing*0.4, Unit: "C"},
		}
		plant.CoolmarkModules[i].PressurePoints = []AnalogPointType{
			{Name: "circuit1CondenserPressureProbe", Value: 19 + swing, Unit: "bar"},
			{Name: "circuit1EEV1PressureEvaporation", Value: 3 + swing*0.3, Unit: "bar"},
		}
		plant.CoolmarkModules[i].AlarmSignals = []DigitalPointType{
			{Name: "dangerAlarm", Active: false},
			{Name: "circuit1CompressorAlarm", Active: false},
		}
	}

	for i := range plant.CoolingTorusUnits {
		plant.CoolingTorusUnits[i].SpeedPoints = []AnalogPointType{
			{Name: "Inverter 1 Speed", Value: 30 + swing*10, Unit: "%"},
			{Name: "Fan speed controller Fan 1", Value: 40 + swing*15, Unit: "%"},
		}
		plant.CoolingTorusUnits[i].ValvePositions = []AnalogPointType{
			{Name: "Electronic Expansion valve EEV 1.VTS1", Value: 75 + swing*10, Unit: "%"},
			{Name: "Torus injection EEV 2.VTS1", Value: 45 + swing*15, Unit: "%"},
		}
	}

	for i := range plant.DispensersH35 {
		plant.DispensersH35[i].PressureBar = 350 + swing*5
		plant.DispensersH35[i].MassFlowKgPerMin = 1.8 + swing*0.2
	}
	for i := range plant.DispensersH70 {
		plant.DispensersH70[i].PressureBar = 700 + swing*8
		plant.DispensersH70[i].MassFlowKgPerMin = 2.4 + swing*0.3
	}

	for i := range plant.H35Towers {
		plant.H35Towers[i].BankPressuresBar = []float64{480 + swing*5, 470 + swing*5, 460 + swing*5}
		plant.H35Towers[i].DispenserPressureBar = 430 + swing*4
		plant.H35Towers[i].NitrogenPressureBar = 8 + swing*0.3
	}
	for i := range plant.H70Towers {
		plant.H70Towers[i].BankPressuresBar = []float64{500 + swing*5, 510 + swing*5, 520 + swing*5, 900 + swing*8, 920 + swing*8, 940 + swing*8}
		plant.H70Towers[i].StoragePressureBar = 870 + swing*6
		plant.H70Towers[i].DispenserPressureBar = 860 + swing*6
	}

	for i := range plant.StorageSources {
		plant.StorageSources[i].Stepper = 20 + i
		plant.StorageSources[i].NeedFilling = i%2 == 0
		plant.StorageSources[i].Drainable = true
	}
	for i := range plant.StorageModules {
		plant.StorageModules[i].SourceCount = len(plant.StorageSources)
		plant.StorageModules[i].TowerCount = len(plant.H35Towers) + len(plant.H70Towers)
		plant.StorageModules[i].BankPressuresBar = []float64{500 + swing*4, 520 + swing*4, 940 + swing*6}
	}
	for i := range plant.SupplyConnectionSkids {
		plant.SupplyConnectionSkids[i].SupplyPressureBar = 22 + swing
	}
	for i := range plant.DispenserLines {
		plant.DispenserLines[i].PressureRequestBar = 350 + float64(i)*350
		plant.DispenserLines[i].NewSource = i + 1
		plant.DispenserLines[i].ActualSource = i + 1
	}
	for i := range plant.FeedCommunications {
		plant.FeedCommunications[i].ActualPriority = i + 1
		plant.FeedCommunications[i].ChosenDestination = i + 1
		plant.FeedCommunications[i].ChosenSupply = i + 1
		plant.FeedCommunications[i].Command = 1
		plant.FeedCommunications[i].SupplyPressureBar = 20 + float64(i) + swing
	}
	for i := range plant.SmartSwitches {
		plant.SmartSwitches[i].StateOfChargePercent = 65 + swing*5
		plant.SmartSwitches[i].LastMessage = "demo"
	}

	plant.LastUpdate = now
}

func demoIdentity(serial uint32, moduleType uint8) IdentityType {
	return IdentityType{
		SerialNumber: serial,
		ModuleType:   moduleType,
		VendorID:     1,
	}
}
