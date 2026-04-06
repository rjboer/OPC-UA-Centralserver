package centralserver

import "time"

func ForwardToCustomerSCADA(src *System, dst *CustomerSCADAState) {
	if src == nil || dst == nil {
		return
	}

	src.mu.RLock()
	defer src.mu.RUnlock()

	dst.HydrogenSupplies = dst.HydrogenSupplies[:0]
	for _, skid := range src.Backend.SupplyConnectionSkids {
		dst.HydrogenSupplies = append(dst.HydrogenSupplies, SCADAHydrogenSupplyType{
			Identity:          skid.Identity,
			SupplyPressureBar: skid.SupplyPressureBar,
		})
	}

	dst.Compressors = dst.Compressors[:0]
	for _, compressor := range src.Backend.Compressors {
		dst.Compressors = append(dst.Compressors, SCADACompressorType{
			Identity:                 compressor.Identity,
			InletPressureBar:         compressor.InletPressureBar,
			BoosterOutletPressureBar: append([]float64(nil), compressor.StageOutletPressuresBar...),
		})
	}

	dst.StorageUnits = dst.StorageUnits[:0]
	for _, tower := range src.Backend.H35Towers {
		dst.StorageUnits = append(dst.StorageUnits, SCADAStorageType{
			Identity:         tower.Identity,
			BankPressuresBar: append([]float64(nil), tower.BankPressuresBar...),
		})
	}
	for _, tower := range src.Backend.H70Towers {
		dst.StorageUnits = append(dst.StorageUnits, SCADAStorageType{
			Identity:         tower.Identity,
			BankPressuresBar: append([]float64(nil), tower.BankPressuresBar...),
		})
	}

	dst.Dispensers = dst.Dispensers[:0]
	for _, dispenser := range src.Backend.DispensersH35 {
		dst.Dispensers = append(dst.Dispensers, SCADADispenserType{
			Identity:    dispenser.Identity,
			PressureBar: dispenser.PressureBar,
		})
	}
	for _, dispenser := range src.Backend.DispensersH70 {
		dst.Dispensers = append(dst.Dispensers, SCADADispenserType{
			Identity:    dispenser.Identity,
			PressureBar: dispenser.PressureBar,
		})
	}

	dst.Coolers = dst.Coolers[:0]
	for _, module := range src.Backend.CoolmarkModules {
		dst.Coolers = append(dst.Coolers, SCADACoolerType{
			Identity: module.Identity,
			Status:   firstActiveStatus(module.AlarmSignals),
		})
	}
	for _, module := range src.Backend.CoolingTorusUnits {
		dst.Coolers = append(dst.Coolers, SCADACoolerType{
			Identity: module.Identity,
			Status:   "running",
		})
	}

	dst.RefuelingSessions = append(dst.RefuelingSessions[:0], src.Backend.RefuelingSessions...)
	dst.ActiveAlarms = append(dst.ActiveAlarms[:0], src.Backend.ActiveAlarms...)
	dst.PowerMeters = append(dst.PowerMeters[:0], src.Backend.PowerMeters...)
	dst.ControlledFunctions = append(dst.ControlledFunctions[:0], src.Backend.ControlledFunctions...)
	dst.LastForward = time.Now().UTC()
}

func firstActiveStatus(signals []DigitalPointType) string {
	for _, signal := range signals {
		if signal.Active {
			return signal.Name
		}
	}
	return "running"
}
