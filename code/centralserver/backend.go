package centralserver

import "time"

func PopulateBackendFromModules(state *CentralServerState) {
	if state == nil {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	state.Backend.Compressors = make([]BackendCompressorModuleType, len(state.Modules.Compressors))
	for i, mod := range state.Modules.Compressors {
		state.Backend.Compressors[i] = BackendCompressorModuleType{
			Identity: mod.Identity,
		}
	}

	state.Backend.StorageSources = state.Backend.StorageSources[:0]
	state.Backend.StorageModules = state.Backend.StorageModules[:0]
	state.Backend.StorageMasters = state.Backend.StorageMasters[:0]
	state.Backend.SupplyConnectionSkids = state.Backend.SupplyConnectionSkids[:0]
	for i, mod := range state.Modules.Storage {
		state.Backend.StorageModules = append(state.Backend.StorageModules, BackendStorageModuleType{
			Identity:    mod.Identity,
			SourceCount: 1,
		})
		state.Backend.StorageSources = append(state.Backend.StorageSources, BackendStorageSourceModuleType{
			Identity: mod.Identity,
			SourceNr: i + 1,
		})
		state.Backend.SupplyConnectionSkids = append(state.Backend.SupplyConnectionSkids, BackendSupplyConnectionSkidModuleType{
			Identity: mod.Identity,
		})
	}
	if len(state.Modules.Storage) > 0 {
		state.Backend.StorageMasters = append(state.Backend.StorageMasters, BackendStorageMasterModuleType{
			Identity: state.Modules.Storage[0].Identity,
		})
	}

	state.Backend.DispensersH35 = state.Backend.DispensersH35[:0]
	state.Backend.DispensersH70 = state.Backend.DispensersH70[:0]
	for _, mod := range state.Modules.Dispensers {
		entry := BackendDispenserModuleType{Identity: mod.Identity}
		if mod.Identity.ModuleType == ModuleTypeDispenserH70 {
			state.Backend.DispensersH70 = append(state.Backend.DispensersH70, entry)
			continue
		}
		state.Backend.DispensersH35 = append(state.Backend.DispensersH35, entry)
	}

	state.Backend.CoolmarkModules = state.Backend.CoolmarkModules[:0]
	state.Backend.CoolingTorusUnits = state.Backend.CoolingTorusUnits[:0]
	for _, mod := range state.Modules.Coolers {
		if mod.Identity.ModuleType == ModuleTypeTorus {
			state.Backend.CoolingTorusUnits = append(state.Backend.CoolingTorusUnits, BackendTorusModuleType{
				Identity: mod.Identity,
			})
			continue
		}
		state.Backend.CoolmarkModules = append(state.Backend.CoolmarkModules, BackendCoolmarkModuleType{
			Identity: mod.Identity,
		})
	}

	state.Backend.LastUpdate = time.Now().UTC()
}

func ForwardToGeneralOPCUA(src *CentralServerState, dst *GeneralOPCUAServerState) {
	if src == nil || dst == nil {
		return
	}

	src.mu.RLock()
	defer src.mu.RUnlock()

	dst.Plant = src.Backend
	dst.LastForward = time.Now().UTC()
}
