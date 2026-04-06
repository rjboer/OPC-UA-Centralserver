package centralserver

import "time"

func PopulateBackendFromModules(memory *System) {
	if memory == nil {
		return
	}

	memory.mu.Lock()
	defer memory.mu.Unlock()

	memory.Backend.Compressors = memory.Backend.Compressors[:0]
	for _, mod := range memory.Modules.Compressors {
		if !mod.Active {
			continue
		}
		memory.Backend.Compressors = append(memory.Backend.Compressors, BackendCompressorModuleType{
			Identity: mod.Identity,
		})
	}

	memory.Backend.StorageSources = memory.Backend.StorageSources[:0]
	memory.Backend.StorageModules = memory.Backend.StorageModules[:0]
	memory.Backend.StorageMasters = memory.Backend.StorageMasters[:0]
	memory.Backend.SupplyConnectionSkids = memory.Backend.SupplyConnectionSkids[:0]
	firstActiveStorage := true
	sourceNr := 1
	for _, mod := range memory.Modules.Storage {
		if !mod.Active {
			continue
		}
		memory.Backend.StorageModules = append(memory.Backend.StorageModules, BackendStorageModuleType{
			Identity:    mod.Identity,
			SourceCount: 1,
		})
		memory.Backend.StorageSources = append(memory.Backend.StorageSources, BackendStorageSourceModuleType{
			Identity: mod.Identity,
			SourceNr: sourceNr,
		})
		memory.Backend.SupplyConnectionSkids = append(memory.Backend.SupplyConnectionSkids, BackendSupplyConnectionSkidModuleType{
			Identity: mod.Identity,
		})
		if firstActiveStorage {
			memory.Backend.StorageMasters = append(memory.Backend.StorageMasters, BackendStorageMasterModuleType{
				Identity: mod.Identity,
			})
			firstActiveStorage = false
		}
		sourceNr++
	}

	memory.Backend.DispensersH35 = memory.Backend.DispensersH35[:0]
	memory.Backend.DispensersH70 = memory.Backend.DispensersH70[:0]
	for _, mod := range memory.Modules.Dispensers {
		if !mod.Active {
			continue
		}
		entry := BackendDispenserModuleType{Identity: mod.Identity}
		if mod.Identity.ModuleType == ModuleTypeDispenserH70 {
			memory.Backend.DispensersH70 = append(memory.Backend.DispensersH70, entry)
			continue
		}
		memory.Backend.DispensersH35 = append(memory.Backend.DispensersH35, entry)
	}

	memory.Backend.CoolmarkModules = memory.Backend.CoolmarkModules[:0]
	memory.Backend.CoolingTorusUnits = memory.Backend.CoolingTorusUnits[:0]
	for _, mod := range memory.Modules.Coolers {
		if !mod.Active {
			continue
		}
		if mod.Identity.ModuleType == ModuleTypeTorus {
			memory.Backend.CoolingTorusUnits = append(memory.Backend.CoolingTorusUnits, BackendTorusModuleType{
				Identity: mod.Identity,
			})
			continue
		}
		memory.Backend.CoolmarkModules = append(memory.Backend.CoolmarkModules, BackendCoolmarkModuleType{
			Identity: mod.Identity,
		})
	}

	memory.Backend.LastUpdate = time.Now().UTC()
}

func ForwardToGeneralOPCUA(src *System, dst *GeneralOPCUAServerState) {
	if src == nil || dst == nil {
		return
	}

	src.mu.RLock()
	defer src.mu.RUnlock()

	dst.Plant = src.Backend
	dst.LastForward = time.Now().UTC()
}
