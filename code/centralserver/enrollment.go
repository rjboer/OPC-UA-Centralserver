package centralserver

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

func identityKey(identity IdentityType) string {
	return strconv.FormatUint(uint64(identity.VendorID), 10) + ":" +
		strconv.FormatUint(uint64(identity.ModuleType), 10) + ":" +
		strconv.FormatUint(uint64(identity.SerialNumber), 10)
}

func moduleKindFromType(moduleType uint8) (ModuleKind, error) {
	switch moduleType {
	case ModuleTypeStorage:
		return ModuleKindStorage, nil
	case ModuleTypeCompressor:
		return ModuleKindCompressor, nil
	case ModuleTypeDispenserH35, ModuleTypeDispenserH70:
		return ModuleKindDispenser, nil
	case ModuleTypeCoolmark, ModuleTypeTorus:
		return ModuleKindCooler, nil
	default:
		return "", fmt.Errorf("unsupported module type %d", moduleType)
	}
}

func (m *System) AddModule(identity IdentityType) (Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.identityIndex == nil {
		m.identityIndex = make(map[string]Enrollment)
	}

	key := identityKey(identity)
	if existing, ok := m.identityIndex[key]; ok {
		if err := m.setModuleActiveLocked(existing, true); err != nil {
			return Enrollment{}, err
		}
		return existing, nil
	}

	kind, err := moduleKindFromType(identity.ModuleType)
	if err != nil {
		return Enrollment{}, err
	}

	base := FSSModuleType{Identity: identity, Active: true}

	var enrollment Enrollment
	switch kind {
	case ModuleKindCompressor:
		m.Modules.Compressors = append(m.Modules.Compressors, CompressorType{
			FSSModuleType: base,
		})
		enrollment = Enrollment{Kind: kind, Index: len(m.Modules.Compressors) - 1}
	case ModuleKindStorage:
		m.Modules.Storage = append(m.Modules.Storage, StorageType{
			FSSModuleType: base,
		})
		enrollment = Enrollment{Kind: kind, Index: len(m.Modules.Storage) - 1}
	case ModuleKindDispenser:
		m.Modules.Dispensers = append(m.Modules.Dispensers, DispenserType{
			FSSModuleType: base,
		})
		enrollment = Enrollment{Kind: kind, Index: len(m.Modules.Dispensers) - 1}
	case ModuleKindCooler:
		m.Modules.Coolers = append(m.Modules.Coolers, CoolerType{
			FSSModuleType: base,
		})
		enrollment = Enrollment{Kind: kind, Index: len(m.Modules.Coolers) - 1}
	default:
		return Enrollment{}, fmt.Errorf("unsupported module kind %q", kind)
	}

	m.identityIndex[key] = enrollment
	return enrollment, nil
}

func (m *System) SetModuleActive(identity IdentityType, active bool) (Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	enrollment, ok := m.identityIndex[identityKey(identity)]
	if !ok {
		return Enrollment{}, fmt.Errorf("module not found")
	}

	if err := m.setModuleActiveLocked(enrollment, active); err != nil {
		return Enrollment{}, err
	}
	return enrollment, nil
}

func (m *System) setModuleActiveLocked(enrollment Enrollment, active bool) error {
	switch enrollment.Kind {
	case ModuleKindCompressor:
		if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Compressors) {
			return fmt.Errorf("compressor index out of range")
		}
		m.Modules.Compressors[enrollment.Index].Active = active
	case ModuleKindStorage:
		if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Storage) {
			return fmt.Errorf("storage index out of range")
		}
		m.Modules.Storage[enrollment.Index].Active = active
	case ModuleKindDispenser:
		if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Dispensers) {
			return fmt.Errorf("dispenser index out of range")
		}
		m.Modules.Dispensers[enrollment.Index].Active = active
	case ModuleKindCooler:
		if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Coolers) {
			return fmt.Errorf("cooler index out of range")
		}
		m.Modules.Coolers[enrollment.Index].Active = active
	default:
		return fmt.Errorf("unsupported module kind %q", enrollment.Kind)
	}
	return nil
}

func (m *System) ListModules() []ModuleStatusView {
	m.mu.RLock()
	defer m.mu.RUnlock()

	items := make([]ModuleStatusView, 0, len(m.identityIndex))
	for key, enrollment := range m.identityIndex {
		view := ModuleStatusView{
			Key:   key,
			Kind:  enrollment.Kind,
			Index: enrollment.Index,
		}

		switch enrollment.Kind {
		case ModuleKindCompressor:
			if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Compressors) {
				continue
			}
			mod := m.Modules.Compressors[enrollment.Index]
			view.Active = mod.Active
			view.SerialNumber = mod.Identity.SerialNumber
			view.ModuleType = mod.Identity.ModuleType
			view.VendorID = mod.Identity.VendorID
		case ModuleKindStorage:
			if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Storage) {
				continue
			}
			mod := m.Modules.Storage[enrollment.Index]
			view.Active = mod.Active
			view.SerialNumber = mod.Identity.SerialNumber
			view.ModuleType = mod.Identity.ModuleType
			view.VendorID = mod.Identity.VendorID
		case ModuleKindDispenser:
			if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Dispensers) {
				continue
			}
			mod := m.Modules.Dispensers[enrollment.Index]
			view.Active = mod.Active
			view.SerialNumber = mod.Identity.SerialNumber
			view.ModuleType = mod.Identity.ModuleType
			view.VendorID = mod.Identity.VendorID
		case ModuleKindCooler:
			if enrollment.Index < 0 || enrollment.Index >= len(m.Modules.Coolers) {
				continue
			}
			mod := m.Modules.Coolers[enrollment.Index]
			view.Active = mod.Active
			view.SerialNumber = mod.Identity.SerialNumber
			view.ModuleType = mod.Identity.ModuleType
			view.VendorID = mod.Identity.VendorID
		}

		items = append(items, view)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Kind != items[j].Kind {
			return items[i].Kind < items[j].Kind
		}
		return items[i].Index < items[j].Index
	})
	return items
}

func (m *System) HasModules() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.identityIndex) > 0
}

func (m *System) Resolve(identity IdentityType) (Enrollment, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	enrollment, ok := m.identityIndex[identityKey(identity)]
	return enrollment, ok
}

func (m *System) RecordBackupEnrollment(identity IdentityType, enrollment Enrollment, applied bool, method string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.BackupEnrollment = BackupEnrollmentState{
		Identity:      identity,
		ArrayName:     string(enrollment.Kind),
		Index:         int32(enrollment.Index),
		Applied:       applied,
		LastMethod:    method,
		LastUpdateUTC: time.Now().UTC(),
	}
}

func (m *System) ReadBackupEnrollment() BackupEnrollmentState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.BackupEnrollment
}
