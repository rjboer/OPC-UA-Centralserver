package centralserver

import (
	"fmt"
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

func (s *CentralServerState) Enroll(identity IdentityType) (Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.identityIndex == nil {
		s.identityIndex = make(map[string]Enrollment)
	}

	key := identityKey(identity)
	if existing, ok := s.identityIndex[key]; ok {
		return existing, nil
	}

	kind, err := moduleKindFromType(identity.ModuleType)
	if err != nil {
		return Enrollment{}, err
	}

	var enrollment Enrollment
	switch kind {
	case ModuleKindCompressor:
		s.Modules.Compressors = append(s.Modules.Compressors, CompressorType{
			FSSModuleType: FSSModuleType{Identity: identity},
		})
		enrollment = Enrollment{Kind: kind, Index: len(s.Modules.Compressors) - 1}
	case ModuleKindStorage:
		s.Modules.Storage = append(s.Modules.Storage, StorageType{
			FSSModuleType: FSSModuleType{Identity: identity},
		})
		enrollment = Enrollment{Kind: kind, Index: len(s.Modules.Storage) - 1}
	case ModuleKindDispenser:
		s.Modules.Dispensers = append(s.Modules.Dispensers, DispenserType{
			FSSModuleType: FSSModuleType{Identity: identity},
		})
		enrollment = Enrollment{Kind: kind, Index: len(s.Modules.Dispensers) - 1}
	case ModuleKindCooler:
		s.Modules.Coolers = append(s.Modules.Coolers, CoolerType{
			FSSModuleType: FSSModuleType{Identity: identity},
		})
		enrollment = Enrollment{Kind: kind, Index: len(s.Modules.Coolers) - 1}
	default:
		return Enrollment{}, fmt.Errorf("unsupported module kind %q", kind)
	}

	s.identityIndex[key] = enrollment
	return enrollment, nil
}

func (s *CentralServerState) Resolve(identity IdentityType) (Enrollment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enrollment, ok := s.identityIndex[identityKey(identity)]
	return enrollment, ok
}

func (s *CentralServerState) RecordBackupEnrollment(identity IdentityType, enrollment Enrollment, applied bool, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.BackupEnrollment = BackupEnrollmentState{
		Identity:      identity,
		ArrayName:     string(enrollment.Kind),
		Index:         int32(enrollment.Index),
		Applied:       applied,
		LastMethod:    method,
		LastUpdateUTC: time.Now().UTC(),
	}
}

func (s *CentralServerState) ReadBackupEnrollment() BackupEnrollmentState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.BackupEnrollment
}
