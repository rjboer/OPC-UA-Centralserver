package centralserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"reflect"
	"runtime/debug"
	"strings"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"golang.org/x/crypto/sha3"
)

type ServerSettings struct {
	Host string
	Port int
}

type RuntimeOPCUAServer struct {
	Settings      ServerSettings
	NameSpaceMngr *server.NamespaceManager
	Server        *server.Server
	nextNodeID    uint32
	trackedNodes  map[ua.NodeID]struct{}
	nodeOrder     []ua.NodeID
	typeRegistry  map[string]reflect.Type
	typeOrder     []string
}

const runtimeNamespaceURI = "urn:opc-ua-centralserver:runtime"
const runtimeBinaryDictionaryNodeID = "ns=2;s=centralserver_OpcBinarySchema"
const runtimeBinaryDictionaryName = "centralserver"

var variableRolePermissions = []ua.RolePermissionType{
	{
		RoleID:      ua.ObjectIDWellKnownRoleAnonymous,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleAuthenticatedUser,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleOperator,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleEngineer,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleSupervisor,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite,
	},
}

var objectRolePermissions = []ua.RolePermissionType{
	{
		RoleID:      ua.ObjectIDWellKnownRoleAnonymous,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeWriteAttribute,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleAuthenticatedUser,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeWriteAttribute,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleOperator,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeWriteAttribute,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleEngineer,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeWriteAttribute,
	},
	{
		RoleID:      ua.ObjectIDWellKnownRoleSupervisor,
		Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeWriteAttribute,
	},
}

var uaTypes = map[reflect.Kind]ua.NodeID{
	reflect.Bool:    ua.DataTypeIDBoolean,
	reflect.Int8:    ua.DataTypeIDSByte,
	reflect.Uint8:   ua.DataTypeIDByte,
	reflect.Int16:   ua.DataTypeIDInt16,
	reflect.Uint16:  ua.DataTypeIDUInt16,
	reflect.Int32:   ua.DataTypeIDInt32,
	reflect.Uint32:  ua.DataTypeIDUInt32,
	reflect.Int64:   ua.DataTypeIDInt64,
	reflect.Uint64:  ua.DataTypeIDUInt64,
	reflect.Float32: ua.DataTypeIDFloat,
	reflect.Float64: ua.DataTypeIDDouble,
	reflect.String:  ua.DataTypeIDString,
	reflect.Int:     ua.DataTypeIDInt64,
	reflect.Uint:    ua.DataTypeIDUInt64,
}

var timeType = reflect.TypeOf(time.Time{})

func NewRuntimeOPCUAServer(settings ServerSettings) *RuntimeOPCUAServer {
	return &RuntimeOPCUAServer{
		Settings:     settings,
		nextNodeID:   1000,
		trackedNodes: map[ua.NodeID]struct{}{},
		typeRegistry: map[string]reflect.Type{},
	}
}

func (s *RuntimeOPCUAServer) logf(format string, args ...any) {
	log.Printf("opcua[%d] "+format, append([]any{s.Settings.Port}, args...)...)
}

func (s *RuntimeOPCUAServer) Start() error {
	RegisterBinaryEncodings()
	s.logf("starting server on %s:%d", s.Settings.Host, s.Settings.Port)

	keyPath := fmt.Sprintf("./pki/%d/server.key", s.Settings.Port)
	certPath := fmt.Sprintf("./pki/%d/server.crt", s.Settings.Port)
	if err := setupSecurity(keyPath, certPath, s.Settings.Host); err != nil {
		s.logf("security setup failed: key=%s cert=%s err=%v", keyPath, certPath, err)
		return err
	}

	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", s.Settings.Host, s.Settings.Port)
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI: fmt.Sprintf("urn:%s:opc-ua-centralserver:%d", s.Settings.Host, s.Settings.Port),
			ProductURI:     "urn:opc-ua-centralserver",
			ApplicationName: ua.LocalizedText{
				Text:   "opc-ua-centralserver",
				Locale: "en",
			},
			ApplicationType: ua.ApplicationTypeServer,
			DiscoveryURLs:   []string{endpointURL},
		},
		certPath,
		keyPath,
		endpointURL,
		server.WithAnonymousIdentity(true),
		server.WithSecurityPolicyNone(true),
		server.WithInsecureSkipVerify(),
		server.WithServerDiagnostics(true),
	)
	if err != nil {
		s.logf("server.New failed for endpoint %s: %v", endpointURL, err)
		return err
	}

	s.Server = srv
	s.NameSpaceMngr = srv.NamespaceManager()
	s.NameSpaceMngr.Add(runtimeNamespaceURI)

	for _, typ := range []any{
		SemVerType{},
		IdentityType{},
		BackupEnrollmentState{},
		AnalogPointType{},
		DigitalPointType{},
		StageStatusType{},
		BackendCompressorModuleType{},
	} {
		if err := s.EnsureTypeDefinition(typ); err != nil {
			s.logf("type registration failed for %T: %v", typ, err)
			return err
		}
	}

	go func() {
		if err := s.Server.ListenAndServe(); err != nil {
			s.logf("server stopped: %v", err)
		}
	}()

	s.logf("server started")
	return nil
}

func (s *RuntimeOPCUAServer) EnsureTypeDefinition(sample any) error {
	value := reflect.ValueOf(sample)
	if !value.IsValid() {
		return fmt.Errorf("invalid type sample")
	}
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			value = reflect.Zero(value.Type().Elem())
			break
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return fmt.Errorf("type definition requires struct sample, got %s", value.Type())
	}
	return s.generateTypeDefs(value)
}

func (s *RuntimeOPCUAServer) Stop() {
	if s.Server != nil {
		s.logf("stopping server")
		s.Server.Close()
	}
}

func (s *RuntimeOPCUAServer) addTrackedNode(node server.Node) error {
	if err := s.NameSpaceMngr.AddNode(node); err != nil {
		return err
	}
	if _, seen := s.trackedNodes[node.NodeID()]; !seen {
		s.trackedNodes[node.NodeID()] = struct{}{}
		s.nodeOrder = append(s.nodeOrder, node.NodeID())
	}
	return nil
}

func (s *RuntimeOPCUAServer) registerType(typ reflect.Type) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || typ == timeType {
		return
	}
	typeName := strings.ReplaceAll(typ.String(), ".", "_")
	if _, seen := s.typeRegistry[typeName]; seen {
		return
	}
	s.typeRegistry[typeName] = typ
	s.typeOrder = append(s.typeOrder, typeName)
}

func (s *RuntimeOPCUAServer) AddFolderNode(id, name, parent string) error {
	node := server.NewObjectNode(
		s.Server,
		ua.NodeIDString{NamespaceIndex: 1, ID: id},
		ua.QualifiedName{NamespaceIndex: 1, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: folderDescription(name)},
		objectRolePermissions,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.ExpandedNodeID{NodeID: ua.ParseNodeID(parent)}},
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, TargetID: ua.ExpandedNodeID{NodeID: ua.ParseNodeID("i=61")}},
		},
		0,
	)
	if err := s.addTrackedNode(node); err != nil {
		s.logf("add folder failed: id=%s name=%s parent=%s err=%v", id, name, parent, err)
		return err
	}
	s.logf("added folder: id=%s name=%s parent=%s", id, name, parent)
	return nil
}

func (s *RuntimeOPCUAServer) AddValueNode(name, parent string, initVal any) (string, error) {
	return s.addVariableNode(qualifiedChildName(parent, name), ua.ReferenceTypeIDHasComponent, ua.NodeIDString{NamespaceIndex: 1, ID: parent}, initVal)
}

func (s *RuntimeOPCUAServer) AddStructArrayNode(name, parent string, elemSample any) (string, error) {
	value := reflect.ValueOf(elemSample)
	if !value.IsValid() {
		return "", fmt.Errorf("invalid struct sample")
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return "", fmt.Errorf("struct array node requires struct sample, got %s", value.Type())
	}

	if err := s.generateTypeDefs(value); err != nil {
		return "", err
	}

	typeID := ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(value.Type().String(), ".", "_")}
	id := s.nextNodeID
	s.nextNodeID++
	nodeID := fmt.Sprintf("ns=2;i=%d", id)
	displayName := qualifiedChildName(parent, name)

	node := server.NewVariableNode(
		s.Server,
		ua.NodeIDNumeric{NamespaceIndex: 2, ID: id},
		ua.QualifiedName{NamespaceIndex: 2, Name: displayName},
		ua.LocalizedText{Text: displayName},
		ua.LocalizedText{Text: variableDescription(parent, name)},
		variableRolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasComponent,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.NodeIDString{NamespaceIndex: 1, ID: parent}},
			},
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDBaseDataVariableType},
			},
		},
		ua.NewDataValue([]ua.ExtensionObject{}, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		typeID,
		ua.ValueRankOneDimension,
		[]uint32{2},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsCurrentWrite,
		250.0,
		false,
		nil,
	)

	if err := s.addTrackedNode(node); err != nil {
		s.logf("add struct array node failed: name=%s parent=%s type=%s err=%v", displayName, parent, typeID, err)
		return "", err
	}
	s.logf("added struct array node: node=%s parent=%s type=%s rank=%d dims=%v", nodeID, parent, typeID, ua.ValueRankOneDimension, node.ArrayDimensions())
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) AddPropertyNode(name string, parent ua.NodeID, initVal any) (string, error) {
	return s.addVariableNode(name, ua.ReferenceTypeIDHasProperty, parent, initVal)
}

func (s *RuntimeOPCUAServer) addVariableNode(name string, refType ua.NodeID, parent ua.NodeID, initVal any) (string, error) {
	typeID, err := s.resolveTypeID(reflect.ValueOf(initVal))
	if err != nil {
		return "", err
	}

	id := s.nextNodeID
	s.nextNodeID++
	nodeID := fmt.Sprintf("ns=2;i=%d", id)

	node := server.NewVariableNode(
		s.Server,
		ua.NodeIDNumeric{NamespaceIndex: 2, ID: id},
		ua.QualifiedName{NamespaceIndex: 2, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: nodeDescription(name, initVal)},
		variableRolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: refType,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: parent},
			},
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDBaseDataVariableType},
			},
		},
		ua.NewDataValue(initVal, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		typeID,
		ua.ValueRankScalarOrOneDimension,
		[]uint32{},
		ua.AccessLevelsCurrentRead|ua.AccessLevelsCurrentWrite,
		250.0,
		false,
		nil,
	)

	if err := s.addTrackedNode(node); err != nil {
		s.logf("add variable node failed: name=%s parent=%s type=%s ref=%s err=%v", name, parent, typeID, refType, err)
		return "", err
	}
	s.logf("added variable node: node=%s name=%s parent=%s type=%s", nodeID, name, parent, typeID)
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) AddMethodNode(id, name string, parent ua.NodeID, handler func(*server.Session, ua.CallMethodRequest) ua.CallMethodResult) (string, error) {
	nodeID := ua.NodeIDString{NamespaceIndex: 2, ID: id}
	rolePermissions := []ua.RolePermissionType{
		{
			RoleID:      ua.ObjectIDWellKnownRoleAnonymous,
			Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeCall,
		},
		{
			RoleID:      ua.ObjectIDWellKnownRoleAuthenticatedUser,
			Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeCall,
		},
		{
			RoleID:      ua.ObjectIDWellKnownRoleOperator,
			Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeCall,
		},
		{
			RoleID:      ua.ObjectIDWellKnownRoleEngineer,
			Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeCall,
		},
		{
			RoleID:      ua.ObjectIDWellKnownRoleSupervisor,
			Permissions: ua.PermissionTypeBrowse | ua.PermissionTypeRead | ua.PermissionTypeWrite | ua.PermissionTypeCall,
		},
	}
	node := server.NewMethodNode(
		s.Server,
		nodeID,
		ua.QualifiedName{NamespaceIndex: 2, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: fmt.Sprintf("OPC UA method %s.", name)},
		rolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasComponent,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: parent},
			},
		},
		true,
	)
	node.SetCallMethodHandler(func(session *server.Session, req ua.CallMethodRequest) (result ua.CallMethodResult) {
		s.logf("method call start: id=%s input_count=%d", id, len(req.InputArguments))
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logf("method call panic: id=%s panic=%v\n%s", id, recovered, debug.Stack())
				result = ua.CallMethodResult{StatusCode: ua.BadInternalError}
				return
			}
			if result.StatusCode == ua.Good {
				s.logf("method call ok: id=%s output_count=%d", id, len(result.OutputArguments))
				return
			}
			s.logf("method call failed: id=%s status=%s input_results=%v output_count=%d", id, result.StatusCode, result.InputArgumentResults, len(result.OutputArguments))
		}()
		return handler(session, req)
	})
	if err := s.addTrackedNode(node); err != nil {
		s.logf("add method failed: id=%s name=%s parent=%s err=%v", id, name, parent, err)
		return "", err
	}
	s.logf("added method: id=%s name=%s parent=%s", id, name, parent)
	return fmt.Sprintf("ns=2;s=%s", id), nil
}

func (s *RuntimeOPCUAServer) AddMethodArgumentsNode(methodNodeID ua.NodeID, propertyName string, args []ua.Argument) (string, error) {
	id := s.nextNodeID
	s.nextNodeID++
	nodeID := fmt.Sprintf("ns=2;i=%d", id)

	node := server.NewVariableNode(
		s.Server,
		ua.NodeIDNumeric{NamespaceIndex: 2, ID: id},
		ua.QualifiedName{NamespaceIndex: 2, Name: propertyName},
		ua.LocalizedText{Text: propertyName},
		ua.LocalizedText{Text: fmt.Sprintf("Method property %s.", propertyName)},
		variableRolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: methodNodeID},
			},
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDPropertyType},
			},
		},
		ua.NewDataValue(args, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		ua.DataTypeIDArgument,
		ua.ValueRankOneDimension,
		[]uint32{uint32(len(args))},
		ua.AccessLevelsCurrentRead,
		250.0,
		false,
		nil,
	)
	if err := s.addTrackedNode(node); err != nil {
		s.logf("add method arguments failed: method=%s property=%s count=%d err=%v", methodNodeID, propertyName, len(args), err)
		return "", err
	}
	s.logf("added method arguments: method=%s property=%s count=%d", methodNodeID, propertyName, len(args))
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) SetNodeValue(nodeIDStr string, newValue any) error {
	nodeID := ua.ParseNodeID(nodeIDStr)
	if nodeID == nil {
		err := fmt.Errorf("failed to parse node id %s", nodeIDStr)
		s.logf("set value failed: node=%s err=%v", nodeIDStr, err)
		return err
	}
	node, ok := s.NameSpaceMngr.FindVariable(nodeID)
	if !ok {
		err := fmt.Errorf("failed to find node %s", nodeIDStr)
		s.logf("set value failed: node=%s err=%v", nodeIDStr, err)
		return err
	}
	node.SetValue(ua.NewDataValue(newValue, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
	s.logf("set value: node=%s type=%T", nodeIDStr, newValue)
	return nil
}

func qualifiedChildName(parent, name string) string {
	return parent + "_" + name
}

func (s *RuntimeOPCUAServer) resolveTypeID(value reflect.Value) (ua.NodeID, error) {
	if !value.IsValid() {
		return ua.DataTypeIDBaseDataType, nil
	}

	if value.Type() == timeType {
		return ua.DataTypeIDDateTime, nil
	}

	if id, ok := uaTypes[value.Kind()]; ok {
		return id, nil
	}

	if value.Kind() == reflect.Struct {
		if err := s.generateTypeDefs(value); err != nil {
			return nil, err
		}
		return ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(value.Type().String(), ".", "_")}, nil
	}

	if value.Kind() == reflect.Slice {
		elem := reflect.Zero(value.Type().Elem())
		if elem.Kind() == reflect.Struct {
			if err := s.generateTypeDefs(elem); err != nil {
				return nil, err
			}
			return ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(elem.Type().String(), ".", "_")}, nil
		}
		if id, ok := uaTypes[elem.Kind()]; ok {
			return id, nil
		}
	}

	return nil, fmt.Errorf("unsupported type %s", value.Type())
}

func (s *RuntimeOPCUAServer) generateTypeDefs(value reflect.Value) error {
	typ := value.Type()
	if typ == timeType {
		return nil
	}
	if typ.Kind() != reflect.Struct {
		return fmt.Errorf("generateTypeDefs requires struct type, got %s", typ)
	}

	typeName := strings.ReplaceAll(typ.String(), ".", "_")
	typeID := ua.NodeIDString{NamespaceIndex: 2, ID: typeName}
	if _, ok := s.NameSpaceMngr.FindNode(typeID); ok {
		return nil
	}
	s.registerType(typ)
	s.logf("generating type definition: type=%s", typ.String())

	fields := make([]ua.StructureField, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		dataType, valueRank, err := s.resolveFieldDefinition(field.Type)
		if err != nil {
			s.logf("type definition field failed: type=%s field=%s err=%v", typ.String(), field.Name, err)
			return fmt.Errorf("unsupported field %s.%s: %w", typ.String(), field.Name, err)
		}

		fields = append(fields, ua.StructureField{
			Name:      field.Name,
			DataType:  dataType,
			ValueRank: valueRank,
		})
	}

	node := server.NewDataTypeNode(
		s.Server,
		typeID,
		ua.QualifiedName{NamespaceIndex: 2, Name: typ.Name()},
		ua.LocalizedText{Text: typ.Name()},
		ua.LocalizedText{Text: fmt.Sprintf("Custom OPC UA structure type for %s.", typ.String())},
		nil,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasSubtype,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.DataTypeIDStructure},
			},
		},
		false,
		ua.StructureDefinition{
			DefaultEncodingID: ua.NodeIDString{NamespaceIndex: 2, ID: typeName + "_Enc"},
			BaseDataType:      ua.DataTypeIDStructure,
			StructureType:     ua.StructureTypeStructure,
			Fields:            fields,
		},
	)

	if _, ok := ua.FindBinaryEncodingIDForType(typ); !ok {
		ua.RegisterBinaryEncodingID(typ, ua.ExpandedNodeID{NodeID: ua.NodeIDString{NamespaceIndex: 2, ID: typeName + "_Enc"}})
		s.logf("registered binary encoding: type=%s encoding=%s", typ.String(), typeName+"_Enc")
	}

	if err := s.addTrackedNode(node); err != nil {
		s.logf("add datatype failed: type=%s err=%v", typ.String(), err)
		return err
	}
	s.logf("added datatype: type=%s node=%s", typ.String(), typeID)

	if err := s.addBinaryEncodingNode(typeName, typeID); err != nil {
		return err
	}
	return s.syncBinaryDictionary()
}

func (s *RuntimeOPCUAServer) resolveFieldDefinition(fieldType reflect.Type) (ua.NodeID, int32, error) {
	for fieldType.Kind() == reflect.Pointer {
		fieldType = fieldType.Elem()
	}

	if fieldType == timeType {
		return ua.DataTypeIDDateTime, ua.ValueRankScalar, nil
	}

	switch fieldType.Kind() {
	case reflect.Map, reflect.Interface:
		return nil, 0, fmt.Errorf("invalid datatype %s", fieldType)
	case reflect.Struct:
		if err := s.generateTypeDefs(reflect.Zero(fieldType)); err != nil {
			return nil, 0, err
		}
		return ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(fieldType.String(), ".", "_")}, ua.ValueRankScalar, nil
	case reflect.Slice:
		elem := fieldType.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem == timeType {
			return ua.DataTypeIDDateTime, ua.ValueRankOneDimension, nil
		}
		if elem.Kind() == reflect.Struct {
			if err := s.generateTypeDefs(reflect.Zero(elem)); err != nil {
				return nil, 0, err
			}
			return ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(elem.String(), ".", "_")}, ua.ValueRankOneDimension, nil
		}
		id, ok := uaTypes[elem.Kind()]
		if !ok {
			return nil, 0, fmt.Errorf("unsupported slice element type %s", elem)
		}
		return id, ua.ValueRankOneDimension, nil
	default:
		id, ok := uaTypes[fieldType.Kind()]
		if !ok {
			return nil, 0, fmt.Errorf("unsupported type %s", fieldType)
		}
		return id, ua.ValueRankScalar, nil
	}
}

func (s *RuntimeOPCUAServer) addBinaryEncodingNode(typeName string, typeID ua.NodeID) error {
	encodingID := ua.NodeIDString{NamespaceIndex: 2, ID: typeName + "_Enc"}
	if _, ok := s.NameSpaceMngr.FindNode(encodingID); ok {
		return s.ensureDictionaryDescriptionNode(typeName, typeID, encodingID)
	}

	node := server.NewObjectNode(
		s.Server,
		encodingID,
		ua.QualifiedName{NamespaceIndex: 0, Name: "Default Binary"},
		ua.LocalizedText{Text: "Default Binary"},
		ua.LocalizedText{Text: fmt.Sprintf("Default binary encoding for %s.", typeName)},
		objectRolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasEncoding,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: typeID},
			},
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.ObjectTypeIDDataTypeEncodingType},
			},
		},
		0,
	)

	if err := s.addTrackedNode(node); err != nil {
		s.logf("add binary encoding node failed: type=%s encoding=%s err=%v", typeName, encodingID, err)
		return err
	}
	s.logf("added binary encoding node: type=%s encoding=%s", typeName, encodingID)
	return s.ensureDictionaryDescriptionNode(typeName, typeID, encodingID)
}

func (s *RuntimeOPCUAServer) syncBinaryDictionary() error {
	schema, err := s.buildBinaryDictionary()
	if err != nil {
		s.logf("build binary dictionary failed: %v", err)
		return err
	}
	dictionaryNodeID := ua.NodeIDString{NamespaceIndex: 2, ID: "centralserver_OpcBinarySchema"}
	if node, ok := s.NameSpaceMngr.FindVariable(dictionaryNodeID); ok {
		node.SetValue(ua.NewDataValue(ua.ByteString(schema), 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
	} else {
		node := server.NewVariableNode(
			s.Server,
			dictionaryNodeID,
			ua.QualifiedName{NamespaceIndex: 2, Name: runtimeBinaryDictionaryName},
			ua.LocalizedText{Text: runtimeBinaryDictionaryName},
			ua.LocalizedText{Text: "Deprecated OPC Binary schema dictionary for centralserver custom datatypes."},
			variableRolePermissions,
			[]ua.Reference{
				{
					ReferenceTypeID: ua.ReferenceTypeIDHasComponent,
					IsInverse:       true,
					TargetID:        ua.ExpandedNodeID{NodeID: ua.ObjectIDOPCBinarySchemaTypeSystem},
				},
				{
					ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
					TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDDataTypeDictionaryType},
				},
			},
			ua.NewDataValue(ua.ByteString(schema), 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
			ua.DataTypeIDByteString,
			ua.ValueRankScalar,
			[]uint32{},
			ua.AccessLevelsCurrentRead,
			250.0,
			false,
			nil,
		)
		if err := s.addTrackedNode(node); err != nil {
			return err
		}
	}
	if err := s.ensureStringProperty(dictionaryNodeID, "DataTypeVersion", "1.0.0"); err != nil {
		return err
	}
	if err := s.ensureStringProperty(dictionaryNodeID, "NamespaceUri", runtimeNamespaceURI); err != nil {
		return err
	}
	for _, typeName := range s.typeOrder {
		typeID := ua.NodeIDString{NamespaceIndex: 2, ID: typeName}
		encodingID := ua.NodeIDString{NamespaceIndex: 2, ID: typeName + "_Enc"}
		if err := s.ensureDictionaryDescriptionNode(typeName, typeID, encodingID); err != nil {
			return err
		}
	}
	return nil
}

func (s *RuntimeOPCUAServer) ensureDictionaryDescriptionNode(typeName string, typeID, encodingID ua.NodeID) error {
	descriptionNodeID := ua.NodeIDString{NamespaceIndex: 2, ID: typeName + "_Desc"}
	if node, ok := s.NameSpaceMngr.FindVariable(descriptionNodeID); ok {
		node.SetValue(ua.NewDataValue(typeName, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
	} else {
		node := server.NewVariableNode(
			s.Server,
			descriptionNodeID,
			ua.QualifiedName{NamespaceIndex: 2, Name: typeName},
			ua.LocalizedText{Text: typeName},
			ua.LocalizedText{Text: fmt.Sprintf("Deprecated binary schema description entry for %s.", typeName)},
			variableRolePermissions,
			[]ua.Reference{
				{
					ReferenceTypeID: ua.ReferenceTypeIDHasComponent,
					IsInverse:       true,
					TargetID:        ua.ExpandedNodeID{NodeID: ua.NodeIDString{NamespaceIndex: 2, ID: "centralserver_OpcBinarySchema"}},
				},
				{
					ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
					TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDDataTypeDescriptionType},
				},
			},
			ua.NewDataValue(typeName, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
			ua.DataTypeIDString,
			ua.ValueRankScalar,
			[]uint32{},
			ua.AccessLevelsCurrentRead,
			250.0,
			false,
			nil,
		)
		if err := s.addTrackedNode(node); err != nil {
			return err
		}
	}
	if err := s.ensureStringProperty(descriptionNodeID, "DataTypeVersion", "1.0.0"); err != nil {
		return err
	}
	fragment, err := s.buildBinaryDictionaryFragment(s.typeRegistry[typeName])
	if err != nil {
		return err
	}
	if err := s.ensureByteStringProperty(descriptionNodeID, "DictionaryFragment", fragment); err != nil {
		return err
	}
	if encodingNode, ok := s.NameSpaceMngr.FindNode(encodingID); ok && !hasForwardReference(encodingNode.References(), ua.ReferenceTypeIDHasDescription, descriptionNodeID) {
		encodingNode.SetReferences(append(encodingNode.References(), ua.Reference{
			ReferenceTypeID: ua.ReferenceTypeIDHasDescription,
			TargetID:        ua.ExpandedNodeID{NodeID: descriptionNodeID},
		}))
	}
	if dataTypeNode, ok := s.NameSpaceMngr.FindNode(typeID); ok && !hasForwardReference(dataTypeNode.References(), ua.ReferenceTypeIDHasDescription, descriptionNodeID) {
		dataTypeNode.SetReferences(append(dataTypeNode.References(), ua.Reference{
			ReferenceTypeID: ua.ReferenceTypeIDHasDescription,
			TargetID:        ua.ExpandedNodeID{NodeID: descriptionNodeID},
		}))
	}
	return nil
}

func hasForwardReference(refs []ua.Reference, refType ua.NodeID, target ua.NodeID) bool {
	for _, ref := range refs {
		if !ref.IsInverse && ref.ReferenceTypeID == refType && ua.ToNodeID(ref.TargetID, []string{"http://opcfoundation.org/UA/", runtimeNamespaceURI}) == target {
			return true
		}
		if !ref.IsInverse && ref.ReferenceTypeID == refType && ref.TargetID.NodeID == target {
			return true
		}
	}
	return false
}

func (s *RuntimeOPCUAServer) ensureStringProperty(parent ua.NodeID, name, value string) error {
	propertyNodeID := ua.NodeIDString{NamespaceIndex: 2, ID: fmt.Sprintf("%s_%s", sanitizeNodeID(parent), name)}
	if node, ok := s.NameSpaceMngr.FindVariable(propertyNodeID); ok {
		node.SetValue(ua.NewDataValue(value, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
		return nil
	}
	node := server.NewVariableNode(
		s.Server,
		propertyNodeID,
		ua.QualifiedName{NamespaceIndex: 2, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: fmt.Sprintf("Property %s.", name)},
		variableRolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: parent},
			},
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDPropertyType},
			},
		},
		ua.NewDataValue(value, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		ua.DataTypeIDString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		250.0,
		false,
		nil,
	)
	return s.addTrackedNode(node)
}

func (s *RuntimeOPCUAServer) ensureByteStringProperty(parent ua.NodeID, name string, value []byte) error {
	propertyNodeID := ua.NodeIDString{NamespaceIndex: 2, ID: fmt.Sprintf("%s_%s", sanitizeNodeID(parent), name)}
	byteValue := ua.ByteString(value)
	if node, ok := s.NameSpaceMngr.FindVariable(propertyNodeID); ok {
		node.SetValue(ua.NewDataValue(byteValue, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
		return nil
	}
	node := server.NewVariableNode(
		s.Server,
		propertyNodeID,
		ua.QualifiedName{NamespaceIndex: 2, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: fmt.Sprintf("Property %s.", name)},
		variableRolePermissions,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasProperty,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: parent},
			},
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition,
				TargetID:        ua.ExpandedNodeID{NodeID: ua.VariableTypeIDPropertyType},
			},
		},
		ua.NewDataValue(byteValue, 0, time.Now().UTC(), 0, time.Now().UTC(), 0),
		ua.DataTypeIDByteString,
		ua.ValueRankScalar,
		[]uint32{},
		ua.AccessLevelsCurrentRead,
		250.0,
		false,
		nil,
	)
	return s.addTrackedNode(node)
}

type binaryTypeDictionary struct {
	XMLName          xml.Name                 `xml:"opc:TypeDictionary"`
	XmlnsOpc         string                   `xml:"xmlns:opc,attr"`
	XmlnsXsi         string                   `xml:"xmlns:xsi,attr"`
	XmlnsUA          string                   `xml:"xmlns:ua,attr"`
	XmlnsTns         string                   `xml:"xmlns:tns,attr"`
	TargetNamespace  string                   `xml:"TargetNamespace,attr"`
	DefaultByteOrder string                   `xml:"DefaultByteOrder,attr"`
	Documentation    string                   `xml:"opc:Documentation,omitempty"`
	Imports          []binaryDictionaryImport `xml:"opc:Import,omitempty"`
	StructuredTypes  []binaryStructuredType   `xml:"opc:StructuredType"`
}

type binaryDictionaryImport struct {
	Namespace string `xml:"Namespace,attr"`
}

type binaryStructuredType struct {
	Name     string                  `xml:"Name,attr"`
	BaseType string                  `xml:"BaseType,attr"`
	Fields   []binaryStructuredField `xml:"opc:Field"`
}

type binaryStructuredField struct {
	Name        string `xml:"Name,attr"`
	TypeName    string `xml:"TypeName,attr"`
	LengthField string `xml:"LengthField,attr,omitempty"`
}

func (s *RuntimeOPCUAServer) buildBinaryDictionary() ([]byte, error) {
	dict := binaryTypeDictionary{
		XmlnsOpc:         "http://opcfoundation.org/BinarySchema/",
		XmlnsXsi:         "http://www.w3.org/2001/XMLSchema-instance",
		XmlnsUA:          "http://opcfoundation.org/UA/",
		XmlnsTns:         runtimeNamespaceURI,
		TargetNamespace:  runtimeNamespaceURI,
		DefaultByteOrder: "LittleEndian",
		Documentation:    "Generated OPC Binary dictionary for centralserver runtime datatypes.",
		Imports: []binaryDictionaryImport{
			{Namespace: "http://opcfoundation.org/BinarySchema/"},
		},
	}
	for _, typeName := range s.typeOrder {
		typ := s.typeRegistry[typeName]
		fields, err := s.buildBinaryDictionaryFields(typ)
		if err != nil {
			return nil, fmt.Errorf("dictionary type %s: %w", typeName, err)
		}
		dict.StructuredTypes = append(dict.StructuredTypes, binaryStructuredType{
			Name:     typeName,
			BaseType: "ua:ExtensionObject",
			Fields:   fields,
		})
	}
	buf, err := xml.MarshalIndent(dict, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), buf...), nil
}

func (s *RuntimeOPCUAServer) buildBinaryDictionaryFields(typ reflect.Type) ([]binaryStructuredField, error) {
	fields := make([]binaryStructuredField, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldType := field.Type
		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		if fieldType == timeType {
			fields = append(fields, binaryStructuredField{Name: field.Name, TypeName: "opc:DateTime"})
			continue
		}
		switch fieldType.Kind() {
		case reflect.Struct:
			s.registerType(fieldType)
			fields = append(fields, binaryStructuredField{Name: field.Name, TypeName: "tns:" + strings.ReplaceAll(fieldType.String(), ".", "_")})
		case reflect.Slice:
			elem := fieldType.Elem()
			for elem.Kind() == reflect.Pointer {
				elem = elem.Elem()
			}
			lengthField := "NoOf" + field.Name
			fields = append(fields, binaryStructuredField{Name: lengthField, TypeName: "opc:Int32"})
			typeName, err := binarySchemaTypeName(elem)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", field.Name, err)
			}
			if elem.Kind() == reflect.Struct {
				s.registerType(elem)
			}
			fields = append(fields, binaryStructuredField{Name: field.Name, TypeName: typeName, LengthField: lengthField})
		default:
			typeName, err := binarySchemaTypeName(fieldType)
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", field.Name, err)
			}
			fields = append(fields, binaryStructuredField{Name: field.Name, TypeName: typeName})
		}
	}
	return fields, nil
}

func (s *RuntimeOPCUAServer) buildBinaryDictionaryFragment(typ reflect.Type) ([]byte, error) {
	fields, err := s.buildBinaryDictionaryFields(typ)
	if err != nil {
		return nil, err
	}
	fragment := struct {
		XMLName  xml.Name                `xml:"opc:StructuredType"`
		XmlnsOpc string                  `xml:"xmlns:opc,attr"`
		XmlnsUA  string                  `xml:"xmlns:ua,attr"`
		XmlnsTns string                  `xml:"xmlns:tns,attr"`
		Name     string                  `xml:"Name,attr"`
		BaseType string                  `xml:"BaseType,attr"`
		Fields   []binaryStructuredField `xml:"opc:Field"`
	}{
		XmlnsOpc: "http://opcfoundation.org/BinarySchema/",
		XmlnsUA:  "http://opcfoundation.org/UA/",
		XmlnsTns: runtimeNamespaceURI,
		Name:     strings.ReplaceAll(typ.String(), ".", "_"),
		BaseType: "ua:ExtensionObject",
		Fields:   fields,
	}
	return xml.Marshal(fragment)
}

func binarySchemaTypeName(fieldType reflect.Type) (string, error) {
	switch fieldType.Kind() {
	case reflect.Bool:
		return "opc:Boolean", nil
	case reflect.Int8:
		return "opc:SByte", nil
	case reflect.Uint8:
		return "opc:Byte", nil
	case reflect.Int16:
		return "opc:Int16", nil
	case reflect.Uint16:
		return "opc:UInt16", nil
	case reflect.Int32, reflect.Int:
		return "opc:Int32", nil
	case reflect.Uint32:
		return "opc:UInt32", nil
	case reflect.Int64:
		return "opc:Int64", nil
	case reflect.Uint64, reflect.Uint:
		return "opc:UInt64", nil
	case reflect.Float32:
		return "opc:Float", nil
	case reflect.Float64:
		return "opc:Double", nil
	case reflect.String:
		return "opc:String", nil
	case reflect.Struct:
		if fieldType == timeType {
			return "opc:DateTime", nil
		}
		return "tns:" + strings.ReplaceAll(fieldType.String(), ".", "_"), nil
	default:
		return "", fmt.Errorf("unsupported schema type %s", fieldType)
	}
}

func sanitizeNodeID(id ua.NodeID) string {
	replacer := strings.NewReplacer("=", "_", ";", "_", ":", "_", ",", "_")
	return replacer.Replace(nodeIDString(id))
}

func folderDescription(name string) string {
	return fmt.Sprintf("Folder node for %s.", name)
}

func variableDescription(parent, name string) string {
	return fmt.Sprintf("Published variable %s under %s.", name, parent)
}

func nodeDescription(name string, value any) string {
	if value == nil {
		return fmt.Sprintf("Published variable %s.", name)
	}
	return fmt.Sprintf("Published variable %s of type %T.", name, value)
}

func setupSecurity(keyPath, certPath, hostIP string) error {
	for _, file := range []string{keyPath, certPath} {
		path := pathpkg.Dir(file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		}
	}

	if _, err := os.Stat(keyPath); err != nil {
		if err := generatePrivateKey(keyPath); err != nil {
			return err
		}
		return generateSelfSignedCertificate(keyPath, certPath, hostIP)
	}
	if _, err := os.Stat(certPath); err != nil {
		return generateSelfSignedCertificate(keyPath, certPath, hostIP)
	}
	return nil
}

func generatePrivateKey(filename string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	return pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

func generateSelfSignedCertificate(privateKeyFilename, certFilename, hostIP string) error {
	keyPEMBlock, err := os.ReadFile(privateKeyFilename)
	if err != nil {
		return err
	}
	keyDERBlock, _ := pem.Decode(keyPEMBlock)
	if keyDERBlock == nil {
		return errors.New("failed to decode PEM block containing private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return err
	}

	applicationURI, _ := url.Parse(fmt.Sprintf("urn:%s:opc-ua-centralserver", hostIP))
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	subjectKeyHash := sha3.New224()
	subjectKeyHash.Write(privateKey.PublicKey.N.Bytes())
	subjectKeyID := subjectKeyHash.Sum(nil)
	oidDC := asn1.ObjectIdentifier([]int{0, 9, 2342, 19200300, 100, 1, 25})

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "opc-ua-centralserver", ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidDC, Value: hostIP}}},
		SubjectKeyId:          subjectKeyID,
		AuthorityKeyId:        subjectKeyID,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageCertSign | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostIP},
		IPAddresses:           []net.IP{net.ParseIP(hostIP)},
		URIs:                  []*url.URL{applicationURI},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certFilename)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}
