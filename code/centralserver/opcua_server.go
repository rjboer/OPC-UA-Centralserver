package centralserver

import (
	"fmt"
	"log"
	"reflect"
	"runtime/debug"
	"strings"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
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
	structNodes   map[string]structBinding
	structArrays  map[string]structArrayBinding
}

type structBinding struct {
	fields []structFieldBinding
}

type structFieldBinding struct {
	index  int
	nodeID string
}

type structArrayBinding struct {
	elemType reflect.Type
	items    []structArrayItemBinding
}

type structArrayItemBinding struct {
	nodeID string
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
		structNodes:  map[string]structBinding{},
		structArrays: map[string]structArrayBinding{},
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
	return s.addObjectNode(ua.NodeIDString{NamespaceIndex: 1, ID: id}, ua.QualifiedName{NamespaceIndex: 1, Name: name}, ua.LocalizedText{Text: name}, ua.LocalizedText{Text: folderDescription(name)}, ua.ReferenceTypeIDOrganizes, ua.ParseNodeID(parent))
}

func (s *RuntimeOPCUAServer) addObjectNode(nodeID ua.NodeID, browseName ua.QualifiedName, displayName ua.LocalizedText, description ua.LocalizedText, refType ua.NodeID, parent ua.NodeID) error {
	node := server.NewObjectNode(
		s.Server,
		nodeID,
		browseName,
		displayName,
		description,
		objectRolePermissions,
		[]ua.Reference{
			{ReferenceTypeID: refType, IsInverse: true, TargetID: ua.ExpandedNodeID{NodeID: parent}},
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, TargetID: ua.ExpandedNodeID{NodeID: ua.ObjectTypeIDBaseObjectType}},
		},
		0,
	)
	if err := s.addTrackedNode(node); err != nil {
		s.logf("add object failed: id=%s name=%s parent=%s err=%v", nodeID, browseName.Name, parent, err)
		return err
	}
	s.logf("added object: id=%s name=%s parent=%s", nodeID, browseName.Name, parent)
	return nil
}

func (s *RuntimeOPCUAServer) AddValueNode(name, parent string, initVal any) (string, error) {
	return s.addVariableNode(qualifiedChildName(parent, name), ua.ReferenceTypeIDHasComponent, ua.NodeIDString{NamespaceIndex: 1, ID: parent}, initVal, ua.VariableTypeIDBaseDataVariableType)
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
	s.structArrays[nodeID] = structArrayBinding{elemType: value.Type()}
	s.logf("added struct array node: node=%s parent=%s type=%s rank=%d dims=%v", nodeID, parent, typeID, ua.ValueRankOneDimension, node.ArrayDimensions())
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) AddPropertyNode(name string, parent ua.NodeID, initVal any) (string, error) {
	return s.addVariableNode(name, ua.ReferenceTypeIDHasProperty, parent, initVal, ua.VariableTypeIDPropertyType)
}

func (s *RuntimeOPCUAServer) addVariableNode(name string, refType ua.NodeID, parent ua.NodeID, initVal any, typeDefinition ua.NodeID) (string, error) {
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
				TargetID:        ua.ExpandedNodeID{NodeID: typeDefinition},
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
		s.logf("add variable node failed: name=%s parent=%s type=%s ref=%s typedef=%s err=%v", name, parent, typeID, refType, typeDefinition, err)
		return "", err
	}
	if binding, ok, err := s.bindStructChildren(nodeID, node.NodeID(), initVal); err != nil {
		return "", err
	} else if ok {
		s.structNodes[nodeID] = binding
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
	if err := s.addMethodArgumentChildren(node.NodeID(), propertyName, args); err != nil {
		s.logf("add method arguments children failed: method=%s property=%s count=%d err=%v", methodNodeID, propertyName, len(args), err)
		return "", err
	}
	s.logf("added method arguments: method=%s property=%s count=%d", methodNodeID, propertyName, len(args))
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) addMethodArgumentChildren(parent ua.NodeID, propertyName string, args []ua.Argument) error {
	for i, arg := range args {
		argNodeID, err := s.AddPropertyNode(fmt.Sprintf("[%d]", i), parent, arg.Name)
		if err != nil {
			return err
		}
		argNode := ua.ParseNodeID(argNodeID)
		if _, err := s.AddPropertyNode("Name", argNode, arg.Name); err != nil {
			return err
		}
		if _, err := s.AddPropertyNode("DataType", argNode, fmt.Sprintf("%v", arg.DataType)); err != nil {
			return err
		}
		if _, err := s.AddPropertyNode("ValueRank", argNode, arg.ValueRank); err != nil {
			return err
		}
		if _, err := s.AddPropertyNode("ArrayDimensions", argNode, arg.ArrayDimensions); err != nil {
			return err
		}
		if _, err := s.AddPropertyNode("DescriptionText", argNode, arg.Description.Text); err != nil {
			return err
		}
		if _, err := s.AddPropertyNode("DescriptionLocale", argNode, arg.Description.Locale); err != nil {
			return err
		}
	}
	return nil
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
	if binding, ok := s.structArrays[nodeIDStr]; ok {
		encodedValue, normalized, err := s.prepareStructArrayValue(binding.elemType, newValue)
		if err != nil {
			return err
		}
		node.SetValue(ua.NewDataValue(encodedValue, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
		if normalized.IsValid() {
			updatedBinding, updateErr := s.updateStructArrayChildren(nodeID, binding, normalized)
			if updateErr != nil {
				return updateErr
			}
			s.structArrays[nodeIDStr] = updatedBinding
		}
		s.logf("set value: node=%s type=%T", nodeIDStr, newValue)
		return nil
	}
	node.SetValue(ua.NewDataValue(newValue, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
	if binding, ok := s.structNodes[nodeIDStr]; ok {
		if err := s.updateStructChildren(binding, newValue); err != nil {
			return err
		}
	}
	s.logf("set value: node=%s type=%T", nodeIDStr, newValue)
	return nil
}

func qualifiedChildName(parent, name string) string {
	return parent + "_" + name
}

func structDataTypeNodeID(typ reflect.Type) ua.NodeID {
	return ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(typ.String(), ".", "_")}
}

func structVariableTypeNodeID(typ reflect.Type) ua.NodeID {
	return ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(typ.String(), ".", "_") + "Type"}
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
		s.registerType(typ)
		if err := s.addBinaryEncodingNode(typeName, typeID); err != nil {
			return err
		}
		return s.syncBinaryDictionary()
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
