package centralserver

import (
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

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
		if !s.isTypeMetadataReady(typeName) {
			continue
		}
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
	if err := s.ensureReferencePair(encodingID, ua.ReferenceTypeIDHasDescription, descriptionNodeID); err != nil {
		return err
	}
	if err := s.ensureReferencePair(typeID, ua.ReferenceTypeIDHasDescription, descriptionNodeID); err != nil {
		return err
	}
	return nil
}

func (s *RuntimeOPCUAServer) ensureReferencePair(sourceID, refType, targetID ua.NodeID) error {
	sourceNode, ok := s.NameSpaceMngr.FindNode(sourceID)
	if !ok {
		return fmt.Errorf("failed to find source node %s for reference %s", sourceID, refType)
	}
	targetNode, ok := s.NameSpaceMngr.FindNode(targetID)
	if !ok {
		return fmt.Errorf("failed to find target node %s for reference %s", targetID, refType)
	}
	if !hasForwardReference(sourceNode.References(), refType, targetID) {
		sourceNode.SetReferences(append(sourceNode.References(), ua.Reference{
			ReferenceTypeID: refType,
			TargetID:        ua.ExpandedNodeID{NodeID: targetID},
		}))
	}
	if !hasInverseReference(targetNode.References(), refType, sourceID) {
		targetNode.SetReferences(append(targetNode.References(), ua.Reference{
			ReferenceTypeID: refType,
			IsInverse:       true,
			TargetID:        ua.ExpandedNodeID{NodeID: sourceID},
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

func hasInverseReference(refs []ua.Reference, refType ua.NodeID, target ua.NodeID) bool {
	for _, ref := range refs {
		if ref.IsInverse && ref.ReferenceTypeID == refType && ua.ToNodeID(ref.TargetID, []string{"http://opcfoundation.org/UA/", runtimeNamespaceURI}) == target {
			return true
		}
		if ref.IsInverse && ref.ReferenceTypeID == refType && ref.TargetID.NodeID == target {
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
		if !s.isTypeMetadataReady(typeName) {
			continue
		}
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

func (s *RuntimeOPCUAServer) isTypeMetadataReady(typeName string) bool {
	if _, ok := s.typeRegistry[typeName]; !ok {
		return false
	}
	if _, ok := s.NameSpaceMngr.FindNode(ua.NodeIDString{NamespaceIndex: 2, ID: typeName}); !ok {
		return false
	}
	if _, ok := s.NameSpaceMngr.FindNode(ua.NodeIDString{NamespaceIndex: 2, ID: typeName + "_Enc"}); !ok {
		return false
	}
	return true
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
