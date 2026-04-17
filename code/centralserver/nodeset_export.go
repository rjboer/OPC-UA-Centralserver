package centralserver

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
)

func (s *RuntimeOPCUAServer) ExportNodeSetXML() ([]byte, error) {
	nodeset := ua.UANodeSet{
		NamespaceUris: s.NameSpaceMngr.NamespaceUris(),
		LastModified:  time.Now().UTC(),
	}
	nodeIDs := append([]ua.NodeID(nil), s.nodeOrder...)
	sort.SliceStable(nodeIDs, func(i, j int) bool {
		return nodeIDString(nodeIDs[i]) < nodeIDString(nodeIDs[j])
	})
	for _, nodeID := range nodeIDs {
		node, ok := s.NameSpaceMngr.FindNode(nodeID)
		if !ok {
			continue
		}
		uaNode, err := exportNode(node, s.NameSpaceMngr.NamespaceUris())
		if err != nil {
			return nil, err
		}
		nodeset.Nodes = append(nodeset.Nodes, uaNode)
	}
	buf, err := xml.MarshalIndent(nodeset, "", "    ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), buf...), nil
}

func exportNode(node server.Node, namespaceURIs []string) (ua.UANode, error) {
	n := ua.UANode{
		NodeID:      nodeIDString(node.NodeID()),
		BrowseName:  exportBrowseName(node.BrowseName()),
		DisplayName: exportLocalizedText(node.DisplayName()),
		Description: exportLocalizedText(node.Description()),
		References:  exportReferences(node.References()),
	}
	switch typed := node.(type) {
	case *server.ObjectNode:
		n.XMLName = xml.Name{Local: "UAObject"}
		n.EventNotifier = typed.EventNotifier()
	case *server.VariableNode:
		n.XMLName = xml.Name{Local: "UAVariable"}
		n.DataType = nodeIDString(typed.DataType())
		n.ValueRank = strconv.Itoa(int(typed.ValueRank()))
		n.ArrayDimensions = exportArrayDimensions(typed.ArrayDimensions())
		n.AccessLevel = strconv.Itoa(int(typed.AccessLevel()))
		n.UserAccessLevel = strconv.Itoa(int(typed.UserAccessLevel(ua.AnonymousIdentity{})))
		n.MinimumSamplingInterval = typed.MinimumSamplingInterval()
		n.Historizing = typed.Historizing()
		n.Value = exportVariant(typed.Value().Value, namespaceURIs)
	case *server.VariableTypeNode:
		n.XMLName = xml.Name{Local: "UAVariableType"}
		n.DataType = nodeIDString(typed.DataType())
		n.ValueRank = strconv.Itoa(int(typed.ValueRank()))
		n.ArrayDimensions = exportArrayDimensions(typed.ArrayDimensions())
		n.IsAbstract = typed.IsAbstract()
		n.Value = exportVariant(typed.Value().Value, namespaceURIs)
	case *server.MethodNode:
		n.XMLName = xml.Name{Local: "UAMethod"}
		n.Executable = strconv.FormatBool(typed.Executable())
		n.UserExecutable = strconv.FormatBool(typed.UserExecutable(ua.AnonymousIdentity{}))
	case *server.DataTypeNode:
		n.XMLName = xml.Name{Local: "UADataType"}
		n.IsAbstract = typed.IsAbstract()
		if def, ok := typed.DataTypeDefinition().(ua.StructureDefinition); ok {
			n.Definition = exportStructureDefinition(node.BrowseName().Name, def)
		}
	default:
		return ua.UANode{}, fmt.Errorf("unsupported node export type %T", node)
	}
	return n, nil
}

func exportBrowseName(name ua.QualifiedName) string {
	return fmt.Sprintf("%d:%s", name.NamespaceIndex, name.Name)
}

func exportLocalizedText(text ua.LocalizedText) ua.UALocalizedText {
	return ua.UALocalizedText{Text: text.Text, Locale: text.Locale}
}

func exportReferences(refs []ua.Reference) []*ua.UAReference {
	out := make([]*ua.UAReference, 0, len(refs))
	for _, ref := range refs {
		item := &ua.UAReference{
			ReferenceType: nodeIDString(ref.ReferenceTypeID),
			TargetNodeID:  ref.TargetID.String(),
		}
		if ref.IsInverse {
			item.IsForward = "false"
		}
		out = append(out, item)
	}
	return out
}

func exportArrayDimensions(dims []uint32) string {
	if len(dims) == 0 {
		return ""
	}
	parts := make([]string, len(dims))
	for i, dim := range dims {
		parts[i] = strconv.FormatUint(uint64(dim), 10)
	}
	return strings.Join(parts, ",")
}

func exportStructureDefinition(name string, def ua.StructureDefinition) *ua.UADataTypeDefinition {
	fields := make([]ua.UADataTypeField, 0, len(def.Fields))
	for _, field := range def.Fields {
		fields = append(fields, ua.UADataTypeField{
			Name:      field.Name,
			DataType:  nodeIDString(field.DataType),
			ValueRank: int(field.ValueRank),
		})
	}
	return &ua.UADataTypeDefinition{
		Name:     name,
		BaseType: nodeIDString(def.BaseDataType),
		Field:    fields,
	}
}

func exportVariant(value any, namespaceURIs []string) ua.UAVariant {
	var variant ua.UAVariant
	switch v := value.(type) {
	case nil:
		return variant
	case bool:
		variant.Bool = &v
	case uint8:
		variant.Byte = &v
	case uint16:
		variant.UInt16 = &v
	case uint32:
		variant.UInt32 = &v
	case uint64:
		variant.UInt64 = &v
	case int8:
		variant.SByte = &v
	case int16:
		variant.Int16 = &v
	case int32:
		variant.Int32 = &v
	case int64:
		variant.Int64 = &v
	case float32:
		variant.Float = &v
	case float64:
		variant.Double = &v
	case string:
		variant.String = &v
	case ua.ByteString:
		variant.ByteString = &v
	case time.Time:
		variant.DateTime = &v
	case []ua.Argument:
		items := make([]ua.UAExtensionObject, 0, len(v))
		for _, arg := range v {
			items = append(items, ua.UAExtensionObject{
				TypeID: "i=297",
				Argument: &ua.UAArgument{
					Name:            arg.Name,
					DataType:        nodeIDString(arg.DataType),
					ValueRank:       strconv.Itoa(int(arg.ValueRank)),
					ArrayDimensions: exportArrayDimensions(arg.ArrayDimensions),
					Description:     exportLocalizedText(arg.Description),
				},
			})
		}
		variant.ListOfExtensionObject = &ua.ListOfExtensionObject{List: items}
	case []string:
		variant.ListOfString = &ua.ListOfString{List: v}
	case []int32:
		variant.ListOfInt32 = &ua.ListOfInt32{List: v}
	case []uint32:
		variant.ListOfUInt32 = &ua.ListOfUInt32{List: v}
	case []bool:
		variant.ListOfBoolean = &ua.ListOfBoolean{List: v}
	case ua.NodeID:
		id := nodeIDString(v)
		variant.NodeID = &ua.UANodeID{Identifier: id}
	case ua.ExpandedNodeID:
		id := v.String()
		variant.ExpandedNodeID = &ua.UAExpandedNodeID{Identifier: id}
	default:
		_ = namespaceURIs
	}
	return variant
}

func nodeIDString(id ua.NodeID) string {
	switch v := id.(type) {
	case nil:
		return ""
	case ua.NodeIDNumeric:
		return v.String()
	case ua.NodeIDString:
		return v.String()
	case ua.NodeIDGUID:
		return v.String()
	case ua.NodeIDOpaque:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}
