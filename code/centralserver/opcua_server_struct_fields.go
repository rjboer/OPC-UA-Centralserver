package centralserver

import (
	"fmt"
	"reflect"
	"time"

	"github.com/awcullen/opcua/ua"
)

func (s *RuntimeOPCUAServer) bindStructChildren(nodeID string, parent ua.NodeID, initVal any) (structBinding, bool, error) {
	value, ok := normalizedStructValue(initVal)
	if !ok {
		return structBinding{}, false, nil
	}

	binding := structBinding{fields: make([]structFieldBinding, 0, value.NumField())}
	for i := 0; i < value.NumField(); i++ {
		field := value.Type().Field(i)
		childNodeID, err := s.addVariableNode(field.Name, ua.ReferenceTypeIDHasComponent, parent, value.Field(i).Interface(), ua.VariableTypeIDBaseDataVariableType)
		if err != nil {
			return structBinding{}, false, err
		}
		binding.fields = append(binding.fields, structFieldBinding{
			index:  i,
			nodeID: childNodeID,
		})
	}
	return binding, true, nil
}

func (s *RuntimeOPCUAServer) updateStructChildren(binding structBinding, newValue any) error {
	value, ok := normalizedStructValue(newValue)
	if !ok {
		return nil
	}
	for _, field := range binding.fields {
		if err := s.SetNodeValue(field.nodeID, value.Field(field.index).Interface()); err != nil {
			return err
		}
	}
	return nil
}

func normalizedStructValue(v any) (reflect.Value, bool) {
	value := reflect.ValueOf(v)
	if !value.IsValid() {
		return reflect.Value{}, false
	}
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			value = reflect.Zero(value.Type().Elem())
			break
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct || value.Type() == reflect.TypeOf(time.Time{}) {
		return reflect.Value{}, false
	}
	return value, true
}

func (s *RuntimeOPCUAServer) prepareStructArrayValue(elemType reflect.Type, newValue any) (any, reflect.Value, error) {
	value := reflect.ValueOf(newValue)
	if !value.IsValid() {
		return []ua.ExtensionObject{}, reflect.MakeSlice(reflect.SliceOf(elemType), 0, 0), nil
	}
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return []ua.ExtensionObject{}, reflect.MakeSlice(reflect.SliceOf(elemType), 0, 0), nil
		}
		value = value.Elem()
	}
	if value.Kind() == reflect.Slice && value.Type().Elem() == elemType {
		return toExtensionObjectSlice(value), value, nil
	}
	if _, ok := newValue.([]ua.ExtensionObject); ok {
		return newValue, reflect.Value{}, nil
	}
	return nil, reflect.Value{}, fmt.Errorf("struct array node requires []%s, got %T", elemType, newValue)
}

func (s *RuntimeOPCUAServer) updateStructArrayChildren(parent ua.NodeID, binding structArrayBinding, items reflect.Value) (structArrayBinding, error) {
	for len(binding.items) > items.Len() {
		last := binding.items[len(binding.items)-1]
		node, ok := s.NameSpaceMngr.FindNode(ua.ParseNodeID(last.nodeID))
		if ok {
			if err := s.NameSpaceMngr.DeleteNode(node, true); err != nil {
				return binding, err
			}
		}
		delete(s.structNodes, last.nodeID)
		binding.items = binding.items[:len(binding.items)-1]
	}

	for len(binding.items) < items.Len() {
		index := len(binding.items)
		childNodeID, err := s.addVariableNode(fmt.Sprintf("[%d]", index), ua.ReferenceTypeIDHasComponent, parent, items.Index(index).Interface(), ua.VariableTypeIDBaseDataVariableType)
		if err != nil {
			return binding, err
		}
		binding.items = append(binding.items, structArrayItemBinding{nodeID: childNodeID})
	}

	for i, item := range binding.items {
		if err := s.SetNodeValue(item.nodeID, items.Index(i).Interface()); err != nil {
			return binding, err
		}
	}
	return binding, nil
}

func toExtensionObjectSlice(items reflect.Value) []ua.ExtensionObject {
	if !items.IsValid() || items.Len() == 0 {
		return []ua.ExtensionObject{}
	}
	result := make([]ua.ExtensionObject, 0, items.Len())
	for i := 0; i < items.Len(); i++ {
		result = append(result, ua.ExtensionObject(items.Index(i).Interface()))
	}
	return result
}
