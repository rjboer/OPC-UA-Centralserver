package centralserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	pathpkg "path"
	"reflect"
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

func NewRuntimeOPCUAServer(settings ServerSettings) *RuntimeOPCUAServer {
	return &RuntimeOPCUAServer{
		Settings:   settings,
		nextNodeID: 1000,
	}
}

func (s *RuntimeOPCUAServer) Start() error {
	keyPath := fmt.Sprintf("./pki/%d/server.key", s.Settings.Port)
	certPath := fmt.Sprintf("./pki/%d/server.crt", s.Settings.Port)
	if err := setupSecurity(keyPath, certPath, s.Settings.Host); err != nil {
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
		return err
	}

	s.Server = srv
	s.NameSpaceMngr = srv.NamespaceManager()

	go func() {
		if err := s.Server.ListenAndServe(); err != nil {
			log.Printf("opc ua server stopped on port %d: %v", s.Settings.Port, err)
		}
	}()

	return nil
}

func (s *RuntimeOPCUAServer) Stop() {
	if s.Server != nil {
		s.Server.Close()
	}
}

func (s *RuntimeOPCUAServer) AddFolderNode(id, name, parent string) error {
	node := server.NewObjectNode(
		s.Server,
		ua.NodeIDString{NamespaceIndex: 1, ID: id},
		ua.QualifiedName{NamespaceIndex: 1, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: ""},
		nil,
		[]ua.Reference{
			{ReferenceTypeID: ua.ReferenceTypeIDOrganizes, IsInverse: true, TargetID: ua.ExpandedNodeID{NodeID: ua.ParseNodeID(parent)}},
			{ReferenceTypeID: ua.ReferenceTypeIDHasTypeDefinition, TargetID: ua.ExpandedNodeID{NodeID: ua.ParseNodeID("i=61")}},
		},
		0,
	)
	return s.NameSpaceMngr.AddNode(node)
}

func (s *RuntimeOPCUAServer) AddValueNode(name, parent string, initVal any) (string, error) {
	return s.addVariableNode(name, ua.ReferenceTypeIDOrganizes, ua.NodeIDString{NamespaceIndex: 1, ID: parent}, initVal)
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
		ua.LocalizedText{Text: ""},
		nil,
		[]ua.Reference{
			{
				ReferenceTypeID: refType,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: parent},
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

	if err := s.NameSpaceMngr.AddNode(node); err != nil {
		return "", err
	}
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) AddMethodNode(id, name string, parent ua.NodeID, handler func(*server.Session, ua.CallMethodRequest) ua.CallMethodResult) (string, error) {
	nodeID := ua.NodeIDString{NamespaceIndex: 2, ID: id}
	node := server.NewMethodNode(
		s.Server,
		nodeID,
		ua.QualifiedName{NamespaceIndex: 2, Name: name},
		ua.LocalizedText{Text: name},
		ua.LocalizedText{Text: ""},
		nil,
		[]ua.Reference{
			{
				ReferenceTypeID: ua.ReferenceTypeIDHasComponent,
				IsInverse:       true,
				TargetID:        ua.ExpandedNodeID{NodeID: parent},
			},
		},
		true,
	)
	node.SetCallMethodHandler(handler)
	if err := s.NameSpaceMngr.AddNode(node); err != nil {
		return "", err
	}
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
		ua.LocalizedText{Text: ""},
		nil,
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
	if err := s.NameSpaceMngr.AddNode(node); err != nil {
		return "", err
	}
	return nodeID, nil
}

func (s *RuntimeOPCUAServer) SetNodeValue(nodeIDStr string, newValue any) error {
	nodeID := ua.ParseNodeID(nodeIDStr)
	if nodeID == nil {
		return fmt.Errorf("failed to parse node id %s", nodeIDStr)
	}
	node, ok := s.NameSpaceMngr.FindVariable(nodeID)
	if !ok {
		return fmt.Errorf("failed to find node %s", nodeIDStr)
	}
	node.SetValue(ua.NewDataValue(newValue, 0, time.Now().UTC(), 0, time.Now().UTC(), 0))
	return nil
}

func (s *RuntimeOPCUAServer) resolveTypeID(value reflect.Value) (ua.NodeID, error) {
	if !value.IsValid() {
		return ua.DataTypeIDBaseDataType, nil
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
	typeID := ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(typ.String(), ".", "_")}
	if _, ok := s.NameSpaceMngr.FindNode(typeID); ok {
		return nil
	}

	fields := make([]ua.StructureField, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldType := field.Type

		for fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}

		var dataType ua.NodeID
		valueRank := ua.ValueRankScalar

		switch fieldType.Kind() {
		case reflect.Struct:
			if err := s.generateTypeDefs(reflect.Zero(fieldType)); err != nil {
				return err
			}
			dataType = ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(fieldType.String(), ".", "_")}
		case reflect.Slice:
			elem := fieldType.Elem()
			if elem.Kind() == reflect.Struct {
				if err := s.generateTypeDefs(reflect.Zero(elem)); err != nil {
					return err
				}
				dataType = ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(elem.String(), ".", "_")}
			} else {
				id, ok := uaTypes[elem.Kind()]
				if !ok {
					return fmt.Errorf("unsupported slice element type %s", elem)
				}
				dataType = id
			}
			valueRank = ua.ValueRankOneDimension
		default:
			id, ok := uaTypes[fieldType.Kind()]
			if !ok {
				return fmt.Errorf("unsupported field type %s in %s.%s", fieldType, typ.String(), field.Name)
			}
			dataType = id
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
		ua.LocalizedText{Text: ""},
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
			DefaultEncodingID: ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(typ.String(), ".", "_") + "_Enc"},
			BaseDataType:      ua.DataTypeIDStructure,
			StructureType:     ua.StructureTypeStructure,
			Fields:            fields,
		},
	)

	if _, ok := ua.FindBinaryEncodingIDForType(typ); !ok {
		ua.RegisterBinaryEncodingID(typ, ua.ExpandedNodeID{NodeID: ua.NodeIDString{NamespaceIndex: 2, ID: strings.ReplaceAll(typ.String(), ".", "_") + "_Enc"}})
	}

	return s.NameSpaceMngr.AddNode(node)
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
