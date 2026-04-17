# OPC-UA-Centralserver
2 Opc-UA servers with an enrollment mechanism

## Current OPC UA behavior

- The general server runs on `opc.tcp://127.0.0.1:4840` by default.
- The SCADA server runs on `opc.tcp://127.0.0.1:4844` by default.
- Custom struct binary encodings are registered during server startup.
- Custom OPC UA datatype nodes are generated when struct-backed nodes are added.
- Generated custom struct datatypes now keep datatype metadata references aligned, including bidirectional `HasDescription` links between the datatype/encoding nodes and the dictionary description node.
- Published variable nodes are created with read/write access levels and read/write role permissions, including anonymous access.

## Library note

When using `github.com/awcullen/opcua`, `NamespaceManager.AddNode()` adds matching inverse references only for references present when the node is added. If references are appended later with `SetReferences(...)`, the inverse side must also be added explicitly. This project does that for custom struct datatype metadata so OPC UA clients can browse the generated datatype relationships correctly.

There is still a separate modelling gap for struct-valued variables:

- The current runtime server creates a variable with `HasTypeDefinition = BaseDataVariableType` and `DataType = <custom struct datatype>`.
- A modeled OPC UA structure instance, like the Siemens `BuildInfo` example, also has a dedicated `VariableType` such as `BuildInfoType`.
- That `VariableType` contains child field declarations like `BuildDate`, `BuildNumber`, `ManufacturerName`, each typically linked with `HasComponent`, `HasTypeDefinition`, and `HasModellingRule`.
- When an instance of that struct variable is created, those child declarations are instantiated as browsable child variables under the struct node.

What currently goes wrong in this project:

- Browsing the custom struct variable only shows the generic `HasTypeDefinition -> BaseDataVariableType`.
- The struct fields are stored only inside the variable's scalar value payload and are not exposed as child nodes.
- Because no struct-specific `VariableType` is created, clients do not see the hierarchical field references that appear in the Siemens example.
- So the missing references are not just missing inverse datatype references; they are missing field-level modelling and instantiation references.

What the library likely needs to support cleanly:

- A helper to generate a `VariableTypeNode` for a struct from a Go struct definition.
- Automatic creation of field declaration children on that `VariableTypeNode`.
- Automatic instantiation of those declared children when creating a variable instance of that struct type.
- Support for adding the expected references for those field nodes, including `HasComponent`, `HasTypeDefinition`, and `HasModellingRule` where appropriate.
- A higher-level "structured variable" helper so a variable can be modeled as a browsable OPC UA structure instance, not only as a scalar ExtensionObject value.

See the detailed setup docs in [documentation/Index.md](documentation/Index.md).
