# OPC-UA-Centralserver
2 Opc-UA servers with an enrollment mechanism

## Current OPC UA behavior

- The general server runs on `opc.tcp://127.0.0.1:4842` by default.
- The SCADA server runs on `opc.tcp://127.0.0.1:4844` by default.
- Custom struct binary encodings are registered during server startup.
- Custom OPC UA datatype nodes are generated when struct-backed nodes are added.
- Published variable nodes are created with read/write access levels and read/write role permissions, including anonymous access.

See the detailed setup docs in [documentation/Index.md](documentation/Index.md).
