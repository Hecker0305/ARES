# Standards Reference

## Modbus Function Codes
| Code | Function | Description | Security Risk |
|------|----------|-------------|---------------|
| 01 | Read Coils | Read binary output coils | Low |
| 02 | Read Discrete Inputs | Read binary input status | Low |
| 03 | Read Holding Registers | Read analog output registers | Low |
| 04 | Read Input Registers | Read analog input registers | Low |
| 05 | Write Single Coil | Write binary output coil | HIGH |
| 06 | Write Single Register | Write single analog register | HIGH |
| 15 | Write Multiple Coils | Write multiple binary coils | HIGH |
| 16 | Write Multiple Registers | Write multiple analog registers | HIGH |
| 22 | Mask Write Register | Mask write to register | HIGH |
| 23 | Read/Write Registers | Combined read/write operation | HIGH |
| 08 | Diagnostics | Modbus diagnostics (sub-function 01 = Restart) | CRITICAL |
| 11 | Get Com Event Counter | Communication event counter | Low |
| 17 | Report Slave ID | Device identification | Medium |

## OT Security Standards
| Standard | Relevance |
|----------|-----------|
| IEC 62443-3-3 | Network segmentation and secure communication |
| IEC 62443-4-2 | Technical security requirements for IACS components |
| NIST SP 800-82 Rev 2 | Guide to Industrial Control System Security |
| NERC CIP-005 | Electronic Security Perimeter(s) |

## References
- Modbus IDA: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
- ICS-CERT Advisories: https://www.cisa.gov/industrial-control-systems
- FireEye ICS Security: https://www.mandiant.com/industrial-control-systems-security
- Dragos OT Security: https://www.dragos.com
