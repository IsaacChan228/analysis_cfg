digraph Ghidra {
  "0012f040" [ Symbols="main" label="main" Code="ENDBR64
PUSH  R15
LEA   R15,[0x2060cc]
PUSH  R14
PUSH  R13
XOR   R13D,R13D
PUSH  R12
LEA   R12,[0x25c020]
PUSH  RBP
LEA   RBP,[0x2175b0]
..." VertexType="Body" ];
  "0012f09f" [ label="0012f09f" Code="LEA   RSI,[0x20608a]
MOV   RDI,RBX
CALL  0x0012e8c0" VertexType="Body" ];
  "0012f0ae" [ label="0012f0ae" Code="MOV   RDI,RBX
LEA   RBX,[0x222efc]
CALL  0x0012e880" VertexType="Body" ];
  "0012f0bd" [ label="0012f0bd" Code="MOV   RAX,qword ptr [RSP + 0x10]
MOV   RDI,qword ptr [RAX]
MOV   qword ptr [0x0025ccc0],RDI
CALL  0x00205d70" VertexType="Body" ];
  "0012f0d1" [ label="0012f0d1" Code="MOV   RDI,qword ptr [0x0025ccc0]
CALL  0x001334d0" VertexType="Body" ];
  "0012f0dd" [ label="0012f0dd" Code="LEA   RSI,[RSP + 0x10]
LEA   RDI,[RSP + 0x1c]
CALL  0x001fc920" VertexType="Body" ];
  "0012f0ec" [ label="0012f0ec" Code="MOV  byte ptr [0x0025ccb3],0x0
MOV  dword ptr [0x0025ccb4],0x4
MOV  byte ptr [0x0025ccb2],0x0
MOV  byte ptr [0x0025ccb1],0x0
MOV  byte ptr [0x0025ccb0],0x0
MOV  qword ptr [0x0025cca8],0x0
MOV  byte ptr [0x0025cca4],0x73
MOV  qword ptr [0x0025cc98],0x0
NOP" VertexType="Body" ];
  "0012f130" [ label="LAB_0012f130" Code="MOV   RSI,qword ptr [RSP + 0x10]
MOV   EDI,dword ptr [RSP + 0x1c]
XOR   R8D,R8D
MOV   RCX,R12
MOV   RDX,RBP
CALL  0x0012e930" VertexType="Body" ];
  "0012f147" [ label="0012f147" Code="CMP  EAX,-0x1
JZ   0x0012f2f0" VertexType="Body" ];
  "0012f2f0" [ label="LAB_0012f2f0" Code="MOV   EAX,dword ptr [0x0025ccbc]
TEST  EAX,EAX
JNZ   0x0012f60f" VertexType="Body" ];
  "0012f150" [ label="0012f150" Code="SUB  EAX,0x3f
CMP  EAX,0x38
JA   0x0012f168" VertexType="Body" ];
  "0012f168" [ Symbols="caseD_40
caseD_41
caseD_42
caseD_43
caseD_44
caseD_45
caseD_46
caseD_47
caseD_49
caseD_4a
caseD_4b
..." label="caseD_40" Code="MOVSXD  R13,dword ptr [0x0025cc38]
JMP     0x0012f130" VertexType="Body" ];
  "0012f158" [ label="0012f158" Code="MOVSXD  RAX,dword ptr [RBX + RAX*0x4]
ADD     RAX,RBX" VertexType="Body" ];
  "0012f15f" [ Symbols="switchD" label="switchD" Code="JMP  RAX" VertexType="Switch" ];
  "0012f7ff" [ Symbols="caseD_3f" label="caseD_3f" Code="MOV   RDI,qword ptr [0x0025cc80]
MOV   ESI,0x1
CALL  0x0012fe60" VertexType="Exit" ];
  "0012f7de" [ Symbols="caseD_48
caseD_68" label="caseD_48" Code="MOV   RDI,qword ptr [0x0025cc20]
XOR   ESI,ESI
CALL  0x0012fe60" VertexType="Exit" ];
  "0012f260" [ Symbols="caseD_54" label="caseD_54" Code="MOV  RAX,qword ptr [0x0025cc60]
MOV  qword ptr [0x0025cca8],RAX
JMP  0x0012f130" VertexType="Body" ];
  "0012f220" [ Symbols="caseD_55" label="caseD_55" Code="MOV   R14,qword ptr [0x0025cc60]
LEA   RSI,[0x2060ab]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f178" [ Symbols="caseD_56
caseD_76" label="caseD_56" Code="MOV   RDI,R15
CALL  0x001326a0" VertexType="Body" ];
  "0012f210" [ Symbols="caseD_61" label="caseD_61" Code="MOV  byte ptr [0x0025ccb0],0x0
JMP  0x0012f130" VertexType="Body" ];
  "0012f2c0" [ Symbols="caseD_64" label="caseD_64" Code="MOV  byte ptr [0x0025ccb0],0x1
JMP  0x0012f130" VertexType="Body" ];
  "0012f2a0" [ Symbols="caseD_65" label="caseD_65" Code="MOV  RAX,qword ptr [0x0025cc60]
CMP  byte ptr [RAX + 0x1],0x0
JNZ  0x0012f7ff" VertexType="Body" ];
  "0012f290" [ Symbols="caseD_66" label="caseD_66" Code="MOV  byte ptr [0x0025ccb1],0x1
JMP  0x0012f130" VertexType="Body" ];
  "0012f278" [ Symbols="caseD_6e" label="caseD_6e" Code="MOV   RDI,qword ptr [0x0025cc60]
CALL  0x0012fa30" VertexType="Body" ];
  "0012f1f8" [ Symbols="caseD_6f" label="caseD_6f" Code="MOV  byte ptr [0x0025ccb2],0x1
MOV  dword ptr [0x0025ccb8],0x8
JMP  0x0012f130" VertexType="Body" ];
  "0012f1e0" [ Symbols="caseD_73" label="caseD_73" Code="MOV  RAX,qword ptr [0x0025cc60]
MOV  qword ptr [0x0025cc98],RAX
JMP  0x0012f130" VertexType="Body" ];
  "0012f198" [ Symbols="caseD_74" label="caseD_74" Code="MOV  RAX,qword ptr [0x0025cc60]
MOV  byte ptr [0x0025ccb2],0x1
CMP  byte ptr [RAX + 0x1],0x0
JNZ  0x0012f7ff" VertexType="Body" ];
  "0012f188" [ Symbols="caseD_77" label="caseD_77" Code="MOV  byte ptr [0x0025ccb3],0x1
JMP  0x0012f130" VertexType="Body" ];
  "0012f180" [ label="0012f180" Code="JMP  0x0012f130" VertexType="Body" ];
  "0012f1b0" [ label="0012f1b0" Code="MOVZX  EAX,byte ptr [RAX]
CMP    AL,0x6f
JZ     0x0012f2e0" VertexType="Body" ];
  "0012f2e0" [ label="LAB_0012f2e0" Code="MOV  dword ptr [0x0025ccb8],0x8
JMP  0x0012f130" VertexType="Body" ];
  "0012f1bb" [ label="0012f1bb" Code="CMP  AL,0x78
JZ   0x0012f2d0" VertexType="Body" ];
  "0012f2d0" [ label="LAB_0012f2d0" Code="MOV  dword ptr [0x0025ccb8],0x10
JMP  0x0012f130" VertexType="Body" ];
  "0012f1c3" [ label="0012f1c3" Code="CMP  AL,0x64
JNZ  0x0012f7ff" VertexType="Body" ];
  "0012f1cb" [ label="0012f1cb" Code="MOV  dword ptr [0x0025ccb8],0xa
JMP  0x0012f130" VertexType="Body" ];
  "0012f236" [ label="0012f236" Code="TEST  EAX,EAX
JZ    0x0012f24f" VertexType="Body" ];
  "0012f24f" [ label="LAB_0012f24f" Code="MOV  dword ptr [0x0025ccbc],0x0
JMP  0x0012f130" VertexType="Body" ];
  "0012f23a" [ label="0012f23a" Code="CMP  byte ptr [R14],0x64
JNZ  0x0012f508" VertexType="Body" ];
  "0012f508" [ label="LAB_0012f508" Code="LEA   RSI,[0x20609b]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f244" [ label="0012f244" Code="CMP  byte ptr [R14 + 0x1],0x0
JNZ  0x0012f508" VertexType="Body" ];
  "0012f284" [ label="0012f284" Code="JMP  0x0012f130" VertexType="Body" ];
  "0012f2b1" [ label="0012f2b1" Code="MOVZX  EAX,byte ptr [RAX]
MOV    byte ptr [0x0025cca4],AL
JMP    0x0012f130" VertexType="Body" ];
  "0012f60f" [ label="LAB_0012f60f" Code="MOV   byte ptr [0x0025cca4],0x53
TEST  R13D,R13D
JNZ   0x0012f711" VertexType="Body" ];
  "0012f2fe" [ label="0012f2fe" Code="TEST  R13D,R13D
JNZ   0x0012f711" VertexType="Body" ];
  "0012f711" [ label="LAB_0012f711" Code="MOV   RAX,qword ptr [RSP + 0x10]
MOV   RDI,qword ptr [RAX + R13*0x8 + -0x8]
ADD   RDI,0x1
CALL  0x0012fa30" VertexType="Body" ];
  "0012f307" [ label="LAB_0012f307" Code="MOVZX  EAX,byte ptr [0x0025cca4]
LEA    ECX,[RAX + -0x42]
CMP    CL,0x31
JA     0x0012f7ff" VertexType="Body" ];
  "0012f31a" [ label="0012f31a" Code="MOV   EAX,0x1
MOV   EDX,0x401
SHL   RAX,CL
SHL   RDX,0x20
TEST  RAX,RDX
JNZ   0x0012f707" VertexType="Body" ];
  "0012f707" [ label="LAB_0012f707" Code="MOV  EDX,0x2
JMP  0x0012f344" VertexType="Body" ];
  "0012f334" [ label="0012f334" Code="MOV   EDX,0x4
TEST  EAX,0x401
JZ    0x0012f7ec" VertexType="Body" ];
  "0012f7ec" [ label="LAB_0012f7ec" Code="MOV   RDX,0x2000000020000
TEST  RAX,RDX
JNZ   0x0012f61f" VertexType="Body" ];
  "0012f344" [ label="LAB_0012f344" Code="MOV   dword ptr [0x0025cca0],EDX
CALL  0x00133520" VertexType="Body" ];
  "0012f34f" [ label="0012f34f" Code="CMP  EAX,0x110
JNZ  0x0012f84e" VertexType="Body" ];
  "0012f84e" [ label="LAB_0012f84e" Code="XOR   EDI,EDI
MOV   EDX,0x5
LEA   RSI,[0x2175d0]
CALL  0x0012e8e0" VertexType="Body" ];
  "0012f35a" [ label="0012f35a" Code="CALL  0x001318c0" VertexType="Body" ];
  "0012f35f" [ label="0012f35f" Code="XOR  R12D,R12D
MOV  EAX,dword ptr [0x0025cc38]
XOR  ECX,ECX
CMP  EAX,dword ptr [RSP + 0x1c]
JGE  0x0012f729" VertexType="Body" ];
  "0012f729" [ label="LAB_0012f729" Code="MOV   RSI,qword ptr [0x0025cc30]
XOR   R8D,R8D
XOR   ECX,ECX
XOR   EDX,EDX
LEA   RDI,[0x2060d4]
MOV   byte ptr [0x0025ccb0],0x0
CALL  0x00130be0" VertexType="Body" ];
  "0012f374" [ label="0012f374" Code="NOP  dword ptr CS:[RAX + RAX*0x1]
NOP" VertexType="Body" ];
  "0012f380" [ label="LAB_0012f380" Code="MOV  RDX,qword ptr [RSP + 0x10]
CDQE
MOV  RBX,qword ptr [RDX + RAX*0x8]
CMP  byte ptr [RBX],0x2d
JZ   0x0012f630" VertexType="Body" ];
  "0012f630" [ label="LAB_0012f630" Code="CMP  byte ptr [RBX + 0x1],0x0
JNZ  0x0012f394" VertexType="Body" ];
  "0012f394" [ label="LAB_0012f394" Code="LEA   RSI,[RSP + 0x30]
MOV   RDI,RBX
CALL  0x0012eae0" VertexType="Body" ];
  "0012f3a1" [ label="0012f3a1" Code="TEST  EAX,EAX
JS    0x0012f6b5" VertexType="Body" ];
  "0012f6b5" [ label="LAB_0012f6b5" Code="CALL  0x0012e7b0" VertexType="Body" ];
  "0012f3a9" [ label="0012f3a9" Code="MOV  EAX,dword ptr [RSP + 0x48]
AND  EAX,0xf000
CMP  EAX,0x4000
JZ   0x0012f74f" VertexType="Body" ];
  "0012f74f" [ label="LAB_0012f74f" Code="MOV  EDX,0x5
LEA  RSI,[0x2060f8]" VertexType="Body" ];
  "0012f3bd" [ label="0012f3bd" Code="CMP  byte ptr [0x0025ccb0],0x0
JZ   0x0012f650" VertexType="Body" ];
  "0012f650" [ label="LAB_0012f650" Code="LEA   RSI,[0x216e73]
MOV   RDI,RBX
CALL  0x0012eca0" VertexType="Body" ];
  "0012f3ca" [ label="0012f3ca" Code="MOV   RSI,qword ptr [0x0025cca8]
MOV   RDI,RBX
CALL  0x00139cf0" VertexType="Body" ];
  "0012f3d9" [ label="0012f3d9" Code="MOV   RBP,RAX
TEST  RAX,RAX
JZ    0x0012f650" VertexType="Body" ];
  "0012f3e5" [ label="0012f3e5" Code="MOV   ESI,0x1
MOV   RDI,RAX
CALL  0x001367e0" VertexType="Body" ];
  "0012f3f2" [ label="0012f3f2" Code="TEST  AL,AL
JZ    0x0012f646" VertexType="Body" ];
  "0012f646" [ label="LAB_0012f646" Code="MOV   RDI,RBP
CALL  0x00139350" VertexType="Body" ];
  "0012f3fa" [ label="0012f3fa" Code="MOV   R14,qword ptr [RBP + 0x90]
TEST  R14,R14
JZ    0x0012f7c1" VertexType="Body" ];
  "0012f7c1" [ label="LAB_0012f7c1" Code="MOV   RDI,RBP
CALL  0x00139350" VertexType="Body" ];
  "0012f40a" [ label="0012f40a" Code="LEA  RAX,[RSP + 0x28]
XOR  R13D,R13D
MOV  qword ptr [RSP],RAX
NOP  word ptr CS:[RAX + RAX*0x1]" VertexType="Body" ];
  "0012f420" [ label="LAB_0012f420" Code="MOV   EAX,dword ptr [R14 + 0x24]
NOT   EAX
TEST  EAX,0x103
JNZ   0x0012f480" VertexType="Body" ];
  "0012f480" [ label="LAB_0012f480" Code="MOV   R14,qword ptr [R14 + 0x8]
TEST  R14,R14
JNZ   0x0012f420" VertexType="Body" ];
  "0012f42d" [ label="0012f42d" Code="MOV   R15,qword ptr [R14 + 0x40]
TEST  R15,R15
JZ    0x0012f480" VertexType="Body" ];
  "0012f436" [ label="0012f436" Code="MOV   RDX,qword ptr [RSP]
MOV   RSI,R14
MOV   RDI,RBP
CALL  0x0013ad90" VertexType="Body" ];
  "0012f445" [ label="0012f445" Code="TEST  AL,AL
JZ    0x0012f771" VertexType="Body" ];
  "0012f771" [ label="LAB_0012f771" Code="CALL  0x00133230" VertexType="Body" ];
  "0012f44d" [ label="0012f44d" Code="MOV   RDX,qword ptr [R14 + 0x80]
MOV   ECX,R15D
XOR   ESI,ESI
MOV   RDI,RBX
MOV   R8,qword ptr [RSP + 0x28]
MOV   byte ptr [RSP + 0x8],AL
CALL  0x00130be0" VertexType="Body" ];
  "0012f46a" [ label="0012f46a" Code="MOV   RDI,qword ptr [RSP + 0x28]
CALL  0x0012e6e0" VertexType="Body" ];
  "0012f474" [ label="0012f474" Code="MOVZX  R13D,byte ptr [RSP + 0x8]
NOP    word ptr [RAX + RAX*0x1]" VertexType="Body" ];
  "0012f489" [ label="0012f489" Code="MOV   RDI,RBP
CALL  0x00139350" VertexType="Body" ];
  "0012f491" [ label="0012f491" Code="TEST  AL,AL
JZ    0x0012f7d1" VertexType="Body" ];
  "0012f7d1" [ label="LAB_0012f7d1" Code="MOV   RDI,RBX
CALL  0x00131430" VertexType="Body" ];
  "0012f499" [ label="0012f499" Code="TEST  R13B,R13B
JZ    0x0012f650" VertexType="Body" ];
  "0012f4a2" [ label="0012f4a2" Code="NOP  dword ptr CS:[RAX + RAX*0x1]
NOP  dword ptr [RAX]" VertexType="Body" ];
  "0012f4b0" [ label="LAB_0012f4b0" Code="MOV  ECX,0x1" VertexType="Body" ];
  "0012f4b5" [ label="LAB_0012f4b5" Code="MOV  EAX,dword ptr [0x0025cc38]
ADD  EAX,0x1
MOV  dword ptr [0x0025cc38],EAX
CMP  EAX,dword ptr [RSP + 0x1c]
JL   0x0012f380" VertexType="Body" ];
  "0012f4ce" [ label="0012f4ce" Code="TEST  CL,CL
JZ    0x0012f7ff" VertexType="Body" ];
  "0012f4d6" [ label="LAB_0012f4d6" Code="MOV  RAX,qword ptr [RSP + 0xc8]
SUB  RAX,qword ptr FS:[0x28]
JNZ  0x0012f86b" VertexType="Body" ];
  "0012f86b" [ label="LAB_0012f86b" Code="CALL  0x0012e900" VertexType="Exit" ];
  "0012f4ed" [ label="0012f4ed" Code="ADD  RSP,0xd8
MOV  EAX,R12D
POP  RBX
POP  RBP
POP  R12
POP  R13
POP  R14
POP  R15
RET" VertexType="Exit" ];
  "0012f517" [ label="0012f517" Code="TEST  EAX,EAX
JZ    0x0012f600" VertexType="Body" ];
  "0012f600" [ label="LAB_0012f600" Code="MOV  dword ptr [0x0025ccbc],0x1
JMP  0x0012f130" VertexType="Body" ];
  "0012f51f" [ label="0012f51f" Code="LEA   RSI,[0x216dae]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f52e" [ label="0012f52e" Code="TEST  EAX,EAX
JZ    0x0012f600" VertexType="Body" ];
  "0012f536" [ label="0012f536" Code="LEA   RSI,[0x2060b3]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f545" [ label="0012f545" Code="TEST  EAX,EAX
JZ    0x0012f7b2" VertexType="Body" ];
  "0012f7b2" [ label="LAB_0012f7b2" Code="MOV  dword ptr [0x0025ccbc],0x2
JMP  0x0012f130" VertexType="Body" ];
  "0012f54d" [ label="0012f54d" Code="LEA   RSI,[0x20613e]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f55c" [ label="0012f55c" Code="TEST  EAX,EAX
JZ    0x0012f7b2" VertexType="Body" ];
  "0012f564" [ label="0012f564" Code="LEA   RSI,[0x2060ba]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f573" [ label="0012f573" Code="TEST  EAX,EAX
JZ    0x0012f810" VertexType="Body" ];
  "0012f810" [ label="LAB_0012f810" Code="MOV  dword ptr [0x0025ccbc],0x5
JMP  0x0012f130" VertexType="Body" ];
  "0012f57b" [ label="0012f57b" Code="LEA   RSI,[0x2073d7]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f58a" [ label="0012f58a" Code="TEST  EAX,EAX
JZ    0x0012f810" VertexType="Body" ];
  "0012f592" [ label="0012f592" Code="LEA   RSI,[0x2066db]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f5a1" [ label="0012f5a1" Code="TEST  EAX,EAX
JZ    0x0012f81f" VertexType="Body" ];
  "0012f81f" [ label="LAB_0012f81f" Code="MOV  dword ptr [0x0025ccbc],0x3
JMP  0x0012f130" VertexType="Body" ];
  "0012f5a9" [ label="0012f5a9" Code="LEA   RSI,[0x208f4b]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f5b8" [ label="0012f5b8" Code="TEST  EAX,EAX
JZ    0x0012f81f" VertexType="Body" ];
  "0012f5c0" [ label="0012f5c0" Code="LEA   RSI,[0x2060c2]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f5cf" [ label="0012f5cf" Code="TEST  EAX,EAX
JZ    0x0012f5ea" VertexType="Body" ];
  "0012f5ea" [ label="LAB_0012f5ea" Code="MOV  dword ptr [0x0025ccbc],0x4
JMP  0x0012f130" VertexType="Body" ];
  "0012f5d3" [ label="0012f5d3" Code="LEA   RSI,[0x216f2e]
MOV   RDI,R14
CALL  0x0012ea60" VertexType="Body" ];
  "0012f5e2" [ label="0012f5e2" Code="TEST  EAX,EAX
JNZ   0x0012f82e" VertexType="Body" ];
  "0012f82e" [ label="LAB_0012f82e" Code="LEA   RSI,[0x217588]
XOR   EDI,EDI
MOV   EDX,0x5
CALL  0x0012e8e0" VertexType="Body" ];
  "0012f61f" [ label="LAB_0012f61f" Code="MOV  EDX,0x1
JMP  0x0012f344" VertexType="Body" ];
  "0012f63a" [ label="0012f63a" Code="MOV  byte ptr [0x0025ccb0],0x0
JMP  0x0012f4b5" VertexType="Body" ];
  "0012f64e" [ label="0012f64e" Code="NOP" VertexType="Body" ];
  "0012f65f" [ label="0012f65f" Code="MOV   RBP,RAX
TEST  RAX,RAX
JZ    0x0012f68a" VertexType="Body" ];
  "0012f68a" [ label="LAB_0012f68a" Code="MOV   RCX,qword ptr [0x0025ccc0]
MOV   RDI,qword ptr [0x0025cc80]
LEA   RDX,[0x206073]
XOR   EAX,EAX
MOV   ESI,0x2
CALL  0x0012ed40" VertexType="Body" ];
  "0012f667" [ label="0012f667" Code="XOR   R8D,R8D
XOR   ECX,ECX
XOR   EDX,EDX
MOV   RDI,RBX
MOV   RSI,RAX
CALL  0x00130be0" VertexType="Body" ];
  "0012f679" [ label="0012f679" Code="MOV   RDI,RBP
CALL  0x0012e890" VertexType="Body" ];
  "0012f681" [ label="0012f681" Code="CMP  EAX,-0x1
JNZ  0x0012f4b0" VertexType="Body" ];
  "0012f6ab" [ label="0012f6ab" Code="MOV   RDI,RBX
CALL  0x0012ecb0" VertexType="Body" ];
  "0012f6b3" [ label="0012f6b3" Code="JMP  0x0012f6fc" VertexType="Body" ];
  "0012f6fc" [ label="LAB_0012f6fc" Code="MOV  R12D,0x1
JMP  0x0012f4b0" VertexType="Body" ];
  "0012f6ba" [ label="0012f6ba" Code="MOV  EDX,0x5
LEA  RSI,[0x2060e5]
MOV  EDI,dword ptr [RAX]
CMP  EDI,0x2
JZ   0x0012f75b" VertexType="Body" ];
  "0012f75b" [ label="LAB_0012f75b" Code="XOR   EDI,EDI
CALL  0x0012e8e0" VertexType="Body" ];
  "0012f6d1" [ label="0012f6d1" Code="CALL  0x0012ed70" VertexType="Body" ];
  "0012f6d6" [ label="0012f6d6" Code="MOV   EDX,0x5
LEA   RSI,[0x2175f8]
XOR   EDI,EDI
MOV   RBP,RAX
CALL  0x0012e8e0" VertexType="Body" ];
  "0012f6ec" [ label="0012f6ec" Code="MOV   RDX,RBP
MOV   RSI,RBX
MOV   RDI,RAX
XOR   EAX,EAX
CALL  0x001317e0" VertexType="Body" ];
  "0012f724" [ label="0012f724" Code="JMP  0x0012f307" VertexType="Body" ];
  "0012f74a" [ label="0012f74a" Code="JMP  0x0012f4d6" VertexType="Body" ];
  "0012f762" [ label="0012f762" Code="MOV   RSI,RBX
MOV   RDI,RAX
XOR   EAX,EAX
CALL  0x001317e0" VertexType="Body" ];
  "0012f76f" [ label="0012f76f" Code="JMP  0x0012f6fc" VertexType="Body" ];
  "0012f776" [ label="0012f776" Code="MOV   EDI,EAX
CALL  0x00133240" VertexType="Body" ];
  "0012f77d" [ label="0012f77d" Code="MOV   R15,qword ptr [R14]
XOR   EDI,EDI
MOV   EDX,0x5
LEA   RSI,[0x217628]
MOV   qword ptr [RSP + 0x8],RAX
CALL  0x0012e8e0" VertexType="Body" ];
  "0012f798" [ label="0012f798" Code="MOV   RCX,qword ptr [RSP + 0x8]
MOV   RDX,R15
MOV   RSI,RBX
MOV   RDI,RAX
XOR   EAX,EAX
CALL  0x001317e0" VertexType="Body" ];
  "0012f7ad" [ label="0012f7ad" Code="JMP  0x0012f480" VertexType="Body" ];
  "0012f7c9" [ label="0012f7c9" Code="TEST  AL,AL
JNZ   0x0012f650" VertexType="Body" ];
  "0012f7d9" [ label="0012f7d9" Code="JMP  0x0012f650" VertexType="Body" ];
  "0012f841" [ label="0012f841" Code="MOV   RSI,R14
MOV   RDI,RAX
XOR   EAX,EAX
CALL  0x00131730" VertexType="Exit" ];
  "0012f861" [ label="0012f861" Code="MOV   RDI,RAX
XOR   EAX,EAX
CALL  0x00131730" VertexType="Exit" ];
  "0012f040" -> "0012f09f" [ EdgeType="Fall Through" ];
  "0012f09f" -> "0012f0ae" [ EdgeType="Fall Through" ];
  "0012f0ae" -> "0012f0bd" [ EdgeType="Fall Through" ];
  "0012f0bd" -> "0012f0d1" [ EdgeType="Fall Through" ];
  "0012f0d1" -> "0012f0dd" [ EdgeType="Fall Through" ];
  "0012f0dd" -> "0012f0ec" [ EdgeType="Fall Through" ];
  "0012f0ec" -> "0012f130" [ EdgeType="Fall Through" ];
  "0012f130" -> "0012f147" [ EdgeType="Fall Through" ];
  "0012f147" -> "0012f2f0" [ EdgeType="Conditional Jump" ];
  "0012f147" -> "0012f150" [ EdgeType="Fall Through" ];
  "0012f150" -> "0012f168" [ EdgeType="Conditional Jump" ];
  "0012f150" -> "0012f158" [ EdgeType="Fall Through" ];
  "0012f158" -> "0012f15f" [ EdgeType="Fall Through" ];
  "0012f15f" -> "0012f7ff" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f168" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f7de" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f260" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f220" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f178" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f210" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f2c0" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f2a0" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f290" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f278" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f1f8" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f1e0" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f198" [ EdgeType="Computed Jump" ];
  "0012f15f" -> "0012f188" [ EdgeType="Computed Jump" ];
  "0012f168" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f178" -> "0012f180" [ EdgeType="Fall Through" ];
  "0012f180" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f188" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f198" -> "0012f7ff" [ EdgeType="Conditional Jump" ];
  "0012f198" -> "0012f1b0" [ EdgeType="Fall Through" ];
  "0012f1b0" -> "0012f2e0" [ EdgeType="Conditional Jump" ];
  "0012f1b0" -> "0012f1bb" [ EdgeType="Fall Through" ];
  "0012f1bb" -> "0012f2d0" [ EdgeType="Conditional Jump" ];
  "0012f1bb" -> "0012f1c3" [ EdgeType="Fall Through" ];
  "0012f1c3" -> "0012f7ff" [ EdgeType="Conditional Jump" ];
  "0012f1c3" -> "0012f1cb" [ EdgeType="Fall Through" ];
  "0012f1cb" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f1e0" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f1f8" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f210" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f220" -> "0012f236" [ EdgeType="Fall Through" ];
  "0012f236" -> "0012f24f" [ EdgeType="Conditional Jump" ];
  "0012f236" -> "0012f23a" [ EdgeType="Fall Through" ];
  "0012f23a" -> "0012f508" [ EdgeType="Conditional Jump" ];
  "0012f23a" -> "0012f244" [ EdgeType="Fall Through" ];
  "0012f244" -> "0012f508" [ EdgeType="Conditional Jump" ];
  "0012f244" -> "0012f24f" [ EdgeType="Fall Through" ];
  "0012f24f" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f260" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f278" -> "0012f284" [ EdgeType="Fall Through" ];
  "0012f284" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f290" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f2a0" -> "0012f7ff" [ EdgeType="Conditional Jump" ];
  "0012f2a0" -> "0012f2b1" [ EdgeType="Fall Through" ];
  "0012f2b1" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f2c0" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f2d0" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f2e0" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f2f0" -> "0012f60f" [ EdgeType="Conditional Jump" ];
  "0012f2f0" -> "0012f2fe" [ EdgeType="Fall Through" ];
  "0012f2fe" -> "0012f711" [ EdgeType="Conditional Jump" ];
  "0012f2fe" -> "0012f307" [ EdgeType="Fall Through" ];
  "0012f307" -> "0012f7ff" [ EdgeType="Conditional Jump" ];
  "0012f307" -> "0012f31a" [ EdgeType="Fall Through" ];
  "0012f31a" -> "0012f707" [ EdgeType="Conditional Jump" ];
  "0012f31a" -> "0012f334" [ EdgeType="Fall Through" ];
  "0012f334" -> "0012f7ec" [ EdgeType="Conditional Jump" ];
  "0012f334" -> "0012f344" [ EdgeType="Fall Through" ];
  "0012f344" -> "0012f34f" [ EdgeType="Fall Through" ];
  "0012f34f" -> "0012f84e" [ EdgeType="Conditional Jump" ];
  "0012f34f" -> "0012f35a" [ EdgeType="Fall Through" ];
  "0012f35a" -> "0012f35f" [ EdgeType="Fall Through" ];
  "0012f35f" -> "0012f729" [ EdgeType="Conditional Jump" ];
  "0012f35f" -> "0012f374" [ EdgeType="Fall Through" ];
  "0012f374" -> "0012f380" [ EdgeType="Fall Through" ];
  "0012f380" -> "0012f630" [ EdgeType="Conditional Jump" ];
  "0012f380" -> "0012f394" [ EdgeType="Fall Through" ];
  "0012f394" -> "0012f3a1" [ EdgeType="Fall Through" ];
  "0012f3a1" -> "0012f6b5" [ EdgeType="Conditional Jump" ];
  "0012f3a1" -> "0012f3a9" [ EdgeType="Fall Through" ];
  "0012f3a9" -> "0012f74f" [ EdgeType="Conditional Jump" ];
  "0012f3a9" -> "0012f3bd" [ EdgeType="Fall Through" ];
  "0012f3bd" -> "0012f650" [ EdgeType="Conditional Jump" ];
  "0012f3bd" -> "0012f3ca" [ EdgeType="Fall Through" ];
  "0012f3ca" -> "0012f3d9" [ EdgeType="Fall Through" ];
  "0012f3d9" -> "0012f650" [ EdgeType="Conditional Jump" ];
  "0012f3d9" -> "0012f3e5" [ EdgeType="Fall Through" ];
  "0012f3e5" -> "0012f3f2" [ EdgeType="Fall Through" ];
  "0012f3f2" -> "0012f646" [ EdgeType="Conditional Jump" ];
  "0012f3f2" -> "0012f3fa" [ EdgeType="Fall Through" ];
  "0012f3fa" -> "0012f7c1" [ EdgeType="Conditional Jump" ];
  "0012f3fa" -> "0012f40a" [ EdgeType="Fall Through" ];
  "0012f40a" -> "0012f420" [ EdgeType="Fall Through" ];
  "0012f420" -> "0012f480" [ EdgeType="Conditional Jump" ];
  "0012f420" -> "0012f42d" [ EdgeType="Fall Through" ];
  "0012f42d" -> "0012f480" [ EdgeType="Conditional Jump" ];
  "0012f42d" -> "0012f436" [ EdgeType="Fall Through" ];
  "0012f436" -> "0012f445" [ EdgeType="Fall Through" ];
  "0012f445" -> "0012f771" [ EdgeType="Conditional Jump" ];
  "0012f445" -> "0012f44d" [ EdgeType="Fall Through" ];
  "0012f44d" -> "0012f46a" [ EdgeType="Fall Through" ];
  "0012f46a" -> "0012f474" [ EdgeType="Fall Through" ];
  "0012f474" -> "0012f480" [ EdgeType="Fall Through" ];
  "0012f480" -> "0012f420" [ EdgeType="Conditional Jump" ];
  "0012f480" -> "0012f489" [ EdgeType="Fall Through" ];
  "0012f489" -> "0012f491" [ EdgeType="Fall Through" ];
  "0012f491" -> "0012f7d1" [ EdgeType="Conditional Jump" ];
  "0012f491" -> "0012f499" [ EdgeType="Fall Through" ];
  "0012f499" -> "0012f650" [ EdgeType="Conditional Jump" ];
  "0012f499" -> "0012f4a2" [ EdgeType="Fall Through" ];
  "0012f4a2" -> "0012f4b0" [ EdgeType="Fall Through" ];
  "0012f4b0" -> "0012f4b5" [ EdgeType="Fall Through" ];
  "0012f4b5" -> "0012f380" [ EdgeType="Conditional Jump" ];
  "0012f4b5" -> "0012f4ce" [ EdgeType="Fall Through" ];
  "0012f4ce" -> "0012f7ff" [ EdgeType="Conditional Jump" ];
  "0012f4ce" -> "0012f4d6" [ EdgeType="Fall Through" ];
  "0012f4d6" -> "0012f86b" [ EdgeType="Conditional Jump" ];
  "0012f4d6" -> "0012f4ed" [ EdgeType="Fall Through" ];
  "0012f508" -> "0012f517" [ EdgeType="Fall Through" ];
  "0012f517" -> "0012f600" [ EdgeType="Conditional Jump" ];
  "0012f517" -> "0012f51f" [ EdgeType="Fall Through" ];
  "0012f51f" -> "0012f52e" [ EdgeType="Fall Through" ];
  "0012f52e" -> "0012f600" [ EdgeType="Conditional Jump" ];
  "0012f52e" -> "0012f536" [ EdgeType="Fall Through" ];
  "0012f536" -> "0012f545" [ EdgeType="Fall Through" ];
  "0012f545" -> "0012f7b2" [ EdgeType="Conditional Jump" ];
  "0012f545" -> "0012f54d" [ EdgeType="Fall Through" ];
  "0012f54d" -> "0012f55c" [ EdgeType="Fall Through" ];
  "0012f55c" -> "0012f7b2" [ EdgeType="Conditional Jump" ];
  "0012f55c" -> "0012f564" [ EdgeType="Fall Through" ];
  "0012f564" -> "0012f573" [ EdgeType="Fall Through" ];
  "0012f573" -> "0012f810" [ EdgeType="Conditional Jump" ];
  "0012f573" -> "0012f57b" [ EdgeType="Fall Through" ];
  "0012f57b" -> "0012f58a" [ EdgeType="Fall Through" ];
  "0012f58a" -> "0012f810" [ EdgeType="Conditional Jump" ];
  "0012f58a" -> "0012f592" [ EdgeType="Fall Through" ];
  "0012f592" -> "0012f5a1" [ EdgeType="Fall Through" ];
  "0012f5a1" -> "0012f81f" [ EdgeType="Conditional Jump" ];
  "0012f5a1" -> "0012f5a9" [ EdgeType="Fall Through" ];
  "0012f5a9" -> "0012f5b8" [ EdgeType="Fall Through" ];
  "0012f5b8" -> "0012f81f" [ EdgeType="Conditional Jump" ];
  "0012f5b8" -> "0012f5c0" [ EdgeType="Fall Through" ];
  "0012f5c0" -> "0012f5cf" [ EdgeType="Fall Through" ];
  "0012f5cf" -> "0012f5ea" [ EdgeType="Conditional Jump" ];
  "0012f5cf" -> "0012f5d3" [ EdgeType="Fall Through" ];
  "0012f5d3" -> "0012f5e2" [ EdgeType="Fall Through" ];
  "0012f5e2" -> "0012f82e" [ EdgeType="Conditional Jump" ];
  "0012f5e2" -> "0012f5ea" [ EdgeType="Fall Through" ];
  "0012f5ea" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f600" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f60f" -> "0012f711" [ EdgeType="Conditional Jump" ];
  "0012f60f" -> "0012f61f" [ EdgeType="Fall Through" ];
  "0012f61f" -> "0012f344" [ EdgeType="Unconditional Jump" ];
  "0012f630" -> "0012f394" [ EdgeType="Conditional Jump" ];
  "0012f630" -> "0012f63a" [ EdgeType="Fall Through" ];
  "0012f63a" -> "0012f4b5" [ EdgeType="Unconditional Jump" ];
  "0012f646" -> "0012f64e" [ EdgeType="Fall Through" ];
  "0012f64e" -> "0012f650" [ EdgeType="Fall Through" ];
  "0012f650" -> "0012f65f" [ EdgeType="Fall Through" ];
  "0012f65f" -> "0012f68a" [ EdgeType="Conditional Jump" ];
  "0012f65f" -> "0012f667" [ EdgeType="Fall Through" ];
  "0012f667" -> "0012f679" [ EdgeType="Fall Through" ];
  "0012f679" -> "0012f681" [ EdgeType="Fall Through" ];
  "0012f681" -> "0012f4b0" [ EdgeType="Conditional Jump" ];
  "0012f681" -> "0012f68a" [ EdgeType="Fall Through" ];
  "0012f68a" -> "0012f6ab" [ EdgeType="Fall Through" ];
  "0012f6ab" -> "0012f6b3" [ EdgeType="Fall Through" ];
  "0012f6b3" -> "0012f6fc" [ EdgeType="Unconditional Jump" ];
  "0012f6b5" -> "0012f6ba" [ EdgeType="Fall Through" ];
  "0012f6ba" -> "0012f75b" [ EdgeType="Conditional Jump" ];
  "0012f6ba" -> "0012f6d1" [ EdgeType="Fall Through" ];
  "0012f6d1" -> "0012f6d6" [ EdgeType="Fall Through" ];
  "0012f6d6" -> "0012f6ec" [ EdgeType="Fall Through" ];
  "0012f6ec" -> "0012f6fc" [ EdgeType="Fall Through" ];
  "0012f6fc" -> "0012f4b0" [ EdgeType="Unconditional Jump" ];
  "0012f707" -> "0012f344" [ EdgeType="Unconditional Jump" ];
  "0012f711" -> "0012f724" [ EdgeType="Fall Through" ];
  "0012f724" -> "0012f307" [ EdgeType="Unconditional Jump" ];
  "0012f729" -> "0012f74a" [ EdgeType="Fall Through" ];
  "0012f74a" -> "0012f4d6" [ EdgeType="Unconditional Jump" ];
  "0012f74f" -> "0012f75b" [ EdgeType="Fall Through" ];
  "0012f75b" -> "0012f762" [ EdgeType="Fall Through" ];
  "0012f762" -> "0012f76f" [ EdgeType="Fall Through" ];
  "0012f76f" -> "0012f6fc" [ EdgeType="Unconditional Jump" ];
  "0012f771" -> "0012f776" [ EdgeType="Fall Through" ];
  "0012f776" -> "0012f77d" [ EdgeType="Fall Through" ];
  "0012f77d" -> "0012f798" [ EdgeType="Fall Through" ];
  "0012f798" -> "0012f7ad" [ EdgeType="Fall Through" ];
  "0012f7ad" -> "0012f480" [ EdgeType="Unconditional Jump" ];
  "0012f7b2" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f7c1" -> "0012f7c9" [ EdgeType="Fall Through" ];
  "0012f7c9" -> "0012f650" [ EdgeType="Conditional Jump" ];
  "0012f7c9" -> "0012f7d1" [ EdgeType="Fall Through" ];
  "0012f7d1" -> "0012f7d9" [ EdgeType="Fall Through" ];
  "0012f7d9" -> "0012f650" [ EdgeType="Unconditional Jump" ];
  "0012f7ec" -> "0012f61f" [ EdgeType="Conditional Jump" ];
  "0012f7ec" -> "0012f7ff" [ EdgeType="Fall Through" ];
  "0012f810" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f81f" -> "0012f130" [ EdgeType="Unconditional Jump" ];
  "0012f82e" -> "0012f841" [ EdgeType="Fall Through" ];
  "0012f84e" -> "0012f861" [ EdgeType="Fall Through" ];
}
