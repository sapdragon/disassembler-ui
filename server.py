import asyncio
import websockets
import json
from capstone import *
from keystone import *
import logging
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('assembler_disassembler_server')

ARCHITECTURES = {
    'x86_64': {
        'cs': (CS_ARCH_X86, CS_MODE_64),
        'ks': (KS_ARCH_X86, KS_MODE_64),
        'uc': (UC_ARCH_X86, UC_MODE_64),
        'regs':
                 [register for register in range(UC_X86_REG_XMM0, UC_X86_REG_XMM0+16)] + 
                 [
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
            UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
            UC_X86_REG_RIP, UC_X86_REG_EFLAGS
        ],
        'reg_names': [
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
            'rip', 'eflags'
        ]
    },
    'arm': {
        'cs': (CS_ARCH_ARM, CS_MODE_ARM),
        'ks': (KS_ARCH_ARM, KS_MODE_ARM),
        'uc': (UC_ARCH_ARM, UC_MODE_ARM),
        'regs': [
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_CPSR
        ],
        'reg_names': [
            'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
            'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc',
            'cpsr'
        ]
    },
    'mips': {
        'cs': (CS_ARCH_MIPS, CS_MODE_MIPS32),
        'ks': (KS_ARCH_MIPS, KS_MODE_MIPS32),
        'uc': (UC_ARCH_MIPS, UC_MODE_MIPS32),
        'regs': [
            UC_MIPS_REG_0, UC_MIPS_REG_1, UC_MIPS_REG_2, UC_MIPS_REG_3,
            UC_MIPS_REG_4, UC_MIPS_REG_5, UC_MIPS_REG_6, UC_MIPS_REG_7,
            UC_MIPS_REG_8, UC_MIPS_REG_9, UC_MIPS_REG_10, UC_MIPS_REG_11,
            UC_MIPS_REG_12, UC_MIPS_REG_13, UC_MIPS_REG_14, UC_MIPS_REG_15,
            UC_MIPS_REG_PC
        ],
        'reg_names': [
            'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
            't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
            'pc'
        ]
    }
}

def is_hex(s):
    return all(c in '0123456789ABCDEFabcdef ' for c in s)

class Emulator:
    def __init__(self, arch):
        self.arch = ARCHITECTURES[arch]
        self.mu = Uc(self.arch['uc'][0], self.arch['uc'][1])
        self.memory_base = 0x400000
        self.memory_size = 2 * 1024 * 1024  # 2 MB
        self.stack_size = 2 * 1024 * 1024  # 2 MB
        self.stack_base = self.memory_base + self.memory_size + self.stack_size

        # Map memory for code
        self.mu.mem_map(self.memory_base, self.memory_size)
        
        # Map memory for stack
        self.mu.mem_map(self.memory_base + self.memory_size, self.stack_size)
        
        self.reset_registers()

    def reset_registers(self):
        for reg in self.arch['regs']:
            self.mu.reg_write(reg, 0)
        if 'x86_64' in self.arch['uc']:
            self.mu.reg_write(UC_X86_REG_RSP, self.stack_base)

    def get_register_state(self):
        return {name: self.mu.reg_read(reg) for name, reg in zip(self.arch['reg_names'], self.arch['regs'])}

    def emulate(self, code):
        self.mu.mem_write(self.memory_base, code)
        try:
            self.mu.emu_start(self.memory_base, self.memory_base + len(code))
        except UcError as e:
            logger.error(f"Emulation error: {e}")
            raise

emulators = {arch: Emulator(arch) for arch in ARCHITECTURES}

def detect_input_type(code):
    """Automatically detects input type (asm, hex, or shellcode)."""
    if all(c in '0123456789abcdefABCDEF \n' for c in code.strip()):
        if any(len(part.strip()) > 2 for part in code.split()):  
            return 'hex'
        else:
            return 'shellcode'
    else:
        return 'asm'

def process_code(code, arch, emulation_enabled):
    """Processes code based on detected input type."""
    input_type = detect_input_type(code)

    if input_type == 'hex': # hex like 0x90 0x90 0x90
        code = bytes.fromhex(code.replace('0x', '').replace(' ', '').replace('\n', ''))
        return disassemble_and_emulate(code, arch, emulation_enabled)
    elif input_type == 'shellcode':
        code = bytes.fromhex(code.replace('\\x', '').replace('0x', '').replace(',', '').replace(' ', '').replace('\n', ''))
        return disassemble_and_emulate(code, arch, emulation_enabled)
    else:
        return assemble_and_emulate(code, arch, emulation_enabled)

async def handle_connection(websocket, path):
    logger.info("New client connected")
    try:
        async for message in websocket:
            logger.debug(f"Received message: {message}")
            try:
                data = json.loads(message)
                code = data['code']
                arch = data.get('architecture', 'x86_64')
                emulation_enabled = data.get('emulationEnabled', True)

                result = process_code(code, arch, emulation_enabled)
                
                await websocket.send(json.dumps({"result": result}))
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {e}")
                await websocket.send(json.dumps({"error": "Invalid JSON"}))
            except ValueError as e:
                logger.error(f"Value error: {e}")
                await websocket.send(json.dumps({"error": str(e)}))
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                await websocket.send(json.dumps({"error": f"Server error: {str(e)}"}))
    except websockets.exceptions.ConnectionClosed:
        logger.info("Client disconnected")

def assemble_and_emulate(code, arch, emulation_enabled):
    try:
        ks = Ks(*ARCHITECTURES[arch]['ks'])
        encoding, count = ks.asm(code)
        if not encoding:
            raise ValueError(f"Failed to assemble: {code}")
        return disassemble_and_emulate(bytes(encoding), arch, emulation_enabled)
    except KsError as e:
        raise ValueError(f"Assembly error: {e}")

def process_shellcode(code, arch, emulation_enabled):
    try:
        # Remove common shellcode formatting
        code = code.replace('\\x', '').replace('0x', '').replace(',', '').replace(' ', '')
        shellcode_bytes = bytes.fromhex(code)
        return disassemble_and_emulate(shellcode_bytes, arch, emulation_enabled)
    except ValueError as e:
        raise ValueError(f"Invalid shellcode: {e}")

def disassemble_and_emulate(code, arch, emulation_enabled):
    try:
        if isinstance(code, str):
            code = bytes.fromhex(code.replace(' ', ''))
        
        md = Cs(*ARCHITECTURES[arch]['cs'])
        emulator = emulators[arch]
        disassembled = []
        
        if emulation_enabled:
            emulator.reset_registers()
            initial_state = emulator.get_register_state()
        else:
            initial_state = None

        for i in md.disasm(code, emulator.memory_base):
            if emulation_enabled:
                before_state = emulator.get_register_state()
                try:
                    emulator.emulate(bytes(i.bytes))
                except UcError as e:
                    logger.error(f"Emulation error at instruction {i.mnemonic} {i.op_str}: {e}")
                    raise ValueError(f"Emulation error: {e}")
                after_state = emulator.get_register_state()
            else:
                before_state = after_state = None

            disassembled.append({
                'address': f'0x{i.address:x}',
                'mnemonic': i.mnemonic,
                'op_str': i.op_str,
                'bytes': ' '.join([f'{b:02x}' for b in i.bytes]),
                'before': before_state,
                'after': after_state
            })

        return {
            'initial_state': initial_state,
            'instructions': disassembled
        }
    except CsError as e:
        raise ValueError(f"Disassembly error: {e}")

async def main():
    server = await websockets.serve(handle_connection, "localhost", 8765)
    logger.info("Server started on ws://localhost:8765")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())