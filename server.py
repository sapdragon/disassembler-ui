import asyncio
import websockets
import json
from capstone import *
from keystone import *
import logging
from unicorn import *
from unicorn.x86_const import *

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('assembler_disassembler_server')

md = Cs(CS_ARCH_X86, CS_MODE_64)
ks = Ks(KS_ARCH_X86, KS_MODE_64)

def is_hex(s):
    return all(c in '0123456789ABCDEFabcdef ' for c in s)

class X86Emulator:
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
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
        self.mu.reg_write(UC_X86_REG_RSP, self.stack_base)
        for reg in [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, 
                    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8, 
                    UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, 
                    UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15]:
            self.mu.reg_write(reg, 0)

    def get_register_state(self):
        return {
            'rax': self.mu.reg_read(UC_X86_REG_RAX),
            'rbx': self.mu.reg_read(UC_X86_REG_RBX),
            'rcx': self.mu.reg_read(UC_X86_REG_RCX),
            'rdx': self.mu.reg_read(UC_X86_REG_RDX),
            'rsi': self.mu.reg_read(UC_X86_REG_RSI),
            'rdi': self.mu.reg_read(UC_X86_REG_RDI),
            'rbp': self.mu.reg_read(UC_X86_REG_RBP),
            'rsp': self.mu.reg_read(UC_X86_REG_RSP),
            'r8': self.mu.reg_read(UC_X86_REG_R8),
            'r9': self.mu.reg_read(UC_X86_REG_R9),
            'r10': self.mu.reg_read(UC_X86_REG_R10),
            'r11': self.mu.reg_read(UC_X86_REG_R11),
            'r12': self.mu.reg_read(UC_X86_REG_R12),
            'r13': self.mu.reg_read(UC_X86_REG_R13),
            'r14': self.mu.reg_read(UC_X86_REG_R14),
            'r15': self.mu.reg_read(UC_X86_REG_R15),
            'rip': self.mu.reg_read(UC_X86_REG_RIP),
            'eflags': self.mu.reg_read(UC_X86_REG_EFLAGS),
        }

    def emulate(self, code):
        self.mu.mem_write(self.memory_base, code)
        try:
            self.mu.emu_start(self.memory_base, self.memory_base + len(code))
        except UcError as e:
            logger.error(f"Emulation error: {e}")
            raise

emulator = X86Emulator()

async def handle_connection(websocket, path):
    logger.info("New client connected")
    try:
        async for message in websocket:
            logger.debug(f"Received message: {message}")
            try:
                data = json.loads(message)
                code = data['code']
                if is_hex(code):
                    result = disassemble_and_emulate(code)
                else:
                    result = assemble_and_emulate(code)
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

def assemble_and_emulate(code):
    try:
        encoding, count = ks.asm(code)
        if not encoding:
            raise ValueError(f"Failed to assemble: {code}")
        return disassemble_and_emulate(bytes(encoding))
    except KsError as e:
        raise ValueError(f"Assembly error: {e}")

def disassemble_and_emulate(code):
    try:
        if isinstance(code, str):
            code = bytes.fromhex(code.replace(' ', ''))
        disassembled = []
        emulator.reset_registers()
        initial_state = emulator.get_register_state()

        for i in md.disasm(code, emulator.memory_base):
            before_state = emulator.get_register_state()
            try:
                emulator.emulate(bytes(i.bytes))
            except UcError as e:
                logger.error(f"Emulation error at instruction {i.mnemonic} {i.op_str}: {e}")
                raise ValueError(f"Emulation error: {e}")
            after_state = emulator.get_register_state()

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