import React, { useState, useEffect, useRef } from 'react';
import { AlertCircle, CheckCircle, Terminal, Moon, Sun, Copy, Check, ChevronRight, ChevronDown, Cpu, Settings } from 'lucide-react';

const ARCHITECTURES = {
  'x86_64': { name: 'x86-64', value: 'x86_64' },
  'arm': { name: 'ARM', value: 'arm' },
  'mips': { name: 'MIPS', value: 'mips' },
};

const AssemblerDisassemblerUI = () => {
  const [code, setCode] = useState('');
  const [disassembled, setDisassembled] = useState([]);
  const [initialState, setInitialState] = useState(null);
  const [expandedInstruction, setExpandedInstruction] = useState(null);
  const [status, setStatus] = useState('Disconnected');
  const [error, setError] = useState('');
  const [darkMode, setDarkMode] = useState(false);
  const [copied, setCopied] = useState(false);
  const [emulationEnabled, setEmulationEnabled] = useState(true);
  const [selectedArchitecture, setSelectedArchitecture] = useState('x86_64');
  const ws = useRef(null);

  useEffect(() => {
    ws.current = new WebSocket('ws://localhost:8765');
    
    ws.current.onopen = () => {
      setStatus('Connected');
      setError('');
    };

    ws.current.onclose = () => {
      setStatus('Disconnected');
    };

    ws.current.onerror = (event) => {
      setError('WebSocket error: ' + event.message);
    };

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.error) {
          setError('Server error: ' + data.error);
        } else if (data.result && data.result.instructions) {
          setDisassembled(data.result.instructions);
          setInitialState(data.result.initial_state);
          setError('');
        }
      } catch (e) {
        setError('Error processing data: ' + e.message);
      }
    };

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, []);

  const handleCodeChange = (e) => {
    const newCode = e.target.value;
    setCode(newCode);
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({ 
        action: 'process', 
        code: newCode, 
        architecture: selectedArchitecture,
        emulationEnabled: emulationEnabled,
      }));
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
      .then(() => {
        console.log('Text copied to clipboard');
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      })
      .catch(err => {
        console.error('Failed to copy: ', err);
      });
  };

  const handleArchitectureChange = (e) => {
    const newArch = e.target.value;
    setSelectedArchitecture(newArch);
  
    setDisassembled([]);
    setInitialState(null);
    setError('');
    
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({ 
        action: 'process', 
        code: code, 
        architecture: newArch,
        emulationEnabled: emulationEnabled,
      }));
    }
  };

  const handleEmulationChange = (e) => {
    const newEmulationEnabled = e.target.checked;
    setEmulationEnabled(newEmulationEnabled);

    setDisassembled([]);
    setInitialState(null);
    setError('');

    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({ 
        action: 'process', 
        code: code, 
        architecture: selectedArchitecture,
        emulationEnabled: newEmulationEnabled,
      }));
    }
  };

  const RegisterState = ({ state, title }) => (
    <div className="space-y-2">
      <h3 className="text-lg font-medium opacity-80">{title}</h3>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {Object.entries(state).map(([reg, value]) => (
          <div key={reg} className="stats shadow-lg bg-base-200">
            <div className="stat p-2">
              <div className="stat-title text-xs">{reg}</div>
              <div className="stat-value text-sm font-mono">
                0x{value.toString(16).padStart(16, '0')}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div data-theme={darkMode ? 'dark' : 'light'} className="min-h-screen bg-base-100">
      <div className="container mx-auto p-4">
        {/* Navbar */}
        <div className="navbar bg-base-200 rounded-box mb-4">
          <div className="flex-1">
            <Terminal className="w-6 h-6 mr-2" />
            <span className="text-xl font-bold">Assembler/Disassembler</span>
          </div>
          <div className="flex-none gap-2">
            <div className={`badge badge-lg gap-2 ${
              status === 'Connected' ? 'badge-success' : 'badge-error'
            }`}>
              {status === 'Connected' ? 
                <CheckCircle className="w-4 h-4" /> : 
                <AlertCircle className="w-4 h-4" />
              }
              {status}
            </div>
            <button 
              className="btn btn-circle btn-ghost"
              onClick={() => setDarkMode(!darkMode)}
            >
              {darkMode ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Settings */}
        <div className="card bg-base-200 shadow-xl mb-4">
          <div className="card-body">
            <h2 className="card-title">
              <Settings className="w-5 h-5" />
              Settings
            </h2>
            <div className="flex flex-wrap gap-4">
              <div className="form-control">
                <label className="label cursor-pointer">
                  <span className="label-text mr-2">Emulation</span> 
                  <input 
                    type="checkbox" 
                    className="toggle toggle-primary"
                    checked={emulationEnabled}
                    onChange={handleEmulationChange}
                  />
                </label>
              </div>
              <div className="form-control">
                <label className="label">
                  <span className="label-text">Architecture</span>
                </label>
                <select 
                  className="select select-bordered w-full max-w-xs"
                  value={selectedArchitecture}
                  onChange={handleArchitectureChange}
                >
                  {Object.entries(ARCHITECTURES).map(([key, arch]) => (
                    <option key={key} value={arch.value}>{arch.name}</option>
                  ))}
                </select>
              </div>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-2 gap-4">
          {/* Input Section */}
          <div className="card bg-base-200 shadow-xl">
            <div className="card-body">
              <h2 className="card-title">
                <Terminal className="w-5 h-5" />
                Input Code
              </h2>
              <textarea
                value={code}
                onChange={handleCodeChange}
                className="textarea textarea-bordered font-mono h-[400px] bg-base-100"
                placeholder={
                  "Enter your assembly / machine code / hex bytes here.\n"  +
                  "Example:\n" +
                  "mov rax, 0x1234\n" + 
                  "add rax, 0x5678\n" +
                  "sub rax, 0x9abc"
                }
              />
            </div>
          </div>

          {/* Output Section */}
          <div className="card bg-base-200 shadow-xl">
            <div className="card-body">
              <h2 className="card-title">
                <Cpu className="w-5 h-5" />
                Disassembled Code
              </h2>
              <div className="h-[400px] overflow-y-auto space-y-2">
                {disassembled.map((instruction, index) => (
                  <div key={index} className="collapse bg-base-100">
                    <input 
                      type="checkbox" 
                      checked={expandedInstruction === instruction}
                      onChange={() => setExpandedInstruction(expandedInstruction === instruction ? null : instruction)}
                    />
                    <div className="collapse-title font-mono text-sm flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        {expandedInstruction === instruction ? 
                          <ChevronDown className="w-4 h-4" /> : 
                          <ChevronRight className="w-4 h-4" />
                        }
                        <span>{instruction.mnemonic} <span className="text-primary">{instruction.op_str}</span></span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="opacity-50 text-xs">{instruction.bytes}</span>
                        <button 
                          className="btn btn-ghost btn-xs"
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(`${instruction.mnemonic} ${instruction.op_str}`);
                          }}
                        >
                          {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                    {emulationEnabled && (
                      <div className="collapse-content">
                        <p className="text-sm opacity-70 mb-4">
                          Address: {instruction.address}
                        </p>
                        <RegisterState state={instruction.before} title="Before" />
                        <div className="divider"></div>
                        <RegisterState state={instruction.after} title="After" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="alert alert-error shadow-lg mt-4">
            <AlertCircle className="w-6 h-6" />
            <span>{error}</span>
          </div>
        )}

        {/* Initial State */}
        {emulationEnabled && initialState && (
          <div className="card bg-base-200 shadow-xl mt-4">
            <div className="card-body">
              <h2 className="card-title">Initial Register State</h2>
              <RegisterState state={initialState} title="Initial Values" />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AssemblerDisassemblerUI;