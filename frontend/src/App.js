import React, { useState, useEffect, useRef } from 'react';
import { AlertCircle, CheckCircle, Code, Terminal, Info, Moon, Sun, Copy, Check } from 'lucide-react';

const AssemblerDisassemblerUI = () => {
  const [code, setCode] = useState('');
  const [disassembled, setDisassembled] = useState([]);
  const [initialState, setInitialState] = useState(null);
  const [hoveredInstruction, setHoveredInstruction] = useState(null);
  const [status, setStatus] = useState('Disconnected');
  const [error, setError] = useState('');
  const [darkMode, setDarkMode] = useState(false);
  const [copied, setCopied] = useState(false);
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
        } else {
          setError('Unexpected data format from server');
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
      ws.current.send(JSON.stringify({ action: 'process', code: newCode }));
    }
  };

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };

  const RegisterState = ({ state, title }) => (
    <div className="mt-2">
      <h4 className="font-semibold text-sm">{title}</h4>
      <div className="grid grid-cols-4 gap-1 text-xs">
        {Object.entries(state).map(([reg, value]) => (
          <div key={reg} className="bg-gray-100 dark:bg-gray-700 p-1 rounded">
            <span className="font-mono">{reg}: 0x{value.toString(16).padStart(16, '0')}</span>
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div className={`min-h-screen ${darkMode ? 'dark bg-gray-900 text-gray-100' : 'bg-gray-100 text-gray-900'} p-4 font-sans transition-colors duration-200`}>
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold flex items-center">
            <Terminal className="mr-2" /> Assembler/Disassembler
          </h1>
          <button 
            onClick={toggleDarkMode} 
            className="p-2 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors duration-200"
          >
            {darkMode ? <Sun /> : <Moon />}
          </button>
        </div>
        
        <div className={`mb-4 p-2 rounded-md flex items-center ${status === 'Connected' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'}`}>
          {status === 'Connected' ? <CheckCircle className="mr-2" /> : <AlertCircle className="mr-2" />}
          Status: {status}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg">
            <h2 className="text-xl font-semibold mb-2 flex items-center">
              <Code className="mr-2" /> Input
            </h2>
            <textarea
              value={code}
              onChange={handleCodeChange}
              className="w-full h-64 p-2 bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-colors duration-200"
              placeholder="Enter assembly code or opcodes"
            />
          </div>

          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg">
            <h2 className="text-xl font-semibold mb-2 flex items-center">
              <Terminal className="mr-2" /> Output
            </h2>
            <div className="h-64 overflow-y-auto bg-gray-50 dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md p-2">
              {disassembled.map((instr, index) => (
                <div 
                  key={index} 
                  className="py-1 px-2 hover:bg-gray-200 dark:hover:bg-gray-600 cursor-pointer rounded transition-colors duration-200"
                  onMouseEnter={() => setHoveredInstruction(instr)}
                  onMouseLeave={() => setHoveredInstruction(null)}
                >
                  <div className="flex justify-between">
                    <span>{instr.mnemonic} {instr.op_str}</span>
                    <span className="text-gray-500 dark:text-gray-400">{instr.bytes}</span>
                  </div>
                  {hoveredInstruction === instr && (
                    <div className="mt-2 text-sm">
                      <p><strong>Address:</strong> {instr.address}</p>
                      <RegisterState state={instr.before} title="Register State Before" />
                      <RegisterState state={instr.after} title="Register State After" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-2 bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 rounded-md flex items-center">
            <AlertCircle className="mr-2" />
            {error}
          </div>
        )}

        {initialState && (
          <div className="mt-6 bg-white dark:bg-gray-800 p-4 rounded-lg shadow-lg">
            <h2 className="text-xl font-semibold mb-2 flex items-center">
              <Info className="mr-2" /> Initial Register State
            </h2>
            <RegisterState state={initialState} title="Initial State" />
          </div>
        )}
      </div>
    </div>
  );
};

export default AssemblerDisassemblerUI;