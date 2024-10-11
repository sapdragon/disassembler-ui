# Web-based x86/x64 Disassembler/Assembler and Emulator

[![Demo](images/preview.gif)](images/preview.gif)

This project provides a web-based application for disassembling, assembling, and *emulating* x86/x64 code. Built using React (frontend), Python (backend), and Unicorn Engine for emulation, 

## Features

* **Disassembly:** Converts machine code into human-readable assembly language. Supports both x86 and x64 architectures.
* **Assembly:** Converts assembly language into machine code.
* **Emulation (powered by Unicorn Engine):** Execute code step-by-step and inspect register and flag values after each instruction. Includes stack support.
* **Interactive Interface:** User-friendly web interface built with React, facilitating easy navigation and code manipulation.
* **Register and Flag Visualization:**  Real-time display of register and flag values during emulation.
* **Stack Visualization:** View the state of the stack during emulation. ( Nope )
* **Cross-Platform Compatibility:** Accessible from any modern web browser, regardless of operating system.


## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/your-username/your-repository-name.git
```

2. **Backend Setup (Python):**

Navigate to the project's root directory and install the required Python dependencies, including Unicorn Engine:

```bash
pip install -r requirements.txt
```

3. **Frontend Setup (React):**

Navigate to the `frontend` directory and install the necessary Node.js packages:

```bash
cd frontend
npm install
```

4. **Running the Application:**

* **Backend:** Start the Python backend server (replace with your specific command):

```bash
python server.py
```

* **Frontend:** Start the React development server:

```bash
npm start
```

The application should now be accessible in your browser (usually `http://localhost:3000`).


## Usage

1. **Input:** Provide machine code or assembly code.
5. **Output:** View the results in the designated output areas.


## Contributing

Contributions are welcome!
