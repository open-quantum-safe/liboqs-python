# Installing liboqs-python on Windows

This guide provides simplified installation steps for `liboqs-python` and its C-library dependency, `liboqs` on Windows.


### Prerequisites
Before starting, ensure you have the following installed:
* **Python 3.10+** (Ensure "Add Python to PATH" was checked during installation)
* **Git** 


### Step 1: Install the C++ Build Environment

We need a C++ compiler and CMake.

1. Download **Build Tools for Visual Studio 2026** (`vs_BuildTools.exe`) from the official Microsoft download page (scroll to the bottom, under "All Downloads" -> "Tools for Visual Studio").
   * Recommended: Click this link to download the Build Tools: https://aka.ms/vs/stable/vs_BuildTools.exe   
   * Visual Studio Download: https://visualstudio.microsoft.com/downloads    
2. Run the installer (`vs_BuildTools.exe`).
3. Under the **Workloads** tab, check **ONLY** one option:
   * **Desktop development with C++**
4. On the right-side **Installation details** panel, uncheck unnecessary components to save space, but ensure these three are checked:
   * **MSVC v14x - VS C++ x64/x86 build tools**
   * **Windows 11 SDK**
   * **C++ CMake tools for Windows**
5. Click **Install**. You can close the installer once it finishes.


### Step 2: Compile liboqs (v0.14.0)  

Python requires a dynamic library (`.dll`) to interact with C code. We must compile `liboqs` specifically to generate this file.

1. Click the Windows Start menu, search for **"Developer Command Prompt for VS"**, right-click it, and select **Run as administrator**.    
2. The prompt defaults to `C:\Windows\System32`. Do not clone code here. Move to a safe root directory:
   ```cmd
   cd /d C:\
   ```
   ```cmd
   mkdir dev
   ```
   ```cmd
   cd dev
   ```
3. Run the following commands sequentially to clone and compile:
   1. Clone the 0.14.0 version:
   ```cmd 
   git clone --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git
   ```
   ```cmd
   cd liboqs
   ```
   2. Configure CMake:   
   ```cmd
   cmake -S . -B build -DBUILD_SHARED_LIBS=ON
   ```
   3. Build the project:   
   ```cmd
   cmake --build build --config Release
    ```
   4. Install to the default Windows system directory:  
   ```cmd
   cmake --install build
   ```
   *The compiled files are now located in `C:\Program Files (x86)\liboqs`.*


### Step 3: Configure Windows Environment Variables

Python needs to know where the compiled `.dll` file is located.

1. Open Windows Search and type **"Edit the system environment variables"**, then hit Enter.
2. Click the **Environment Variables** button at the bottom right.
3. Under the **System variables** section (the bottom list), find and double-click the variable named **`Path`**.
4. Click **New** and paste the exact path to the `bin` folder:
   ```text
   C:\Program Files (x86)\liboqs\bin
   ```
5. Click **OK** on all three windows to save the settings.


### Step 4: Install liboqs-python (v0.14.1)

For the new environment variables to take effect, you must completely close any open terminals or IDEs before proceeding.  

1. Open a fresh, standard Command Prompt or your Python virtual environment.
2. Install the Python wrapper:
   ```cmd
   pip install liboqs-python
   ```


### Step 5: Verify the Installation

Create a test script (e.g., `test_pqc.py`) and run the following code to ensure the Python wrapper is successfully communicating with the underlying C library.

```python
import oqs
print("liboqs version:", oqs.oqs_version())
print("liboqs-python version:", oqs.oqs_python_version())
print("KEM supported in liboqs:")
print(oqs.get_supported_kem_mechanisms()[:3])
```
---