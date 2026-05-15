# Installing liboqs-python on Raspberry Pi

This guide provides simplified installation steps for `liboqs-python` and its C-library dependency, `liboqs` on Raspberry Pi.


### Step 1: Prepare the System and Base Dependencies

This step ensures we have the correct build tools (`cmake`, `ninja`) and the essential development libraries required for cryptographic algorithms (OpenSSL headers).

1. Update the system package list
```bash
sudo apt update
```
```bash
sudo apt upgrade -y
```
2. Install build tools and dependencies   
```bash
sudo apt install -y build-essential cmake ninja-build libssl-dev git python3-pip python3-venv
```


### Step 2: Compile and Install liboqs (v0.14.0)
`liboqs-python` is just a wrapper; it heavily relies on the `.so` dynamic library existing in the system. We must compile the C library correctly first.

1. Return to the home directory
```bash
cd ~
```
2. Clone the specific 0.14.0 version source code
```bash
git clone --branch 0.14.0 https://github.com/open-quantum-safe/liboqs.git
```
```bash
cd liboqs
```
3. Create a build directory
```bash
mkdir build && cd build
```
4. Configure the project using CMake  
```bash
cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
```
5. Compile and install to the system path
```bash
ninja
```
```bash
sudo ninja install
```
6. Refresh the system's shared library cache    
```bash
sudo ldconfig
```  
Verification: Run `ls -l /usr/local/lib/liboqs*` to ensure you can see `liboqs.so.0.14.0`.


### Step 3: Configure the Python Virtual Environment
To avoid polluting the Raspberry Pi's system-level Python environment, we use a virtual environment for isolation.

1. Return to the home directory
```bash
cd ~
```
2. Create a virtual environment named oqs_env
```bash
python3 -m venv oqs_env
```
3. Activate the virtual environment (Once successful, your command line prefix will show "(oqs_env)")
```bash
source oqs_env/bin/activate
```
4. Update base packages (Optional but recommended)
```bash
pip install --upgrade pip setuptools
```


### Step 4: Install liboqs-python
You must compile and install from the local source code while the virtual environment is **activated**. This ensures it perfectly binds to the 0.14.0 C library you just compiled.

0. Ensure the virtual environment is ACTIVATED
```bash
source oqs_env/bin/activate
```
1. Return to the home directory
```bash
cd ~
```
2. Clone the Python wrapper source code
```bash
git clone https://github.com/open-quantum-safe/liboqs-python.git
```
```bash
cd liboqs-python
```
3. Compile and install locally   
```bash
pip install . --no-cache-dir
```

---

### Step 5: Final Verification
Run the following Python one-liner directly in the terminal to test your installation:

```bash
python3 -c "import oqs; print('\n Installation Successful!\nCurrent liboqs and liboqs-python version:', oqs.oqs_version(), oqs.oqs_python_version()); print('Supported KEM algorithms:', oqs.get_enabled_kem_mechanisms()[:3])"
```
---