# Version 0.10.0 - April 1, 2024

- Replaced CHANGES by
  [CHANGES.md](https://github.com/open-quantum-safe/liboqs-python/blob/main/CHANGES.md),
  as we now use Markdown format to keep track of changes in new releases
- Removed the NIST PRNG as the latter is no longer exposed by liboqs' public
  API
- liboqs is installed automatically if it is not detected at runtime

# Version 0.9.0 - October 30, 2023

- This is a maintenance release, minor deprecation fixes
- Python minimum required version is enforced to Python 3.8 in `pyproject.toml`
- To follow Python conventions, renamed in `oqs/oqs.py`:
  - `is_KEM_enabled()` -> `is_kem_enabled()`
  - `get_enabled_KEM_mechanisms()` -> `get_enabled_kem_mechanisms()`
  - `get_supported_KEM_mechanisms()` -> `get_supported_kem_mechanisms()`

# Version 0.8.0 - July 5, 2023

- This is a maintenance release, minor fixes
- Minimalistic Docker support
- Migrated installation method to `pyproject.toml`
- Removed AppVeyor and CircleCI, all continuous integration is now done via
  GitHub actions

# Version 0.7.2 - August 27, 2022

- Added library version retrieval functions:
  - `oqs_version()`
  - `oqs_python_version()`

# Version 0.7.1 - January 5, 2022

- Release numbering updated to match liboqs
- Added macOS support on CircleCI, we now support macOS & Linux (CircleCI) and
  Windows (AppVeyor)

# Version 0.4.0 - November 28, 2020

- Renamed 'master' branch to 'main'

# Version 0.3.0 - June 10, 2020

- The liboqs handle has now module-private visibility in `oqs.py` so clients
  can not access it directly; can be accessed via the new `oqs.native()`
  function
- Closing
  #7 [link](https://github.com/open-quantum-safe/liboqs-python/issues/7), all
  issues addressed
- Added AppVeyor continuous integration

# Version 0.2.1 - January 22, 2020

- Added a signature example
- Added partial support for RNGs from `<oqs/rand.h>`
- Added an RNG example

# Version 0.2.0 - October 8, 2019

- This release updates for compatibility with liboqs 0.2.0, which contains
  new/updated algorithms based on NIST Round 2 submissions.

# Version 0.1.0 - April 23, 2019

- Initial release
