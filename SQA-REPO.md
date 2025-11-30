**Team:** BENHAGGARD  
**Repository:** https://github.com/benhaggard/BENHAGGARD-FALL2025-SQA

AI was used to help write this report as well as implement some of the project.

## Activity 1: Fuzzing 

Created `fuzz.py` - a script that automatically tests 5 Python methods with random and invalid inputs to find bugs.

### Methods Tested
1. `py_parser.checkIfParsablePython()` - Tests if files can be parsed
2. `py_parser.getPythonParseObject()` - Parses Python files
3. `lint_engine.getDataLoadCount()` - Detects data loading operations
4. `lint_engine.getModelLoadCounta()` - Detects model loading operations
5. `py_parser.getPythonAtrributeFuncs()` - Extracts function calls

### Results
- **Total bugs found:** 14 bugs
- **Test types:** Invalid file paths, None values, binary data, empty files, syntax errors
- **Main bugs discovered:**
  - FileNotFoundError when files don't exist
  - TypeError when given None input
  - UnicodeDecodeError on binary files
  - IndexError in string formatting

### How to Run
```bash
python3 fuzz.py
```

The fuzzing also runs automatically in GitHub Actions on every commit.

---

## Activity 2: Forensics Logging 

Added security logging to 5 Python methods to detect potential attacks on ML systems. Based on research from Papernot et al. on ML security attacks.

### Logging Configuration
```python
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
```

This adds timestamps and severity levels to all log messages.

### Methods Modified

**1. py_parser.getPythonParseObject() - in py_parser.py**
- Added ~50 lines of logging code
- Logs file access attempts
- Logs file metadata (size, modification time)
- Detects suspicious file access patterns
- Example log: `"DATA_LOAD_EVENT: Attempting to parse Python file: example.py"`

**2. lint_engine.getDataLoadCount() - in lint_engine.py**
- Added ~40 lines of logging code
- Tracks data loading operations
- Flags dangerous operations like pickle.load()
- Detects excessive data loading
- Example log: `"HIGH_RISK_OPERATION: pickle.load() detected - RISK: Code execution"`

**3. lint_engine.getModelLoadCounta() - in lint_engine.py**
- Added ~35 lines of logging code
- Tracks model loading operations
- Detects untrusted model sources
- Example log: `"MODEL_LOAD_EVENT: Keras model loading - RISK: Untrusted model"`

**4. lint_engine.getEnvironmentCount() - in lint_engine.py**
- Added ~30 lines of logging code
- Monitors reinforcement learning environment operations
- Detects environment manipulation
- Example log: `"RL_ENV_STEP: Environment interaction - MONITOR: Manipulation risk"`

**5. main.runFameML() - in main.py**
- Added ~45 lines of logging code
- Creates complete audit trail of analysis
- Tracks pipeline start, progress, and completion
- Example log: `"PIPELINE_START: Starting MLForensics analysis"`

### Total Changes
- **3 files modified**
- **~200 lines of logging code added**
- **25+ security log events created**

---

## Activity 3: Continuous Integration

Created `.github/workflows/ci.yml` - a GitHub Actions workflow that automatically runs tests on every code commit.
Located at https://github.com/benhaggard/BENHAGGARD-FALL2025-SQA/actions

### CI Pipeline Jobs

**1. Automated Fuzzing Tests**
- Runs fuzz.py automatically
- Discovers bugs on every push
- Uploads results as artifacts

**2. Code Quality Checks**
- Runs Pylint (code style checking)
- Runs Flake8 (PEP 8 compliance)
- Runs Bandit (security scanning)

**3. Static Analysis**
- Verifies logging is implemented
- Checks that fuzz.py exists
- Counts Python files and lines of code

**4. Integration Tests**
- Tests that modules can be imported
- Verifies basic functionality works

**5. Build Summary**
- Collects results from all jobs
- Creates summary report

### How It Works
- Runs automatically when code is pushed to GitHub
- Takes 3-5 minutes to complete
- Shows pass/fail status for each job

---

## Lessons Learned

### What Worked Well
1. **Fuzzing found real bugs** - Discovered 14 bugs we didn't know existed
2. **Logging helps security** - Can now track suspicious activity in ML code
3. **CI catches errors fast** - Found problems within minutes of committing code
4. **Automation saves time** - Tests run automatically without manual work

### Challenges Faced
1. **Indentation errors** - Python is very strict about spacing
2. **File path issues** - Had to move files to correct locations for CI
3. **YAML syntax** - GitHub Actions configuration was tricky to get right
4. **Understanding test failures** - Had to learn that fuzzing "failures" are actually successes when bugs are found

### Key Takeaways
1. Automated testing is essential for finding bugs
2. Security logging should be specific to actual threats
3. CI/CD makes development safer and faster
4. Good documentation takes time but is worth it
