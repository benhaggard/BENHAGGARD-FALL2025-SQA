"""
Fuzzing Module for MLForensics Project
Tests 5 selected methods with various inputs to find bugs
"""

import sys
import os
import random
import string

# Add the project directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import modules to test
import py_parser
import lint_engine
import constants

def generate_random_string(length=10):
    """Generate random string for fuzzing"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_random_path():
    """Generate random file paths"""
    return os.path.join(generate_random_string(5), generate_random_string(8) + '.py')

def generate_random_python_code():
    """Generate random Python code snippets"""
    templates = [
        "import {}\n",
        "def {}(): pass\n",
        "{} = {}\n",
        "class {}:\n    pass\n",
        "# {}\n"
    ]
    return random.choice(templates).format(generate_random_string())


# ==============================================================================
# FUZZ TEST 1: py_parser.checkIfParsablePython()
# ==============================================================================
def fuzz_checkIfParsablePython():
    """
    Fuzz test for checkIfParsablePython function
    Tests with: invalid paths, non-existent files, empty files, malformed Python
    """
    print("\n" + "="*70)
    print("FUZZ TEST 1: py_parser.checkIfParsablePython()")
    print("="*70)
    
    test_cases = []
    bugs_found = []
    
    # Test Case 1: Non-existent file
    try:
        result = py_parser.checkIfParsablePython("/nonexistent/file.py")
        test_cases.append(("Non-existent file", "PASS", None))
    except Exception as e:
        bugs_found.append(("Non-existent file", type(e).__name__, str(e)))
        test_cases.append(("Non-existent file", "FAIL", str(e)))
    
    # Test Case 2: Empty string path
    try:
        result = py_parser.checkIfParsablePython("")
        test_cases.append(("Empty string path", "PASS", None))
    except Exception as e:
        bugs_found.append(("Empty string path", type(e).__name__, str(e)))
        test_cases.append(("Empty string path", "FAIL", str(e)))
    
    # Test Case 3: None as input
    try:
        result = py_parser.checkIfParsablePython(None)
        test_cases.append(("None input", "PASS", None))
    except Exception as e:
        bugs_found.append(("None input", type(e).__name__, str(e)))
        test_cases.append(("None input", "FAIL", str(e)))
    
    # Test Case 4: Random garbage path
    for i in range(5):
        garbage_path = generate_random_string(50)
        try:
            result = py_parser.checkIfParsablePython(garbage_path)
            test_cases.append((f"Garbage path {i+1}", "PASS", None))
        except Exception as e:
            bugs_found.append((f"Garbage path {i+1}", type(e).__name__, str(e)))
            test_cases.append((f"Garbage path {i+1}", "FAIL", str(e)))
    
    # Test Case 5: Very long path
    try:
        long_path = "/" + "/".join([generate_random_string(50) for _ in range(10)]) + ".py"
        result = py_parser.checkIfParsablePython(long_path)
        test_cases.append(("Very long path", "PASS", None))
    except Exception as e:
        bugs_found.append(("Very long path", type(e).__name__, str(e)))
        test_cases.append(("Very long path", "FAIL", str(e)))
    
    print_test_results(test_cases, bugs_found)
    return bugs_found


# ==============================================================================
# FUZZ TEST 2: py_parser.getPythonParseObject()
# ==============================================================================
def fuzz_getPythonParseObject():
    """
    Fuzz test for getPythonParseObject function
    Tests with: invalid files, non-Python files, corrupted content
    """
    print("\n" + "="*70)
    print("FUZZ TEST 2: py_parser.getPythonParseObject()")
    print("="*70)
    
    test_cases = []
    bugs_found = []
    
    # Create a temporary test file
    temp_file = "temp_fuzz_test.py"
    
    # Test Case 1: Empty file
    try:
        with open(temp_file, 'w') as f:
            f.write("")
        result = py_parser.getPythonParseObject(temp_file)
        test_cases.append(("Empty file", "PASS", None))
    except Exception as e:
        bugs_found.append(("Empty file", type(e).__name__, str(e)))
        test_cases.append(("Empty file", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 2: Invalid Python syntax
    try:
        with open(temp_file, 'w') as f:
            f.write("def ((():\n    pass")
        result = py_parser.getPythonParseObject(temp_file)
        test_cases.append(("Invalid syntax", "PASS", None))
    except Exception as e:
        bugs_found.append(("Invalid syntax", type(e).__name__, str(e)))
        test_cases.append(("Invalid syntax", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 3: Random binary data
    try:
        with open(temp_file, 'wb') as f:
            f.write(os.urandom(100))
        result = py_parser.getPythonParseObject(temp_file)
        test_cases.append(("Binary data", "PASS", None))
    except Exception as e:
        bugs_found.append(("Binary data", type(e).__name__, str(e)))
        test_cases.append(("Binary data", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 4: Extremely large file simulation
    try:
        with open(temp_file, 'w') as f:
            f.write("# " + "x" * 10000 + "\n")
        result = py_parser.getPythonParseObject(temp_file)
        test_cases.append(("Large file", "PASS", None))
    except Exception as e:
        bugs_found.append(("Large file", type(e).__name__, str(e)))
        test_cases.append(("Large file", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 5: Non-existent file
    try:
        result = py_parser.getPythonParseObject("nonexistent_file.py")
        test_cases.append(("Non-existent file", "PASS", None))
    except Exception as e:
        bugs_found.append(("Non-existent file", type(e).__name__, str(e)))
        test_cases.append(("Non-existent file", "FAIL", str(e)))
    
    print_test_results(test_cases, bugs_found)
    return bugs_found


# ==============================================================================
# FUZZ TEST 3: lint_engine.getDataLoadCount()
# ==============================================================================
def fuzz_getDataLoadCount():
    """
    Fuzz test for getDataLoadCount function
    Tests with: invalid files, empty files, files with unexpected content
    """
    print("\n" + "="*70)
    print("FUZZ TEST 3: lint_engine.getDataLoadCount()")
    print("="*70)
    
    test_cases = []
    bugs_found = []
    
    temp_file = "temp_fuzz_test.py"
    
    # Test Case 1: Empty file
    try:
        with open(temp_file, 'w') as f:
            f.write("")
        result = lint_engine.getDataLoadCount(temp_file)
        test_cases.append(("Empty file", "PASS", None))
    except Exception as e:
        bugs_found.append(("Empty file", type(e).__name__, str(e)))
        test_cases.append(("Empty file", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 2: File with only comments
    try:
        with open(temp_file, 'w') as f:
            f.write("# This is a comment\n# Another comment\n")
        result = lint_engine.getDataLoadCount(temp_file)
        test_cases.append(("Only comments", "PASS", None))
    except Exception as e:
        bugs_found.append(("Only comments", type(e).__name__, str(e)))
        test_cases.append(("Only comments", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 3: File with syntax errors
    try:
        with open(temp_file, 'w') as f:
            f.write("def broken(:\n    pass\n")
        result = lint_engine.getDataLoadCount(temp_file)
        test_cases.append(("Syntax errors", "PASS", None))
    except Exception as e:
        bugs_found.append(("Syntax errors", type(e).__name__, str(e)))
        test_cases.append(("Syntax errors", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 4: Random valid Python code
    for i in range(3):
        try:
            with open(temp_file, 'w') as f:
                f.write(generate_random_python_code())
            result = lint_engine.getDataLoadCount(temp_file)
            test_cases.append((f"Random code {i+1}", "PASS", None))
        except Exception as e:
            bugs_found.append((f"Random code {i+1}", type(e).__name__, str(e)))
            test_cases.append((f"Random code {i+1}", "FAIL", str(e)))
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    # Test Case 5: Non-existent file
    try:
        result = lint_engine.getDataLoadCount("/fake/path/file.py")
        test_cases.append(("Non-existent file", "PASS", None))
    except Exception as e:
        bugs_found.append(("Non-existent file", type(e).__name__, str(e)))
        test_cases.append(("Non-existent file", "FAIL", str(e)))
    
    print_test_results(test_cases, bugs_found)
    return bugs_found


# ==============================================================================
# FUZZ TEST 4: lint_engine.getModelLoadCounta()
# ==============================================================================
def fuzz_getModelLoadCounta():
    """
    Fuzz test for getModelLoadCounta function
    """
    print("\n" + "="*70)
    print("FUZZ TEST 4: lint_engine.getModelLoadCounta()")
    print("="*70)
    
    test_cases = []
    bugs_found = []
    
    temp_file = "temp_fuzz_test.py"
    
    # Test Case 1: Valid Python file with no model loading
    try:
        with open(temp_file, 'w') as f:
            f.write("x = 1\ny = 2\nprint(x + y)\n")
        result = lint_engine.getModelLoadCounta(temp_file)
        test_cases.append(("Valid file no model", "PASS", None))
    except Exception as e:
        bugs_found.append(("Valid file no model", type(e).__name__, str(e)))
        test_cases.append(("Valid file no model", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 2: File with Unicode characters
    try:
        with open(temp_file, 'w', encoding='utf-8') as f:
            f.write("# 你好世界\n# Здравствуй мир\nx = 'test'\n")
        result = lint_engine.getModelLoadCounta(temp_file)
        test_cases.append(("Unicode content", "PASS", None))
    except Exception as e:
        bugs_found.append(("Unicode content", type(e).__name__, str(e)))
        test_cases.append(("Unicode content", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 3-5: Random edge cases
    for i in range(3):
        try:
            with open(temp_file, 'w') as f:
                content = "\n".join([generate_random_python_code() for _ in range(random.randint(1, 10))])
                f.write(content)
            result = lint_engine.getModelLoadCounta(temp_file)
            test_cases.append((f"Edge case {i+1}", "PASS", None))
        except Exception as e:
            bugs_found.append((f"Edge case {i+1}", type(e).__name__, str(e)))
            test_cases.append((f"Edge case {i+1}", "FAIL", str(e)))
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    print_test_results(test_cases, bugs_found)
    return bugs_found


# ==============================================================================
# FUZZ TEST 5: py_parser.getPythonAtrributeFuncs()
# ==============================================================================
def fuzz_getPythonAttributeFuncs():
    """
    Fuzz test for getPythonAtrributeFuncs function
    """
    print("\n" + "="*70)
    print("FUZZ TEST 5: py_parser.getPythonAtrributeFuncs()")
    print("="*70)
    
    test_cases = []
    bugs_found = []
    
    temp_file = "temp_fuzz_test.py"
    
    # Test Case 1: Empty AST
    try:
        with open(temp_file, 'w') as f:
            f.write("")
        tree = py_parser.getPythonParseObject(temp_file)
        result = py_parser.getPythonAtrributeFuncs(tree)
        test_cases.append(("Empty AST", "PASS", None))
    except Exception as e:
        bugs_found.append(("Empty AST", type(e).__name__, str(e)))
        test_cases.append(("Empty AST", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 2: Complex nested structures
    try:
        with open(temp_file, 'w') as f:
            f.write("class A:\n    def method(self):\n        self.obj.func()\n")
        tree = py_parser.getPythonParseObject(temp_file)
        result = py_parser.getPythonAtrributeFuncs(tree)
        test_cases.append(("Nested structures", "PASS", None))
    except Exception as e:
        bugs_found.append(("Nested structures", type(e).__name__, str(e)))
        test_cases.append(("Nested structures", "FAIL", str(e)))
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)
    
    # Test Case 3-5: Random code patterns
    for i in range(3):
        try:
            with open(temp_file, 'w') as f:
                f.write(f"obj{i}.method{i}()\n")
            tree = py_parser.getPythonParseObject(temp_file)
            result = py_parser.getPythonAtrributeFuncs(tree)
            test_cases.append((f"Pattern {i+1}", "PASS", None))
        except Exception as e:
            bugs_found.append((f"Pattern {i+1}", type(e).__name__, str(e)))
            test_cases.append((f"Pattern {i+1}", "FAIL", str(e)))
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)
    
    print_test_results(test_cases, bugs_found)
    return bugs_found


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================
def print_test_results(test_cases, bugs_found):
    """Print formatted test results"""
    print(f"\nTest Results: {len(test_cases)} tests run")
    passed = sum(1 for tc in test_cases if tc[1] == "PASS")
    failed = len(test_cases) - passed
    print(f"  ✓ Passed: {passed}")
    print(f"  ✗ Failed: {failed}")
    
    if bugs_found:
        print("\nBugs/Issues Found:")
        for bug in bugs_found:
            print(f"  - {bug[0]}: {bug[1]} - {bug[2][:100]}")
    else:
        print("\n✓ No bugs found - all error handling works correctly!")


def main():
    """Main fuzzing execution"""
    print("\n" + "="*70)
    print("STARTING FUZZING TESTS FOR MLFORENSICS PROJECT")
    print("="*70)
    print("Testing 5 key methods with randomized inputs to discover bugs...")
    
    all_bugs = []
    
    # Run all fuzz tests
    all_bugs.extend(fuzz_checkIfParsablePython())
    all_bugs.extend(fuzz_getPythonParseObject())
    all_bugs.extend(fuzz_getDataLoadCount())
    all_bugs.extend(fuzz_getModelLoadCounta())
    all_bugs.extend(fuzz_getPythonAttributeFuncs())
    
    # Final summary
    print("\n" + "="*70)
    print("FUZZING SUMMARY")
    print("="*70)
    print(f"Total bugs/issues discovered: {len(all_bugs)}")
    
    if all_bugs:
        print("\nDetailed Bug Report:")
        for i, bug in enumerate(all_bugs, 1):
            print(f"\n{i}. Test: {bug[0]}")
            print(f"   Error Type: {bug[1]}")
            print(f"   Details: {bug[2][:200]}")
    else:
        print("\n✓ No bugs found! All methods handle edge cases correctly.")
    
    print("\n" + "="*70)
    return len(all_bugs)


if __name__ == "__main__":
    exit_code = main()
    sys.exit(0 if exit_code == 0 else 1)
