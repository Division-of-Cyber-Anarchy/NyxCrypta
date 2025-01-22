import sys
import pytest
from io import StringIO

def run_tests():
    """
    Run all tests and return status (True/False) and error messages if any
    """
    # Capture the test output
    captured_output = StringIO()
    status = True
    error_messages = []

    try:
        # Run pytest and capture the result
        pytest_exit_code = pytest.main(['nyxcrypta/tests/', '-v', '--capture=sys'])
        
        # Check pytest exit code
        # 0 = All tests passed
        # 1 = Tests failed
        # 2 = Test execution was interrupted
        # 3 = Internal error
        # 4 = pytest command line usage error
        # 5 = No tests collected
        if pytest_exit_code != 0:
            status = False
            error_messages.append(f"Tests failed with exit code: {pytest_exit_code}")
            
    except Exception as e:
        status = False
        error_messages.append(f"Error running tests: {str(e)}")

    return {
        'success': 1 if status else 0,
        'errors': error_messages if error_messages else None
    }

def main():
    result = run_tests()
    if result['success']:
        print("All tests passed successfully")
        sys.exit(0)
    else:
        print("Tests failed!")
        if result['errors']:
            for error in result['errors']:
                print(f"Error: {error}")
        sys.exit(1)

if __name__ == '__main__':
    main()