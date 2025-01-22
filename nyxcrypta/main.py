import sys
import logging
from .core.crypto import NyxCrypta
from .core.security import SecurityLevel
from .cli.parser import create_parser
from .cli.commands import print_help, handle_command
from .test_runner import TestRunner

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)

    parser = create_parser()
    args = parser.parse_args()
    
    # Handle test command
    if args.command == 'test':
        runner = TestRunner()
        results = runner.run_all_tests()
        
        # Print summary
        print("\n📊 Test Summary:")
        print(f"Total tests: {results['total']}")
        print(f"Passed: {results['passed']}")
        print(f"Failed: {results['failed']}")
        
        if results['failed_tests']:
            print("\n❌ Failed Tests:")
            for test_name, error in results['failed_tests']:
                print(f"- {test_name}: {error}")
            sys.exit(1)
        else:
            print("\n✨ All tests passed successfully!")
            sys.exit(0)
    
    if not args.command:
        print("Error: No command supplied.")
        print_help()
        sys.exit(1)

    nyxcrypta = NyxCrypta(SecurityLevel(args.securitylevel))
    handle_command(args, nyxcrypta)

if __name__ == '__main__':
    main()