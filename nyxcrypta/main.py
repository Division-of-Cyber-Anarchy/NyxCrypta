import sys
import logging
from .core.crypto import NyxCrypta
from .core.security import SecurityLevel
from .cli.parser import create_parser
from .cli.commands import print_help, handle_command
from .test_runner import run_tests

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    if len(sys.argv) == 1 or '-h' in sys.argv or '--help' in sys.argv:
        print_help()
        sys.exit(0)

    parser = create_parser()
    args = parser.parse_args()
    
    # Handle test command
    if args.command == 'test':
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
    
    if not args.command:
        print("Error : No command supplied.")
        print_help()
        sys.exit(1)

    nyxcrypta = NyxCrypta(SecurityLevel(args.securitylevel))
    handle_command(args, nyxcrypta)

if __name__ == '__main__':
    main()