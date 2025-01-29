import sys
import logging
import questionary
from rich.console import Console
from .core.crypto import NyxCrypta
from .core.security import SecurityLevel
from .cli.parser import create_parser
from .cli.commands import print_help, handle_command
from .cli.interactive import InteractiveCLI
from .test_runner import TestRunner
from argparse import Namespace

console = Console()

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    cli = InteractiveCLI()

    # Interactive mode if no arguments
    if len(sys.argv) == 1:
        cli.welcome()
        while True:
            command = cli.show_menu()
            
            if command == 'quit':
                cli.show_info("Goodbye!")
                sys.exit(0)
            
            # Create empty args with just the command for interactive mode
            args = Namespace(command=command)
            
            # Create NyxCrypta instance with chosen security level
            if command == 'keygen':
                security_level = cli.get_security_level()
            else:
                security_level = SecurityLevel.STANDARD

            if command == 'test':
                cli.show_info("Running tests...")
                runner = TestRunner()
                results = runner.run_all_tests()
                
                console.print("\n[bold cyan]📊 Test Summary:[/bold cyan]")
                console.print(f"Total tests: {results['total']} tests")
                console.print(f"Passed: [green]{results['passed']}[/green]")
                console.print(f"Failed: [red]{results['failed']}[/red]")
                
                if results['failed_tests']:
                    console.print("\n[red]❌ Failed Tests:[/red]")
                    for test_name, error in results['failed_tests']:
                        console.print(f"- {test_name}: {error}")
                else:
                    console.print("\n[green]✨ All tests passed successfully![/green]")
            
            nyxcrypta = NyxCrypta(security_level)
            handle_command(args, nyxcrypta)
            
            print()  # Empty line for readability

    # Classic command line mode
    else:
        parser = create_parser()
        
        if '-h' in sys.argv or '--help' in sys.argv:
            print_help()
            sys.exit(0)
            
        args = parser.parse_args()
        
        if args.command == 'test':
            cli.show_info("Running tests...")
            runner = TestRunner()
            results = runner.run_all_tests()
            
            console.print("\n[bold cyan]📊 Test Summary:[/bold cyan]")
            console.print(f"Total tests: {results['total']}")
            console.print(f"Passed: [green]{results['passed']}[/green]")
            console.print(f"Failed: [red]{results['failed']}[/red]")
            
            if results['failed_tests']:
                console.print("\n[red]❌ Failed Tests:[/red]")
                for test_name, error in results['failed_tests']:
                    console.print(f"- {test_name}: {error}")
                sys.exit(1)
            else:
                console.print("\n[green]✨ All tests passed successfully![/green]")
                sys.exit(0)
        
        if not args.command:
            cli.show_error("No command provided.")
            print_help()
            sys.exit(1)

        # Create NyxCrypta instance with security level from command line
        security_level = SecurityLevel(getattr(args, 'securitylevel', 1))
        nyxcrypta = NyxCrypta(security_level)
        
        try:
            handle_command(args, nyxcrypta)
        except Exception as e:
            cli.show_error(f"Command failed: {str(e)}")
            sys.exit(1)

if __name__ == '__main__':
    main()