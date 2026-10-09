"""
Module for NyxCrypta's interactive CLI interface.
"""
from typing import Optional, Callable
import questionary
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint
from ..core.security import SecurityLevel
from ..core.compatibility import KeyFormat
from contextlib import contextmanager

console = Console()


class UserCancelled(Exception):
    """Raised when the user aborts a prompt (Ctrl+C / Esc)."""


def ask(question):
    """Runs a questionary prompt and turns a cancelled prompt (None) into UserCancelled."""
    result = question.ask()
    if result is None:
        raise UserCancelled()
    return result


class InteractiveCLI:
    def __init__(self):
        self.console = Console()
        
    def welcome(self):
        """Display welcome message"""
        welcome_text = """[bold cyan]
╔═╗ ╔╗         ╔═══╗                    ╔╗        
║║╚╗║║         ║╔═╗║                    ║║        
║╔╗╚╝║╔╗ ╔╗╔╗ ║║ ╚╝╔═╗╔╗ ╔╗╔══╗╔╗╔═╗  ║║ ╔══╗   
║║╚╗║║║║ ║║╠╣ ║║   ║╔╝║║ ║║║╔╗║╠╣║╔╗╗ ║║ ║╔╗║   
║║ ║║║║╚═╝║║║ ║╚═╗║║║║╚═╝║║╚╝║║║║╚╝║ ║╚╗║╚╝║   
╚╝ ╚═╝╚═╗╔╝╚╝ ╚══╝╚╝╚╝   ╚╣╔═╝╚╝║╔═╝ ╚═╝╚══╝   
      ╔═╝║               ║║   ║║        v3.2.0   
      ╚══╝               ╚╝   ╚╝                 
[/bold cyan]

[yellow]RSA+AES Hybrid Cryptography Tool - Argon2id key protection, Ed25519 signatures[/yellow]
"""
        self.console.print(Panel(welcome_text, expand=False))

    def show_menu(self) -> str:
        """Display main menu and return chosen command"""
        choices = {
            "🔑 Generate Keys": "keygen",
            "🔄 Convert Key Format": "convert",
            "🔒 Encrypt File": "encrypt",
            "🔓 Decrypt File": "decrypt",
            "📝 Encrypt Data": "encryptdata",
            "📋 Decrypt Data": "decryptdata",
            "🖋️  Generate Signing Keys (Ed25519)": "signkeygen",
            "✍️  Sign File": "sign",
            "🔍 Verify Signature": "verify",
            "🧪 Run Tests": "test",
            "❌ Exit": "quit"
        }
        
        try:
            result = ask(questionary.select(
                "What would you like to do?",
                choices=list(choices.keys())
            ))
        except UserCancelled:
            return "quit"  # Ctrl+C on the main menu leaves the application

        return choices[result]

    def get_security_level(self) -> SecurityLevel:
        """Request security level"""
        choices = {
            "Standard (RSA 2048-bit) - General use": SecurityLevel.STANDARD,
            "High (RSA 3072-bit) - Sensitive data": SecurityLevel.HIGH,
            "Paranoid (RSA 4096-bit) - Maximum security": SecurityLevel.PARANOID
        }
        
        result = ask(questionary.select(
            "Choose security level:",
            choices=list(choices.keys())
        ))

        return choices[result]

    def get_key_format(self, include_ssh: bool = True) -> str:
        """Request key format"""
        choices = {
            "PEM - Standard text format": "PEM",
            "DER - Binary format": "DER",
            "JSON - Structured format": "JSON"
        }
        
        if include_ssh:
            choices["SSH - OpenSSH format (public keys only)"] = "SSH"
        
        result = ask(questionary.select(
            "Choose key format:",
            choices=list(choices.keys())
        ))

        return choices[result]

    def get_file_path(self, purpose: str, file_type: str = "file") -> str:
        """Request file path"""
        return ask(questionary.path(
            f"Path to {file_type} to {purpose}:"
        ))

    def ask_text(self, message: str) -> str:
        """Request free text"""
        return ask(questionary.text(message))

    def get_password(self, confirm: bool = True) -> str:
        """Request password with optional confirmation"""
        while True:
            password = ask(questionary.password("Enter password:"))
            
            if not confirm:
                return password
                
            confirm_password = ask(questionary.password("Confirm password:"))
            
            if password == confirm_password:
                return password
            else:
                self.console.print("[red]Passwords do not match. Please try again.[/red]")

    @contextmanager
    def show_progress(self, operation: str):
        """Display progress for an operation"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"[cyan]{operation}...", total=None)
            try:
                yield task
            finally:
                progress.update(task, completed=True)

    def show_success(self, message: str):
        """Display success message"""
        self.console.print(f"[green]✓[/green] {message}")

    def show_error(self, message: str):
        """Display error message"""
        self.console.print(f"[red]✗ Error: {message}[/red]")

    def show_warning(self, message: str):
        """Display warning message"""
        self.console.print(f"[yellow]⚠ {message}[/yellow]")

    def show_info(self, message: str):
        """Display information message"""
        self.console.print(f"[blue]ℹ[/blue] {message}")

    def show_key_info(self, key_path: str, key_type: str):
        """Display key information"""
        try:
            with open(key_path, 'r') as f:
                content = f.read()
                
            syntax = Syntax(
                content, 
                "text", 
                theme="monokai",
                line_numbers=True,
                word_wrap=True
            )
            
            self.console.print(Panel(
                syntax,
                title=f"[cyan]{key_type}[/cyan]",
                expand=False
            ))
        except Exception as e:
            self.show_error(f"Unable to read key: {str(e)}")

    def confirm_action(self, action: str) -> bool:
        """Request confirmation for an action"""
        return ask(questionary.confirm(
            f"Are you sure you want to {action}?",
            default=False
        ))