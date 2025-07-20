#!/usr/bin/env python3
import secrets
import hashlib
import hmac
import time
import json
import importlib
from pathlib import Path
from getpass import getpass
from typing import Tuple, Optional, Dict, List, Any
import argparse
import inspect

# Optional dependencies with graceful fallback
try:
    import geocoder
    GPS_AVAILABLE = True
except ImportError:
    GPS_AVAILABLE = False
try:
    import platform
    DEVICE_INFO = True
except ImportError:
    DEVICE_INFO = False

# Constants
BUOY_SEED_LENGTH = 32
TIME_QUANTUM = 30  # seconds
DICE_SIDES = 2**20
PHASE_MODULUS = 64
PLUGINS_DIR = "buoy_plugins"

class BuoyPlugin:
    """Base class for all Buoy plugins"""
    version = "1.0"
    
    def __init__(self, cipher: 'BuoyCipher'):
        self.cipher = cipher
    
    def pre_encrypt(self, plaintext: str, context: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Modify message before encryption"""
        return plaintext, context
    
    def post_encrypt(self, ciphertext: bytes, context: Dict[str, Any]) -> bytes:
        """Modify ciphertext after encryption"""
        return ciphertext
    
    def pre_decrypt(self, ciphertext: bytes, context: Dict[str, Any]) -> Tuple[bytes, Dict[str, Any]]:
        """Modify ciphertext before decryption"""
        return ciphertext, context
    
    def post_decrypt(self, plaintext: str, context: Dict[str, Any]) -> str:
        """Modify message after decryption"""
        return plaintext
    
    def get_metadata(self) -> Dict[str, Any]:
        """Return plugin metadata"""
        return {
            "name": self.__class__.__name__,
            "version": self.version,
            "description": inspect.getdoc(self) or ""
        }

class BuoyCipher:
    def __init__(self, shared_secret: str):
        self.shared_secret = shared_secret
        self.plugins: List[BuoyPlugin] = []
        
    def load_plugins(self, plugin_names: List[str]):
        """Load plugins by their module names"""
        for plugin_name in plugin_names:
            try:
                module = importlib.import_module(f"{PLUGINS_DIR}.{plugin_name}")
                plugin_class = getattr(module, plugin_name)
                self.plugins.append(plugin_class(self))
                print(f"Loaded plugin: {plugin_name}")
            except Exception as e:
                print(f"Failed to load plugin {plugin_name}: {str(e)}")
    
    @staticmethod
    def roll_buoy_dice(seed: str, message_len: int, sides: int = DICE_SIDES) -> list:
        rng = secrets.SystemRandom()
        hashed = int(hashlib.sha3_512(seed.encode()).hexdigest(), 16)
        return [(hashed + i * rng.randint(1, sides)) % sides for i in range(message_len)]
    
    @staticmethod
    def buoy_xor(message: str, dice_rolls: list, buoy_phase: int) -> bytes:
        return bytes([(ord(c) ^ ((d >> (buoy_phase % 8)) & 0xFF)) for c, d in zip(message, dice_rolls)])
    
    def get_current_phase(self, additional_entropy: str = "") -> int:
        time_quantum = int(time.time()) // TIME_QUANTUM
        phase_seed = f"{self.shared_secret}{time_quantum}{additional_entropy}"
        return int(hashlib.sha3_256(phase_seed.encode()).hexdigest(), 16) % PHASE_MODULUS
    
    def encrypt(self, plaintext: str, gps_location: Optional[str] = None, 
               device_info: Optional[str] = None) -> Tuple[bytes, int, Dict[str, Any]]:
        context = {
            "gps": gps_location,
            "device": device_info,
            "timestamp": time.time(),
            "plugins": {}
        }
        
        # Run pre-encrypt plugins
        for plugin in self.plugins:
            plaintext, context = plugin.pre_encrypt(plaintext, context)
        
        phase = self.get_current_phase()
        dice_seed = f"{self.shared_secret}{phase}{context}"
        dice = self.roll_buoy_dice(dice_seed, len(plaintext))
        ciphertext = self.buoy_xor(plaintext, dice, phase)
        
        # Run post-encrypt plugins
        for plugin in self.plugins:
            ciphertext = plugin.post_encrypt(ciphertext, context)
        
        return ciphertext, phase, context
    
    def decrypt(self, ciphertext: bytes, phase: int, 
               gps_location: Optional[str] = None, 
               device_info: Optional[str] = None,
               plugin_context: Optional[Dict] = None) -> str:
        context = {
            "gps": gps_location,
            "device": device_info,
            "phase": phase,
            "timestamp": time.time(),
            "plugins": plugin_context or {}
        }
        
        # Run pre-decrypt plugins
        for plugin in self.plugins:
            ciphertext, context = plugin.pre_decrypt(ciphertext, context)
        
        dice_seed = f"{self.shared_secret}{phase}{context}"
        dice = self.roll_buoy_dice(dice_seed, len(ciphertext))
        plaintext = self.buoy_xor(ciphertext.decode('latin1'), dice, phase).decode('utf-8', errors='replace')
        
        # Run post-decrypt plugins
        for plugin in self.plugins:
            plaintext = plugin.post_decrypt(plaintext, context)
        
        return plaintext

class BuoyCLI:
    def __init__(self):
        self.cipher = None
        self.gps_cache = None
        self.device_info = self.get_device_info() if DEVICE_INFO else "Unknown"
        self.active_plugins = []
    
    @staticmethod
    def get_device_info() -> str:
        system = platform.system()
        machine = platform.machine()
        node = platform.node()
        return f"{system}/{machine}/{node}"
    
    def get_gps_location(self) -> Optional[str]:
        if not GPS_AVAILABLE:
            return None
        
        if self.gps_cache and (time.time() - self.gps_cache[1] < 300):
            return self.gps_cache[0]
            
        try:
            g = geocoder.ip('me')
            if g.ok:
                loc = f"{g.latlng[0]:.4f},{g.latlng[1]:.4f}"
                self.gps_cache = (loc, time.time())
                return loc
        except Exception:
            pass
        return None
    
    def discover_plugins(self) -> List[str]:
        """Find available plugins in the plugins directory"""
        plugin_dir = Path(PLUGINS_DIR)
        if not plugin_dir.exists():
            return []
        
        return [f.stem for f in plugin_dir.glob("*.py") if not f.name.startswith("_")]
    
    def establish_connection(self):
        print("=== Buoy Secure Messaging ===")
        method = input("Establish shared secret via:\n1. Manual entry\n2. Generate new\nChoice: ")
        
        if method == "1":
            secret = getpass("Enter shared secret: ")
        else:
            secret = secrets.token_urlsafe(BUOY_SEED_LENGTH)
            print(f"\nGenerated new secret (share securely!):\n{secret}\n")
        
        self.cipher = BuoyCipher(secret)
        
        # Plugin discovery and loading
        available_plugins = self.discover_plugins()
        if available_plugins:
            print("\nAvailable plugins:")
            for i, name in enumerate(available_plugins, 1):
                print(f"{i}. {name}")
            
            choices = input("Select plugins to load (comma-separated numbers or 'all'): ")
            if choices.lower() == 'all':
                selected = available_plugins
            else:
                selected = []
                for choice in choices.split(','):
                    try:
                        idx = int(choice.strip()) - 1
                        if 0 <= idx < len(available_plugins):
                            selected.append(available_plugins[idx])
                    except ValueError:
                        pass
            
            self.cipher.load_plugins(selected)
            self.active_plugins = selected
    
    def send_message(self):
        if not self.cipher:
            print("Error: No secure connection established")
            return
        
        message = input("Enter message: ")
        gps = self.get_gps_location()
        device = self.device_info
        
        print("\nEncrypting with:", end=' ')
        if gps:
            print(f"GPS={gps}", end=' ')
        print(f"Device={device}")
        if self.active_plugins:
            print(f"Active plugins: {', '.join(self.active_plugins)}")
        
        ciphertext, phase, context = self.cipher.encrypt(message, gps, device)
        
        output = {
            "ciphertext": ciphertext.hex(),
            "phase": phase,
            "context": {
                "gps": gps,
                "device": device,
                "timestamp": context["timestamp"],
                "plugins": context["plugins"]
            }
        }
        
        print("\nEncrypted Message Package:")
        print(json.dumps(output, indent=2))
    
    def receive_message(self):
        if not self.cipher:
            print("Error: No secure connection established")
            return
        
        try:
            message_pkg = input("Enter message package (JSON): ")
            data = json.loads(message_pkg)
            
            ciphertext = bytes.fromhex(data["ciphertext"])
            phase = data["phase"]
            context = data.get("context", {})
            
            gps = self.get_gps_location()
            device = self.device_info
            
            print("\nDecrypting with:", end=' ')
            if gps:
                print(f"GPS={gps}", end=' ')
            print(f"Device={device}")
            if self.active_plugins:
                print(f"Active plugins: {', '.join(self.active_plugins)}")
            
            plaintext = self.cipher.decrypt(
                ciphertext, phase, gps, device, 
                plugin_context=context.get("plugins", {})
            )
            
            print(f"\nDecrypted Message:")
            print(plaintext)
        except Exception as e:
            print(f"Error: {str(e)}")
            print("Please ensure:")
            print("- Correct shared secret")
            print("- Matching plugins are loaded")
            print("- GPS/device context matches")
            print("- Phase is correct (current phase: {self.cipher.get_current_phase()})")

    def run(self):
        self.establish_connection()
        
        while True:
            print("\nOptions:")
            print("1. Send message")
            print("2. Receive message")
            print("3. Show current phase")
            print("4. List active plugins")
            print("5. Exit")
            
            choice = input("Choice: ")
            
            if choice == "1":
                self.send_message()
            elif choice == "2":
                self.receive_message()
            elif choice == "3":
                phase = self.cipher.get_current_phase()
                print(f"Current phase: {phase} (changes every {TIME_QUANTUM} seconds)")
            elif choice == "4":
                print("\nActive plugins:")
                for plugin in self.cipher.plugins:
                    meta = plugin.get_metadata()
                    print(f"{meta['name']} v{meta['version']}")
                    print(f"  {meta['description']}")
            elif choice == "5":
                print("Wiping session...")
                break
            else:
                print("Invalid choice")

if __name__ == "__main__":
    # Create plugins directory if it doesn't exist
    Path(PLUGINS_DIR).mkdir(exist_ok=True)
    
    parser = argparse.ArgumentParser(description="Buoy Secure Messaging CLI")
    parser.add_argument('--no-gps', action='store_true', help="Disable GPS features")
    parser.add_argument('--plugins', nargs='+', help="Preload specific plugins")
    args = parser.parse_args()
    
    if args.no_gps:
        GPS_AVAILABLE = False
    
    try:
        cli = BuoyCLI()
        if args.plugins:
            cli.cipher = BuoyCipher("temp")  # Temporary cipher for preloading
            cli.cipher.load_plugins(args.plugins)
            cli.active_plugins = args.plugins
            cli.cipher = None  # Reset for proper initialization
        cli.run()
    except KeyboardInterrupt:
        print("\nSession terminated")
