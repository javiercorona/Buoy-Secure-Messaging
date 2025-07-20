# 🛟 Buoy Secure Messaging

> Quantum-inspired, entropy-driven, dice-phase encrypted messaging system with optional GPS, device fingerprinting, plugins, and biometric lock.

## 🚀 Features
- 🎲 Dice-based encryption with high entropy (millions of sides)
- 🔐 SHA3 / HMAC-secure encryption and verification
- ⏱️ Time-phase sync like OTP or QKD
- 🌍 Contextual encryption (GPS + device)
- 🧩 Plugin support (e.g. FaceLock)
- 📤 Secure CLI message send/receive
- 📦 Cross-platform Python 3.x

## 🔗 Links
- 🔧 **Source Code**: [https://lnkd.in/gPAdabUQ)
- 📚 **Docs**: [https://lnkd.in/gEGRuVDF)
- 🔐 **FaceLock Plugin**: [FaceLock.py](https://lnkd.in/g4U8k-pM)
- 🎲 **Encryption Engine**: [BuoyCore](https://lnkd.in/gjDxqeyn)
- 🧪 **Plugin Dev Template**: [PluginBase](https://lnkd.in/ggcca67m)

## 📥 Install

```bash
git clone https://lnkd.in/gKF--b48
cd buoy-secure-messaging
pip install -r requirements.txt
python3 cli.py
```

## 🧠 Usage

```bash
# Encrypt a message with dice entropy + GPS
python3 cli.py send --to Bob --message "Meet at sector 7" --gps-lock

# Decrypt with biometric plugin enabled
python3 cli.py receive --plugin FaceLock
```

## 🔐 Optional Plugins
- ✅ FaceLock (Face recognition auth)
- 🔊 MicroEntropy (Mic noise as entropy source)
- 📍 GeoFence (region-limited decryption)
- 🧬 TPMLock (TPM/hardware binding)

---
