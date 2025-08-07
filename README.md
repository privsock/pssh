# pssh

pssh (Privilege SSH) is an ssh client wrapper designed to easen ssh connections through the CyberArk Platform. It abstracts away the complexities of declaring the cyberark jump host address and username for every CyberArk-managed connection.

## 🔐 Getting Started

The CyberArk Platform provides secure, audited access to privileged systems. However, initiating ssh sessions manually can be cumbersome. pssh automates:
- The Cyberark domain identification (based on the username)
- The CyberArk mfa key retrieval
- SSH jump host resolution (tenant.ssh.cyberark.cloud)
- SSH command formatting (user#tenant@account@target@cyberark-jump-host)

## ⚙️ Features
- Simple ssh wrapper to connect to CyberArk-managed endpoints
- Cross Platform (Windows, Linux, macOS)
- Custom SSH agent to securely store the Cyberark ssh mfa key

## 🚀 Usage

### Configure pssh
```bash
# Create an ark profile
$ pssh ark configure
# Configure pssh (preferred ark profile, username, network) 
$ pssh configure
```

### Connect to a target
```bash
# Connect with the account user@address, stored in a CyberArk Vault
$ pssh username@address

# Connect with an ephemeral user
$ pssh address
```
## 📦 Installation

### From sources
Prerequisites:
- [Golang](https://go.dev) >= 1.24.1
```bash
$ git clone https://github.com/privsock/pssh.git
$ cd pssh
$ go install .
```

### Prebuilt binaries
Download the latest [release](https://github.com/privsock/pssh/releases), rename it to `pssh` and place it in your PATH (e.g. /usr/local/bin).  
On Linux and macOS, grant execution permissions:
```bash
$ chmod +x pssh
```

## License
This project is under the [GNU General Public License v3.0](https://github.com/privsock/pssh/LICENSE.txt)

## Acknowledgments
- [Ark SDK](https://github.com/cyberark/ark-sdk-golang)