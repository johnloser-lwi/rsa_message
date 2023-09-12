# RSA Message Encrypt/Decrypt Tool
Author: [JohnLoser](https://github.com/johnloser-lwi)
## About
Since WeChat is a Chinese app, the government can easily access the messages. So we need a tool to encrypt our messages. This tool uses RSA algorithm to encrypt and decrypt messages. It is a very secure algorithm and is widely used in the real world. 
<br/>
With the encryption, the government can only see the encrypted messages, which are meaningless to them. The messages can only be decrypted with the private key, which is only known by the sender and the receiver. So the messages are safe.
<br/>
You may think that using other platform will be safer, but not everyone has a steady access to Discord, Telegram, etc. WeChat is still the most convenient way to communicate with each other in PRC.
## Download
Get the latest version from [Releases](https://github.com/johnloser-lwi/rsa_message/releases)
## Usage
Before your start, generate a key pair by clicking `Generate Key Pair`
### Encrypt Messages
- (Optional) Get other's public key for encryption
- Type your message in the `TextBox`
- Click `Encrypt Message` and the encrypted message will be copied to clipboard
- Send the encrypted message to your friend with any method you want
### Decrypt Messages
- Message can only be decrypted with the corresponding private key
- Copy the encrypted message to the clipboard
- Click `Decrypt Message` and the decrypted message will be shown in the `TextBox`
## Build
We only provide the Windows version. If you want to build for other platforms, you can build it yourself.
### Requirements
- Python 3.x
### Scripts
```bash
git clone git@github.com:johnloser-lwi/rsa_message.git # download the source code

cd rsa_message

pip install -r requirements.txt # install dependencies

pyinstaller rsa_message.py --onefile --noconsole # build the executable file
```
## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.