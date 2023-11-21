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

Encontramos un posible usuario orestis.

















































