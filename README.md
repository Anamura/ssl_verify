## Утилита для проверки SSL сертификата


Входные данные:
Имеется текстовый файл. В каждой строке записано имя хоста
варианты:

    https://hostname
    https://hostname/
    https://hostname/blabl
    hostname/
    hostname/blabla


Выходные данные:
На выход требуется создать файл output.csv формата:
Host SSL_validityExpires

    $ python3.7 ssl_verify.py "hosts.txt"
