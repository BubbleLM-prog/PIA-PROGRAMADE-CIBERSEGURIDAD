from modulos import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser( fromfile_prefix_chars='@',
        description='PIA de programación para ciberseguridad.\n' +
        '\nTareas que puede realizar:\n' +
        '1. Escaneo de puertos\n' +
        '2. Web scraping.\n' +
        '3. Envío de correos.\n' +
        '4. Obtención de claves HASH.\n' +
        '5. Cifrado de mensajes.\n'+
        '\nArgumentos requeridos para la ejecución del programa:', formatter_class=argparse. RawDescriptionHelpFormatter)
    parser.add_argument('-re', metavar='remitente', dest='remitente', help='correo del remitente', default='')
    parser.add_argument('-co', metavar='contraseña', dest='contraseña',help='contraseña del remitente', default='')
    parser.add_argument('-de', metavar='destinatario', dest='destinatario', help='correo del destinatario', default='')
    parser.add_argument('-as', metavar='asunto', dest='asunto', help='asunto del correo', default='')
    parser.add_argument('-cu', metavar='cuerpo', dest='cuerpo', help='cuerpo del correo', default='')
    parser.add_argument('-pa', metavar='path', dest='path', help='ingresa el path en donde se encuentra la imagen', default= '')
    parser.add_argument('-url', metavar='url', dest= 'url', help='url de la página (web scraping)', default='')
    parser.add_argument('-r', metavar='ruta', dest = 'ruta', help='ruta de la carpeta para la obtención de claves HASH', default='')
    parser.add_argument('-m', metavar='mensaje', dest = 'mensaje', help='mensaje a cifrar', default='')
    parser.add_argument('-cl', metavar='clave', dest = 'clave', help='palabra clave', default=('Py'))
    parser.add_argument('-ip', metavar='ip', dest='ip', help='ingresa una ip', default= '')
    params= parser.parse_args()
    
    #Lista de variables
    url = params.url
    ip = params.ip
    remitente = params.remitente
    contraseña = params.contraseña
    destinatario = params.destinatario
    asunto = params.asunto
    cuerpo = params.cuerpo
    path = params.path
    rutaHash = params.ruta
    clave = params.clave
    mensaje = params.mensaje

    try:
        os.mkdir('Reportes')
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    
#Script para escanear puertos  
if ip != '':  
    def checkPortsSocket(ip, portlist):
        try:
            archivo = open(datetime.now().strftime("Reportes/puertos_%H_%M_%d_%m_%Y.txt"), 'w')
            for port in portlist:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    archivo.write("Puerto {}: \t Abierto".format(port) + '\n')
                else:
                    archivo.write("Puerto {}: \t Cerrado".format(port) + '\n')
                sock.close()
            print("\nEscaner de la IP:" , ip, "realizado.")
        except socket.error as error:
            print("\nError de conexión")
            logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', filename='Reportes/Error-Puertos.log')
            logging.warning("Hubo un error de conexión.")
            sys.exit
    puertos = range(75, 86)
    portlist = puertos
    checkPortsSocket(ip, portlist)
    
#Script para web scraping
if url != '':
    print('\nObteniendo links de:'+  url)
    try:
        file = open(datetime.now().strftime("Reportes/WEB_SCRAPING_%H_%M_%d_%m_%Y.txt"), 'w')
        page = requests.get(url)
        body = html.fromstring(page.text)
        links = body.xpath('//a/@href')
                
        for link in links:
            file.write(link + '\n')
                
        print('Web scraping realizado.')

        def virustotalr():
            url2 = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {"apikey": "787abaa4f96865eb9a93ff7855f3965a7af9bee1ad83fdc4cce3e715750fce2c", "resource":url}

            response = (requests.post(url2, data=params))
            data = (response.json())
            d = str(data)

            file = open(datetime.now().strftime("Reportes/VIRUSTOTAL_REPORT_%H_%M_%d_%m_%Y.txt"), 'w')
            file.writelines(d)
            file.close()

            print('\nVirusTotal realizado.')
        virustotalr()

    except Exception as i:
                print(i)
                print('\nUps,connection error' + url)
                logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', filename='Reportes/Error-WS.log')
                logging.warning('Hubo un error')
   
#Script para mandar correos
if remitente != '':
    try:
        sender_email = remitente
        password = contraseña
            
        receiver_email = destinatario

        subject = asunto
        body = cuerpo

        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject
        message["Bcc"] = receiver_email 
        message.attach(MIMEText(body, "plain"))
        
        if path != '':
            file = open(path, "rb")
            attach_image = MIMEImage(file.read())
            attach_image.add_header('Content-Disposition', 'attachment; filename = imagen')
            message.attach(attach_image)
        
        text = message.as_string()
        
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, text)
            print("\nCorreo enviado")
        print("Remitente:", sender_email + "\n" + "Destinatario:", receiver_email + "\n" + "Asunto:", subject + "\n" + "Cuerpo:",body, file=open(datetime.now().strftime("Reportes/REPORTE_CORREOS_%H_%M_%d_%m_%Y.txt"), 'a'))
    except:
        print("\nPor favor revise sus credenciales")
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', filename='Reportes/Error-Correos.log')
        logging.warning("Hubo un error en tus credenciales")

#Script para obtener claves hash
if rutaHash != '':
    if os.path.isdir(rutaHash):
        try:    
            lineaPS = 'Powershell -ExecutionPolicy ByPass -File .\\hash.ps1 -rutaHash ' + rutaHash
            runningProcesses = subprocess.check_output(lineaPS)
            print(runningProcesses.decode())
            print('Valores Hash obtenidos')
        except (IOError,NameError) as e:
            logging.basicConfig(filename='Reportes/Error_Hash.log',level=logging.INFO)
            logging.error('Ha ocurrido un error: ' + str(e))
    else:
        logging.basicConfig(filename='Reportes/Error_Hash.log',level=logging.INFO)
        logging.error('El path ingresado no existe')

#Script para cifrado de mensajes
if mensaje != '':
    message = mensaje
    espacios = 1
    while espacios > 0:
        espacios = clave.count(' ')
        if clave.isalpha() == False:
            espacios += 1
    key = len(clave)

    SYMBOLS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890 !?.'

    translated = ''
    x = ''
    for symbol in message:
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)
            translatedIndex = symbolIndex + key

            if translatedIndex >= len(SYMBOLS):
                translatedIndex = translatedIndex - len(SYMBOLS)
            elif translatedIndex < 0:
                translatedIndex = translatedIndex + len(SYMBOLS)

            translated = translated + SYMBOLS[translatedIndex]
        else:
            translated = translated + symbol


    for symbol in translated:
        if symbol in SYMBOLS:
            symbolIndex = SYMBOLS.find(symbol)
            translatedIndex = symbolIndex - key
                    
            if translatedIndex >= len(SYMBOLS):
                translatedIndex = translatedIndex - len(SYMBOLS)
            elif translatedIndex < 0:
                translatedIndex = translatedIndex + len(SYMBOLS)

            x = x + SYMBOLS[translatedIndex]
        else:
            translated = translated + symbol

    ruta = (os.path.abspath("ReportedeCifrado.txt"))

    try:
        docum = open(datetime.now().strftime("Reportes/ReportedeCifrado_%H_%M_%d_%m_%Y.txt") ,"w")
        docum.write("Texto plano: "+ x + '\n')
        docum.write("Clave: " + clave + '\n')
        docum.write("Texto cifrado: " + translated)
        docum.close()
    except Exception as i:
        print(i)
        print("Lo sentimos ha ocurrido un error :(")

        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(message)s', filename='Reportes/Error-Cifrado.log')
        logging.warning("Hubo un error en tus credenciales")

    print('\nMensaje cifrado')
        
        

