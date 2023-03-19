# -*- codign: utf-8 -*-
import logging
import threading
import time
import subprocess
import re
import xml.etree.ElementTree as etree
from flask import Flask, render_template, request
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json




# App Definition
app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)



#
#
#
def parse_nmap_xml_output(output):
    try:
        root = etree.fromstring(output)
    except Exception as e:
        app.logger.error(str(e))
        return

    # holds results
    found_services = []

    # traverse xml
    for child in root:
        if child.tag == 'host':
            for host in child:
                for ports in host:
                    print(ports.attrib)
                    service_node = {'protocol': '', 'portid': '', 'state': '', 'name': '', 'product': '', 'version': '', 'cve': None}
                    service_node['protocol'] = ports.attrib['protocol'] if 'protocol' in ports.attrib else ''
                    service_node['portid']   = ports.attrib['portid'] if 'portid' in ports.attrib else ''
                    for port in ports:
                        #print(port.tag)
                        if port.tag == 'state':
                            #print(f'port state: {port.attrib["state"]}')
                            service_node['state'] = port.attrib["state"]  if 'state' in port.attrib else ''
                        elif port.tag == 'service':
                            #print(f'service info: {port.attrib["name"]}')
                            service_node['name'] = port.attrib["name"]  if 'name' in port.attrib else ''
                            service_node['product'] = port.attrib["product"]  if 'product' in port.attrib else ''
                            service_node['version'] = port.attrib["version"]  if 'version' in port.attrib else ''
                            # port.attrib[name, product, version, extrainfo, method, conf
                        elif port.tag == 'script':
                            # port.attrib[id, output]
                            output = port.attrib["output"]
                            output_lines = output.split("\n")
                            regex = "\t(CVE.*)\t(.*)\t(.*)"
                            found_cve = []
                            for line in output_lines:
                                re_result = re.findall(regex, line)
                                if re_result:
                                    cve, score, url = re_result[0]
                                    #print(f'cve: {cve}, score: {score}, url: {url}')
                                    found_cve.append({'cve': cve, 'score': score, 'url': url})
                            if found_cve:
                                service_node['cve'] = found_cve

                    found_services.append(service_node)
    return found_services


#
#
#
def worker_sample(remoteip, nome, email):
    app.logger.info(f'started a new thread worker for ip {remoteip} requested by {nome} mail:  {email}')
    #r = subprocess.run(f'nmap -sT -Pn -n -sV --script=vulners -oX - -p80 127.0.0.1', capture_output=True, shell=True)
    try:
        r = subprocess.run(f'nmap -sT -Pn -n -sV --script=vulners -oX - -p- {remoteip}', capture_output=True, shell=True)
    except Exception as e:
        app.logger.critical(f'failed to run nmap with exception as follow: {str(e)}')
        return
    if r.returncode != 0:
        app.logger.critical(f'failed execute nmap for ip {remoteip}')
        app.logger.critical(r.stdout)
        return

    # hold service findings
    process_output = r.stdout
    with open(f'scan_{remoteip}.xml', 'w') as xml_out_file:
        xml_out_file.write(str(process_output))
    found_services = parse_nmap_xml_output(process_output)
    send_results_by_email(found_services, email, remoteip, nome)



#
#
#
def send_results_by_email(found_services, recipient, remoteip, nome):

    gmail_user = "myemail@gmail.com"
    gmail_pass = "myapppasswordfromgooglemail"
    sent_from = gmail_user
    subject = '[MY BUSINESS] Relatorio de vulnerabilidade'
    msg = MIMEMultipart('alternative')
    msg['To'] = recipient
    msg['From'] = gmail_user
    msg['Subject']  = subject
    #vulnerability_details = ""
    html = f"""    <html>
        <head>
        <style>
            table{{border: 2px solid black; border-collapse: collapse;width:100%}}
        </style>
        </head>
        <body>
        <div>
            <span>Olá <strong>{nome}</strong>,
            <br>
            Estamos enviando o relatório da Varredura de Vulnerabilidades solicitada para o endereço IP {remoteip}.
            </span>
            <br>
            <br>
    """
    if len(found_services) > 0:
        html += f"""        <span>A tabela abaixo lista as portas, serviços e se alguma vulnerabilidade conhecida foi encontrada.</span>
        <br><br>
        <table border="1" cellspacing="0" style="border:1px solid black;">
        <tr>
            <td style="background-color:#b2b2b2;"><center><strong>Serviço<strong></center></td>
            <td style="background-color:#b2b2b2;"><center><strong>Software<strong></center></td>
            <td style="background-color:#b2b2b2;"><center><strong>Porta<strong></center></td>
            <td style="background-color:#b2b2b2;"><center><strong>Vulnerabilidades<strong><br><strong>Relacionadas<strong></center></td>
        </tr>
        """
        for service in found_services:
            if service["portid"] == '':
                continue
            html += f"""                <tr>
                    <td><center>{service["name"]}</center></td>
                    <td><center>{service["product"]}&nbsp;&nbsp;{service["version"]}</center></td>
                    <td><center>{service["portid"]}</center></td>
            """
            if service['cve'] is not None:
                html += f"""                    <td><center>{'<br>'.join([ "<a href='{}'>{}</a>".format(x["url"],x["cve"]) for x in service['cve'] ])}</center></td>
                """

            html += f"""                </tr>
            """
        html += f"""            </table>
        """
    else:
        html += f"""Parabéns, não foram encontrados serviços ou portas expostas na internet para o IP {remoteip} ✨.
            Isso não significa que você está totalmente seguro, mas significa que a exposição da sua rede na internet é mínima..
        """
        


    html += f"""        </div>
        <br><br>
        <div>
        <span><a href="https://www.citrait.com.br">Clique aqui</a> caso queira solicitar um relatório mais detalhado.
        <br>
        Acesse <a href="https://www.citrait.com.br">este link</a> para conhecer o portifólio de serviços de CyberSecurity da CitraIT.</span>
        </div>
        </body>

    </html>
    """
    #.format(nome, remoteip, mail_body)
    part1 = MIMEText(html, 'html', _charset="utf-8")
    msg.attach(part1)
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_pass)
        server.sendmail(sent_from, recipient, msg.as_string().encode('utf-8'))
        server.close()
        app.logger.debug(f'done processing for {remoteip}, e-mail sent to {recipient}.')
    except Exception as e:
        app.logger.info(f'error sending the e-mail to {recipient}')
        app.logger.debug(str(e))
        #print(dir(e))
        #print(e.object)





#
#
#
def format_html():
    html = """    <html>
        <head>

        </head>
        <body>
            <h1>{}</h1>
            <table>
            <tr>
            <td>porta</td>
            <td>serviço</td>
            <td>
    """.format("Relatório de Vulnerabilidades no Firewall")


    html += """

    """




#
#
#
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        ipaddress   = request.headers.get('X-Forwarded-For')
        return render_template("index.html", ctx={'ipaddress': ipaddress})
    elif request.method == "POST":
        nome     = request.form["nome"]
        email    = request.form["email"]
        remoteip = request.headers.get('X-Forwarded-For')

        t = threading.Thread(target=worker_sample, args=(remoteip, nome, email))
        t.start()

        return render_template("thanks.html", ctx={})


@app.route("/", methods=["POST"])
def manual():
    ipaddress = request.form.get("ip")
    nome = request.form.get("nome")
    email = request.form.get("email")
    t = threading.Thread(target=worker_sample, args=(ipaddress, nome, email))
    t.start()
    return "ok"



#
# MAIN ROUTINE
#
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)
