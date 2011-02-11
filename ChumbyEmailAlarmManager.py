#!/usr/bin/python
'''
File: ChumbyEmailAlarmManager.py
Author: Adam Coddington
Description: Manage your alarms via E-mail
'''
import os.path
import logging.handlers
import smtplib
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from xml.dom.minidom import parse
from imaplib import IMAP4
from poplib import POP3
import datetime
import tempfile
import rfc822
import re
import email.Errors
from optparse import OptionParser
from ConfigParser import SafeConfigParser

class EmailAuthenticityException(Exception):
    def __init__(self, param):
        self.param = param

class ImapMailEnumerator(object):
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def connect(self, username, password):
        self.server = IMAP4(self.hostname, self.port)
        typ, msg = self.server.login(username, password)
        self.server.select()

    def get_message(self):
        typ, inbox = self.server.search(None, 'ALL')
        for key in inbox[0].split():
            try:
                typ, msg_contents = self.server.fetch(key, '(RFC822)')
                message = email.message_from_string(msg_contents[0][1])
                yield message
            except email.Errors.MessageParseError:
                continue
            self.server.store(key, "+FLAGS", "\\Deleted");
        self.server.expunge()
        return

class PopMailEnumerator(object):
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def connect(self, username, password):
        self.server = POP3(self.hostname, self.port)
        self.server.user(username)
        self.server.pass_(password)

    def get_message(self):
        message_count = len(self.server.list()[1])
        for i in range(message_count):
            try:
                msg_contents = "\r\n".join(self.server.retr(i + 1)[1])
                message = email.message_from_string(msg_contents)
                yield message
            except email.Errors.MessageParseError:
                continue
            self.server.dele(i + 1)
        self.server.quit()
        return

class ChumbyEmailAlarmManager(object):
    def __init__(self, options, args):
        config = self.read_configuration(options.configfile)

        self.logger = logging.getLogger('')
        self.logger.setLevel(logging.DEBUG)
        loghandler = logging.StreamHandler()
        loghandler.setLevel(logging.DEBUG)
        logformatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        loghandler.setFormatter(logformatter)
        file_handler = logging.handlers.RotatingFileHandler(config.get("defaults", "log_path"), maxBytes = 100000, backupCount = 2)
        file_formatter = logging.Formatter("%(asctime)s: %(process)d: %(name)-25s: %(module)-20s: %(funcName)-20s: %(levelname)-8s %(message)s")
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(loghandler)
        self.logger.info("Starting")

        self.smtp_server = config.get("defaults", "smtp_server")
        self.smtp_user = config.get("defaults", "smtp_user")
        self.smtp_password = config.get("defaults", "smtp_password")

        self.alarm_path = config.get("defaults", "alarm_path")
        self.secret_code = config.get("defaults", "secret_code")
        self.chumby_email_address = config.get("defaults", "chumby_email_address")

        self.mail_type = config.get('defaults', 'mail_type').upper()
        if(self.mail_type == "IMAP"):
            try:
                port = config.getint("defaults", "mail_port")
            except:
                port = 143
            self.mailserver = ImapMailEnumerator(
                    config.get("defaults", "mail_server"), port
                    )
        elif(self.mail_type == "POP3" or self.mail_type == "POP"):
            try:
                port = config.getint("defaults", "mail_port")
            except:
                port = 110
            self.mailserver = PopMailEnumerator(
                    config.get("defaults", "mail_server"), port
                    )
        self.mailserver.connect(
                config.get("defaults", "mail_user"),
                config.get("defaults", "mail_password")
                )

        self.process_new_messages()

        self.logger.info("Finished.")

    def read_configuration(self, configfile):
        if(configfile == None):
            configfile = os.path.join(
                    os.path.dirname(__file__),
                    "emailconfig.conf"
                    )
        defaults = {
                'alarm_path': '/psp/alarms',
                'log_path': '/mnt/storage/alarm_log',
                'smtp_server': '',
                'smtp_user': '',
                'smtp_password': '',
                'mail_type': 'IMAP',
                'mail_server': '',
                'mail_user': '',
                'mail_password': '',
                'mail_port': '',
                'secret_code': 'youSh0ulds3tThis',
                'chumby_email_address': 'chumby@yourdomain.com'
                }
        parser = SafeConfigParser(defaults)
        parser.read([configfile])
        return parser

    def is_authentic(self, message):
        msg_text = ""
        if(message.is_multipart()):
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    msg_text = part.get_payload()
        else:
            msg_text = message.get_payload()
        if(msg_text.strip()[0:25].find(self.secret_code.strip()) >= 0):
            return True
        else:
            return False

    def action_help(self, message, email_from):
        message_parts = [
                "Help from your Chumby.",
                "",
                "Instructions",
                "------------",
                "1) Create a new email message addressed to:",
                "\t%s" % self.chumby_email_address,
                "2) Set the subject of the message to match",
                "any one of the below commands.",
                "3) Enter your secret code into the body of the",
                "email message (in case you're confused, your ",
                "secret code is set in the configuration file ",
                "currently saved to your Chumby).",
                "",
                "Available Commands",
                "------------------",
                "\"HELP\":\tSend me this message.",
                "\"OFF\":\tTurn all alarms off.",
                "\"STATUS\":\tSend current alarm status.",
                "\"<ALARM NAME>: OFF\":\tTurn off a single alarm.",
                "\"<ALARM NAME>: ON\":\tTurn on a single alarm.",
                "\"<ALARM NAME>: DETAILS\":\tSend details for this alarm.",
                "\"GET XML\":\tSend me the current alarm XML file.",
                "\"SET XML\":\tSet the current alarm XML to an attached file.",
                ]
        self.send_notification(email_from, 
            "\n".join(message_parts),
            "Help");

    def action_status(self, message, email_from):
        self.send_notification(email_from,
            self.gather_alarm_status_string(),
            "Status")

    def action_alarm_off(self, message, email_from):
        alarm_name = re.match(r"([^:]*): OFF", message["subject"].upper()).groups()[0]
        result = self.alter_alarm_status(
                alarm_name, False
                )
        if(result):
            self.send_notification(email_from,
                self.gather_alarm_status_string(),
                "Alarm '%s' disabled" % alarm_name)
        else:
            self.send_notification(email_from,
                self.gather_alarm_status_string(),
                "Alarm '%s' not found" % alarm_name)

    def action_alarm_on(self, message, email_from):
        alarm_name = re.match(r"([^:]*): ON", message["subject"].upper()).groups()[0]
        result = self.alter_alarm_status(
                alarm_name, True
                )
        if(result):
            self.send_notification(email_from,
                self.gather_alarm_status_string(),
                "Alarm '%s' enabled" % alarm_name)
        else:
            self.send_notification(email_from,
                self.gather_alarm_status_string(),
                "Alarm '%s' not found" % alarm_name)

    def action_global_alarm_off(self, message, email_from):
        self.disable_all_alarms()
        self.send_notification(email_from,
            self.gather_alarm_status_string(),
            "Alarms are off.")

    def action_alarm_details(self, message, email_from):
        alarm_name = re.match(r"([^:]*): DETAILS", message["subject"].upper()).groups()[0]
        self.send_notification(email_from,
            self.gather_alarm_details_string(alarm_name),
            "Alarm '%s' details" % alarm_name
            )

    def action_get_xml(self, message, email_from):
        message_parts = [
                "The alarms XML file is attached.",
                "",
                "To set your Chumby's alarms to a new set of alarms",
                "defined in the same format as the attached XML file, ",
                "send a response with a subject of 'SET XML'.",
                ]
        self.send_notification(email_from,
            "\n".join(message_parts),
            "Alarms XML",
            attachments = [self.alarm_path]
            )

    def action_set_xml(self, message, email_from):
        if(message.is_multipart()):
            for part in message.walk():
                if((part.get_content_type() not in ("text/plain", "text/html", ))
                        and
                    (part.get_content_maintype() not in ("multipart", ))
                    ):
                    temp = tempfile.TemporaryFile()
                    temp.write(part.get_payload(decode = True))
                    temp.seek(0)

                    try:
                        parsed = parse(temp)
                        self.write_and_notify(parsed)
                        self.send_notification(email_from,
                            self.gather_alarm_status_string(),
                            "New Alarms XML Applied"
                            )
                    except Exception, e:
                        self.send_notification(email_from,
                            "An error was encountered while applying your new XML file.\n\n%s" % str(e),
                            "Error"
                            )
                    temp.close()
        else:
            self.send_notification(email_from,
                "Attachment not found.",
                "Attachment Error"
                )

    def process_new_messages(self):
        messages = []

        for message in self.mailserver.get_message():
            subject = message["subject"].upper()
            self.logger.info("Processing message '%s'" % subject)
            email_from = rfc822.parseaddr(message["from"])[1]

            try:
                if(not self.is_authentic(message)):
                    raise EmailAuthenticityException("Either you did not specify a secret code in the body of your email message, or your message is not authentic.");
                if(subject == "HELP"):
                    self.action_help(message, email_from)
                elif(subject == "STATUS"):
                    self.action_status(message, email_from)
                elif(re.match(r"([^:]*):\s*OFF", subject.upper())):
                    self.action_alarm_off(message, email_from)
                elif(re.match(r"([^:]*):\s*ON", subject.upper())):
                    self.action_alarm_on(message, email_from)
                elif(re.match(r"([^:]*):\s*DETAILS", subject.upper())):
                    self.action_alarm_details(message, email_from)
                elif(subject == "OFF"):
                    self.action_global_alarm_off(message, email_from)
                elif(subject == "GET XML"):
                    self.action_get_xml(message, email_from)
                elif(subject == "SET XML"):
                    self.action_set_xml(message, email_from)
                else:
                    self.send_notification(email_from, 
                            "Command unrecognized.  Send 'HELP' for instructions.",
                            "Command Unrecognized")
            except EmailAuthenticityException, e:
                self.logger.exception("Authenticity Check Failed.")
                self.send_notification(email_from,
                        "You either did not specify a secret code in the body of your e-mail message or the secret code you entered did not match.",
                        "Authentication Required")
            except Exception, e:
                self.logger.exception("Unable to process message!")
                self.send_notification(email_from,
                        "An exception was encountered while processing your e-mail message. \n\n%s" % str(e), 
                        "Error")

    def alter_alarm_status(self, name, status):
        document = parse(self.alarm_path)
        found = False
        for element in document.getElementsByTagName("alarm"):
            if(element.getAttribute("name").upper() == name.upper()):
                found = True
                if(status == True):
                    element.setAttribute("enabled", "1")
                else:
                    element.setAttribute("enabled", "0")
        if(found):
            self.write_and_notify(document)
        return found

    def gather_alarm_details_string(self, name):
        document = parse(self.alarm_path)
        message_parts = []
        for element in document.getElementsByTagName("alarm"):
            if(element.getAttribute("name").upper() == name.upper()):
                message_parts = ["Name: %s" % element.getAttribute("name"),]
                message_parts.append("Interval: %s" % element.getAttribute("when"))
                try:
                    if(element.getAttribute("when") in ("daily", "weekday", )):
                        raw_time = int(element.getAttribute("time"))
                        human_time = (
                                datetime.datetime.strptime("00:00", "%H:%M") +
                                datetime.timedelta(minutes = raw_time)
                                    ).strftime("%H:%M")
                        message_parts.append("Time: %s" % human_time)
                except:
                    pass
                message_parts.append("Duration: %s" % element.getAttribute("duration"))
                if(element.getAttribute("backup") == "1"):
                    message_parts.append("Backup Alarm: ON")
                    message_parts.append("Backup Delay: %s minutes" % 
                            element.getAttribute("backupDelay")
                            )
                else:
                    message_parts.append("Backup Alarm: OFF")

        if(len(message_parts) < 1):
            return "No alarm named '%s' was found." % name
        else:
            return "\n".join(message_parts)

    def gather_alarm_status_string(self):
        document = parse(self.alarm_path)
        message_parts = []

        for element in document.getElementsByTagName("alarm"):
            name = element.getAttribute("name")
            enabled = element.getAttribute("enabled")
            if(enabled == "1"):
                message_parts.append("%s: ON" % name)
            else:
                message_parts.append("%s: OFF" % name)
        return "\n".join(message_parts)

    def disable_all_alarms(self):
        document = parse(self.alarm_path)
        
        for element in document.getElementsByTagName("alarm"):
            element.setAttribute("enabled", "0")

        self.write_and_notify(document)

    def write_and_notify(self, document):
        fout = open(self.alarm_path, "w")
        fout.write(document.toxml())
        fout.close()

        self.notify_chumby_of_updates()

    def send_notification(self, to_address, message, subject = None, attachments = []):
        if(subject == None):
            subject = "Chumby Notifier"
        else:
            subject = "Chumby :: %s" % subject
        msg = MIMEMultipart()
        msg["subject"] = subject
        msg["from"] = self.chumby_email_address
        msg["to"] = to_address

        msg_text = MIMEText(message)
        msg.attach(msg_text)

        for attachment in attachments:
            mime_content = MIMEBase("application", "octet-stream")
            att_file = open(attachment)
            mime_content.set_payload(att_file.read())
            att_file.close()
            mime_content.add_header("Content-Disposition", 
                    "attachment", 
                    filename = os.path.basename(attachment))
            msg.attach(mime_content)

        s = smtplib.SMTP(self.smtp_server, 25)
        s.login(self.smtp_user, self.smtp_password)
        s.sendmail(msg["from"], [msg["to"]], msg.as_string())
        s.quit()
        self.logger.info("Sending '%s' to '%s'" % (subject, to_address))

    def notify_chumby_of_updates(self):
        self.logger.debug("Notifying chumby of alarm changes")
        xml = "<event type=\"AlarmPlayer\" value=\"reload\" comment=\"%s\"/>" % self.alarm_path
        note = open("/tmp/flashplayer.event", "w")
        note.write(xml)
        note.close()
        os.system("chumbyflashplayer.x -F1")

    def get_alarmfile_from_server(self, dav_url, username, password, file_path):
        self.logger.info("Getting alarmfile from server.")
        command = "/usr/bin/curl --basic --user %s:%s -o %s  %s" % (
                    username,                       
                    password,                               
                    file_path,                             
                    dav_url,
        	)
       	os.system(command)
        return file_path

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--config", dest="configfile", default=None)
    (options, args, ) = parser.parse_args()
    synchronizer = ChumbyEmailAlarmManager(options, args)
