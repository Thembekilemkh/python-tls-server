#!/usr/bin/python3

import socketserver, ssl, os, pickle, time, logging, json, threading, datetime
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
from logging.handlers import SocketHandler

cwd = '/opt/api/tls/organization'
certfile = f"{cwd}/certs/server.pem"
keyfile = f"{cwd}/certs/server.key"
ip = "localhost"
port = 5514

class TextSocketHandler(logging.handlers.SocketHandler):
    def makePickle(self, record):
        # Convert the log record to a text string instead of a binary representation
        return record.getMessage().encode() + b'\n'


class MySSL_TCPServer(TCPServer):
    def __init__(self, server_address, RequestHandlerClass,
                 certfile, keyfile, ssl_version=ssl.PROTOCOL_TLSv1_2,
                 bind_and_activate=True):
        TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
       
        print("Server now running on port 5514..")
    def get_request(self):
        try: 
            newsocket, fromaddr = self.socket.accept()
            connstream = ssl.wrap_socket(newsocket, server_side=True, certfile=self.certfile,
                                     keyfile=self.keyfile, ssl_version=self.ssl_version)
            return connstream, fromaddr
        except Exception as e:
            print(f"Failed to decrypt events... {e}")
            return False, False

# Inititae a TLS TCP server
class MySSL_ThreadingTCPServer(ThreadingMixIn, MySSL_TCPServer):
    pass

# Handle events that come in through the socket
class SyslogHandler(StreamRequestHandler):
    remote_server = "localhost"
    remote_port = 5514
    def handle(self):
        data = self.connection.recv(4096)
        print(data)
        data = bytes.decode(data)

        # Format event and get them ready to be sent to the remote server
        events = []
        data = data.split('\n')
        for i in range(len(data)):
            evnt = data[i]
            if evnt == "\n":
                pass
            else:
                if data[i] != "":
                   #data[i] = evnt+"\n"
                   events.append(data[i])

        # Send events to remote server
        self.send_syslog2(events=events)

    def forward_events(self, **kwargs):
        # Get required data
        events = kwargs["events"]


        for i in range(len(events)):
            # Create the socket handler 
            handler = TextSocketHandler(syslog_ip , syslog_port)
            syslog_logger = logging.getLogger()
            syslog_logger.addHandler(handler)
            syslog_logger.setLevel(logging.INFO)


            # send events and close socket
            syslog_logger.info(events[i])
            handler.close()
            syslog_logger.removeHandler()


    def pickle_events(self, **kwargs):
        # Get required variables
        cwd = os.getcwd()
        event = kwargs['event']
        
        # Get the data that is already archived
        with open(f"{cwd}/logs.pickle", "rb") as pickle_in:
            archive_jsonData = pickle.load(pickle_in)
            
        # Append the data to the list the was recieved from the pickle file
        archive_jsonData.append(event)

        # Load the new list on events to the pickle file
        with open(f"{cwd}/logs.pickle", 'wb') as pickle_out:
            pickle.dump(archive_jsonData, pickle_out)

    def convert_to_json(self, **kwargs):

        event = kwargs['event']

        packet_len = len(event)
        last_ind = packet_len-1
        
        # Get header 
        msg_body = {}
        header = ""
        start_header = False
        got_header = False
        prev = ''
        pipes = 0
        body = ""
        key = ""
        got_key = False
        value = ""
        values = ""
        got_value = False
        for l in range(len(event)):
            current = f"{event[l]}" 

            if start_header == False:
                # Check start header
                next_ = f"{event[l+1]}"
                if ((prev == "-" ) and (current == " ") and (next_ == "-")):
                    start_header = True
                else:
                    header = f"{header}{current}"
            else:
                if got_header == False:
                    if current == "|":
                        pipes = pipes+1
                        if pipes == 7:
                            got_header = True 
                            header = f"{header}{current}"
                        else:
                            header = f"{header}{current}"
                    else:
                        header = f"{header}{current}"
                # If we come down here we have already gotten our header and can move on.
                else:
                    
                    if got_key == False:
                        if current == "=":
                            if len(list(msg_body.keys())) == 0:
                                key = body#[0:-1]
                                msg_body[key] = ""
                                got_key = True
                                body = ""
                            else:
                                temp = body.index(" ")
                                cur_ind = body.index(current)
                                key = body[temp:cur_ind]
                                msg_body[key] = ""
                                got_key = True
                                body = ""
                        else:
                            body = body + current

                    elif got_value == False:
                        if l == last_ind:
                            values = values + body+current
                            msg_body[key] = values

                            body = ""
                            values = ""

                        elif current == "=":
                            msg_body[key] = values

                            # This is the new key now leading us into the next value
                            key = body
                            msg_body[key] = ""
                            body = ""
                            values = ""

                        else:
                            if current == " ":
                                values = values + body+current
                                body = ""
                            else:
                                body = body + current
                        
            prev = event[l]


        return header, msg_body

    def convert_date(self, **kwargs):
        old_date = kwargs['date_time']
        new_date = datetime.datetime.strptime(old_date, '%b %d %Y %H:%M:%S ')
        formatted_date = new_date.strftime("%Y-%m-%d %H:%M:%S")#("%d-%b-%Y %H:%M:%S")
        print(f'{formatted_date}') 
        return str(formatted_date)

    def send_syslog2(self, **kwargs):
        # Gather required data
        events = kwargs['events']

        # Gather syslog configs
        SYSLOG_SERVER = self.remote_server
        SYSLOG_PORT = self.remote_port
        LOG_LEVEL = logging.INFO
        formatter = logging.Formatter('%(asctime)s organizationapi01 %(message)s', datefmt='%b %d %Y %H:%M:%S')
        sent_events = False

        #Setup syslog logger
        syslog_logger = logging.getLogger()
        syslog_logger.setLevel(LOG_LEVEL)
        
        #Setup syslog handler
        try:
            syslog_handler = TextSocketHandler(SYSLOG_SERVER, SYSLOG_PORT)
        except ConnectionRefusedError:
            print(str(datetime.datetime.now().isoformat()).split('.')[0] + " ERROR - Could not setup syslog socket, connection refused. Ensure you have the correct syslog server configs and/or the syslog server port is listening")

        #Add formatter to syslog handler
        syslog_handler.setFormatter(formatter)

        #Add handler to syslog logger
        syslog_logger.addHandler(syslog_handler)
        	
        # Loop through our subscriptions
        for evnt in events:
            #Dump JSON object
            data = json.dumps(evnt)
            
            #Send the event to the receiver
            syslog_logger.info(f"{data}")
            sent_events = True

        #Close and remove the syslog handler to avoid stale TCP sockets
        syslog_handler.close()
        syslog_logger.removeHandler(syslog_handler)

        return sent_events


# Initiate a TCP server and attach the handler for the events and the certs the that are meant to be used to decrypth in coming events 
MySSL_ThreadingTCPServer((ip,port), SyslogHandler, certfile, keyfile).serve_forever()

