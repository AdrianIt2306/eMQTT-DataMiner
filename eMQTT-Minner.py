import pyshark
import time
import json
import logging
import os
import mysql.connector
from dotenv import load_dotenv
load_dotenv()
logging.basicConfig(encoding='utf-8', format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
#logging.basicConfig(filename='example.log', encoding='utf-8', format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',datefmt='%Y-%m-%d:%H:%M:%S',level=logging.DEBUG)    

networkInterface = 'lo'
capture = pyshark.LiveCapture(interface=networkInterface,bpf_filter="tcp and port 1883",use_json=True)

logging.info("        __  _______  ____________    __  ___                       ")
logging.info("  ___  /  |/  / __ \/_  __/_  __/   /  |/  (_)___  ____  ___  _____")
logging.info(" / _ \/ /|_/ / / / / / /   / /_____/ /|_/ / / __ \/ __ \/ _ \/ ___/")
logging.info("/  __/ /  / / /_/ / / /   / /_____/ /  / / / / / / / / /  __/ /    ")
logging.info("\___/_/  /_/\___\_\/_/   /_/     /_/  /_/_/_/ /_/_/ /_/\___/_/     ")  
logging.info("                                                                   ")  
logging.info("Listening interface on: %s" % networkInterface)

mydb = mysql.connector.connect(
  host=os.getenv('DATABASE_IP'),
  user=os.getenv('DATABASE_USER'),
  password=os.getenv('DATABASE_PASSWORD'),
  database=os.getenv('DATABASE_NAME')
)
def StorePacketRelationMQTT (arguments_pr):
    #logging.debug(arguments_pr)
    if(arguments_pr[0]=='None'):
        logging.warning("Request does not contain identifier")
    else:
        try:
            mycursor = mydb.cursor()
            mycursor.callproc("mqtt_relation_packet",arguments_pr)
            mydb.commit()
        except mysql.connector.Error as err:        
            logging.error("Something went wrong: {}".format(err))
def StoreWareHousePacketMQTT (arguments_w):
    #logging.debug(arguments_p)
    mycursor = mydb.cursor()
    mycursor.callproc("mqtt_warehouse_packet",arguments_w)
    mydb.commit()
def StoreDataLakeMQTT (raw_message):
    try:
        coded_msg = str(raw_message)
        pre_decoded_msg = coded_msg.replace(':', '')
        decoded_msg = bytes.fromhex(pre_decoded_msg).decode('utf-8')
        msg_json = json.loads(decoded_msg)
        arguments_dl = [decoded_msg,str(msg_json["TokenID"])]    
        logging.debug(arguments_dl)
        mycursor = mydb.cursor()
        mycursor.callproc("mqtt_insert_data_lake",arguments_dl)
        mydb.commit()   
    except:
        logging.error("Cannot be posible to cast token")
def StorePacketMQTT (arguments_p):
    #logging.debug(arguments_p)
    mycursor = mydb.cursor()
    mycursor.callproc("mqtt_packet",arguments_p)
    mydb.commit()
def ControlPacketType (mqtt_flag_hex):
    if mqtt_flag_hex == "0x10":
        mqtt_packet_name = "CONNECT PACKET"

    elif mqtt_flag_hex == "0x20":
        mqtt_packet_name = "CONNECTACK PACKET"

    elif(mqtt_msg_type=="0x30"):
        mqtt_packet_name ="PUBLISH PACKET"

    elif(mqtt_msg_type=="0x31"):
        mqtt_packet_name ="PUBLISH PACKET with OPTS (Retained)"

    elif(mqtt_msg_type=="0x32"):
        mqtt_packet_name ="PUBLISH PACKET with OPTS (QoS)"

    elif(mqtt_msg_type=="0x33"):
        mqtt_packet_name ="PUBLISH PACKET with OPTS (QoS and Retained)"        

    elif(mqtt_msg_type=="0x40"):
        mqtt_packet_name ="PUBACK PACKET"

    elif(mqtt_msg_type=="0x50"):
        mqtt_packet_name ="PUBACK PACKET"        

    elif(mqtt_msg_type=="0x60"):
        mqtt_packet_name = "PUBREL PACKET"

    elif(mqtt_msg_type=="0x62"):
        mqtt_packet_name = "PUBREL PACKET"     

    elif(mqtt_msg_type=="0x6f"):
        mqtt_packet_name = "PUBREL PACKET"              

    elif(mqtt_msg_type=="0x70"):
        mqtt_packet_name = "PUBCOMP PACKET"

    elif(mqtt_msg_type=="0x72"):
        mqtt_packet_name = "PUBCOMP PACKET"

    elif(mqtt_msg_type=="0x75"):
        mqtt_packet_name = "PUBCOMP PACKET"

    elif(mqtt_msg_type=="0x80"):
        mqtt_packet_name ="SUBSCRIBE PACKET"

    elif(mqtt_msg_type=="0x90"):
        mqtt_packet_name ="SUBACK PACKET"

    elif(mqtt_msg_type=="0xa0"):
        mqtt_packet_name ="SUBACK PACKET"  

    elif(mqtt_msg_type=="0xb0"):
        mqtt_packet_name = "UNSUBSCRIBE PACKET"

    elif(mqtt_msg_type=="0xc0"):
        mqtt_packet_name ="UNSUBACK PACKET"
           
    elif(mqtt_msg_type=="0xd0"):
        mqtt_packet_name ="PINGRESP PACKET"

    elif(mqtt_msg_type=="0xe0"):
        mqtt_packet_name ="DISCONNECT PACKET"           

    elif(mqtt_msg_type=="0xf0"):
        mqtt_packet_name = "AUTH PACKET"      

    elif(mqtt_msg_type=="0x82"):
        mqtt_packet_name = "PACKET ERROR"         
    else:
        logging.error("Not message found")
        mqtt_packet_name = "UNKNOWN"
    
    return mqtt_packet_name        

    splitte_hex_var= hex_value.split('x')     
    dec2num= int(splitte_hex_var[1],16)
    array_positions= [int(d) for d in bin(dec2num)[2:].zfill(zero_fill)]
    return array_positions 
sensor_keys = []
port_keys = []

for packet in capture.sniff_continuously():
    try:                                                                          
        mqtt_msg_type = packet.mqtt.hdrflags
        logging.info("("+mqtt_msg_type+") - "+ControlPacketType(mqtt_msg_type) + " from port: " +packet.tcp.srcport)

        if(mqtt_msg_type=='0x10'):
            logging.debug(packet.mqtt)
            hexconflags=str(packet.mqtt.conflags)
            sconflags= hexconflags.split('x')     
            decNum= int(sconflags[1],16)
            conflags= [int(d) for d in bin(decNum)[2:].zfill(8)]
            #logging.debug(conflags)
            if (str(packet.mqtt.clientid) in sensor_keys and str(packet.mqtt.clientid) in port_keys):
                logging.warning("The sensor is in cache")
            else:
                arguments_pr = [str(packet.mqtt.clientid),str(packet.tcp.srcport)]   
                StorePacketRelationMQTT(arguments_pr)  
                sensor_keys.append(str(packet.mqtt.clientid))            
            arguments_w=[str(packet.tcp.flags), "0", str(packet.tcp.len), "0", "0","0", "0", str(conflags[6]), str(conflags[1]),str(conflags[3]),str(conflags[7]),str(conflags[2]),str(conflags[0]),str(conflags[5]),str(packet.mqtt.conflags),"0",str(packet.mqtt.hdrflags),str(packet.mqtt.kalive),str(packet.mqtt.len),"0","0","1",str(packet.mqtt.proto_len),str(packet.mqtt.protoname),"0","0","0","0",str(packet.mqtt.ver),"0","0","0","0",str(packet.mqtt.clientid),str(packet.tcp.srcport),str(packet.tcp.dstport)]
            logging.debug(arguments_w)
            StoreWareHousePacketMQTT(arguments_w)
            
        elif(mqtt_msg_type=='0x20'):
            hexflags=str(packet.mqtt.flags)
            sflags= hexflags.split('x')     
            decNum= int(sflags[1],16)
            flags= [int(d) for d in bin(decNum)[2:].zfill(2)]
            #logging.error(flags)
            arguments_w=[str(packet.tcp.flags), "0", str(packet.tcp.len), str(packet.mqtt.flags), str(flags[0]),str(flags[1]), str(packet.mqtt.val),"0","0","0","0","0","0","0","0","0",str(packet.mqtt.hdrflags),"0",str(packet.mqtt.len),"0","0","2","0","0","0","0","0","0","0","0","0","0","0","",str(packet.tcp.srcport),str(packet.tcp.dstport)]
            StoreWareHousePacketMQTT(arguments_w)
            logging.debug(arguments_w)            

        elif(mqtt_msg_type=='0x30'):
            pubhexflags=str(packet.mqtt.hdrflags)
            splitted_hdrflags= pubhexflags.split('x')    
            decNumPub= int(splitted_hdrflags[1],16)
            pubhdrflags= [int(d) for d in bin(decNumPub)[2:][-4:]]
            if(pubhdrflags[1]==0 and pubhdrflags[2]==0):
                qos_val=0
            elif(pubhdrflags[1]==0 and pubhdrflags[2]==1):
                qos_val=1
            elif(pubhdrflags[1]==1 and pubhdrflags[2]==0):
                qos_val=2
            #logging.debug("QOS is: "+str(qos_val))
            arguments_w=[str(packet.tcp.flags), "0", str(packet.tcp.len), "0", "0","0","0","0","0","0","0","0","0","0","0","0",str(packet.mqtt.hdrflags),"0",str(packet.mqtt.len),str(packet.mqtt.msg),"0","3","0","0",str(qos_val),str(pubhdrflags[3]),"0","0","0","0","0","0","0","",str(packet.tcp.srcport),str(packet.tcp.dstport)]            
            StoreWareHousePacketMQTT(arguments_w)
            StoreDataLakeMQTT(str(packet.mqtt.msg))
            logging.debug(arguments_w)         
            logging.debug(packet.mqtt)

        elif(mqtt_msg_type=='0x31'):
            pubhexflags=str(packet.mqtt.hdrflags)
            splitted_hdrflags= pubhexflags.split('x')   
            #logging.debug(splitted_hdrflags)  
            decNumPub= int(splitted_hdrflags[1],16)
            pubhdrflags= [int(d) for d in bin(decNumPub)[2:][-4:]]
            logging.error(pubhdrflags)
            if(pubhdrflags[1]==0 and pubhdrflags[2]==0):
                qos_val=0
            elif(pubhdrflags[1]==0 and pubhdrflags[2]==1):
                qos_val=1
            elif(pubhdrflags[1]==1 and pubhdrflags[2]==0):
                qos_val=2
            #logging.debug("QOS is: "+str(qos_val))
            arguments_w=[str(packet.tcp.flags), "0", packet.tcp.len, "0", "0","0","0","0","0","0","0","0","0","0","0","0",str(packet.mqtt.hdrflags),"0",str(packet.mqtt.len),str(packet.mqtt.msg),"0","3","0","0",qos_val,pubhdrflags[3],"0","0","0","0","0","0","0","",str(packet.tcp.srcport),str(packet.tcp.dstport)]
            StoreWareHousePacketMQTT(arguments_w)
            logging.debug(arguments_w)         
            #logging.debug(packet.mqtt)

        elif(mqtt_msg_type=='0x32'):
            pubhexflags=str(packet.mqtt.hdrflags)
            splitted_hdrflags= pubhexflags.split('x')   
            #logging.debug(splitted_hdrflags)  
            decNumPub= int(splitted_hdrflags[1],16)
            pubhdrflags= [int(d) for d in bin(decNumPub)[2:][-4:]]
            #logging.error(pubhdrflags)
            if(pubhdrflags[1]==0 and pubhdrflags[2]==0):
                qos_val=0
            elif(pubhdrflags[1]==0 and pubhdrflags[2]==1):
                qos_val=1
            elif(pubhdrflags[1]==1 and pubhdrflags[2]==0):
                qos_val=2
            logging.debug("QOS is: "+str(qos_val))
            arguments_w=[str(packet.tcp.flags), "0", packet.tcp.len, "0", "0","0","0","0","0","0","0","0","0","0","0","0",str(packet.mqtt.hdrflags),"0",str(packet.mqtt.len),str(packet.mqtt.msg),str(packet.mqtt.msgid),"3","0","0",qos_val,pubhdrflags[3],"0","0","0","0","0","0","0","",str(packet.tcp.srcport),str(packet.tcp.dstport)]
            StoreWareHousePacketMQTT(arguments_w)
            logging.debug(arguments_w)         
            #logging.debug(packet.mqtt)

        elif(mqtt_msg_type=='0x33'):
            pubhexflags=str(packet.mqtt.hdrflags)
            splitted_hdrflags= pubhexflags.split('x')   
            #logging.debug(splitted_hdrflags)  
            decNumPub= int(splitted_hdrflags[1],16)
            pubhdrflags= [int(d) for d in bin(decNumPub)[2:][-4:]]
            #logging.error(pubhdrflags)
            if(pubhdrflags[1]==0 and pubhdrflags[2]==0):
                qos_val=0
            elif(pubhdrflags[1]==0 and pubhdrflags[2]==1):
                qos_val=1
            elif(pubhdrflags[1]==1 and pubhdrflags[2]==0):
                qos_val=2
            logging.debug("QOS is: "+str(qos_val))
            arguments_w=[str(packet.tcp.flags), "0", packet.tcp.len, "0","0","0","0","0","0","0","0","0","0","0","0","0",str(packet.mqtt.hdrflags),"0",str(packet.mqtt.len),str(packet.mqtt.msg),"0","3","0","0",qos_val,pubhdrflags[3],"0","0","0","0","0","0","0","",str(packet.tcp.srcport),str(packet.tcp.dstport)]
            StoreWareHousePacketMQTT(arguments_w)
            logging.debug(arguments_w)         
            #logging.debug(packet.mqtt)          

        #elif(mqtt_msg_type=='0x40'):
            
            #logging.debug(packet)

        #elif(mqtt_msg_type=='0x50'):
            
            #logging.debug(packet)            

        #elif(mqtt_msg_type=='0x60'):
            
            #logging.debug(packet)  

        #elif(mqtt_msg_type=='0x70'):
            
            #logging.debug(packet)             

        #elif(mqtt_msg_type=='0x80'):
            
            #logging.debug(packet) 

        #elif(mqtt_msg_type=='0x90'):
            
            #logging.debug(packet)                            

        #elif(mqtt_msg_type=='0xa0'):
            
            #logging.debug(packet)   

        #elif(mqtt_msg_type=='0xb0'):
            
            #logging.debug(packet)   

        elif(mqtt_msg_type=='0xc0'):
            
            logging.debug(packet.mqtt)

           
        #elif(mqtt_msg_type=='0xd0'):
            
            #logging.debug(packet) 

        elif(mqtt_msg_type=='0xe0'):
            logging.debug(packet.mqtt) 

           
        #elif(mqtt_msg_type=='0xf0'):
            
            #logging.debug(packet)

        elif(mqtt_msg_type=='0x82'):
            logging.debug(packet.mqtt)


        
    except AttributeError as e:
        # ignore packets other than TCP, UDP and IPv4
        #print(e)
        pass
    #print (" ")    


