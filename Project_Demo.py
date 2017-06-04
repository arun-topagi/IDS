#!/usr/bin python
'''
----------(  INTRUSION DETECTION SYSTEM FOR MALICIOUS ACCESS POINT(AP) IN WIRELESS NETWORK  )------------
'''

'''
mysql.connector module to connect to mysql database
'''
import mysql.connector
import unicodedata
'''
scapy python module is powerful
interactive packet manipulation program
'''
from scapy.all import *
from scapy.layers.dot11 import Dot11
'''
subprocess module is for execution of shell commands
'''
import subprocess
'''
Time module is for sleep function
'''
from time import sleep

'''
Making connection to mysql database
with database credentials
'''
connection = mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='accesspoint_db')

'''
creating temporary connection object for work
'''
cursor = connection.cursor()
'''
data of authorised AP to safe use
'''
query = ("SELECT * from authorised_ap;")
cursor.execute(query)
'''
parsing cursor result in list format and it contain authorised AP's
'''
rows_auth=[item[0] for item in cursor.fetchall()]
# print rows_auth
query1 = ("SELECT * from dumped_ap;")
cursor.execute(query1)
rows_dumped=[item[0] for item in cursor.fetchall()]


'''
    ap_list is globle list, it store AP
    MAC address which are unique in network
    '''
ap_list = []
def Access_points(pkt):
    '''
    Access_point() function detects AP nearby device and
    make entry of each AP(MAC_address and SSID) in database
    :param pkt:
    :return:
    '''

    '''
        Dot11 is for wireless standard 802.11
        '''
    if pkt.haslayer(Dot11):
        '''
        Beacon packet filter based upon type and subtype
        '''
        if pkt.type == 0 and pkt.subtype == 8:
            '''
            comparing AP MAC address and already stored MAC Address in ap_list
            if any new AP detected then condition will satisfies
            '''
            if pkt.addr2 not in ap_list:
                '''
                any new AP detected then store in ap_list
                '''
                ap_list.append(pkt.addr2)
                '''
                Mantaining database of All AP so dumped_dp containn all AP info in nework
                for future analyse
                '''
                if pkt.addr2 not in rows_dumped :
                    cursor.execute('''insert into dumped_ap (MAC_addr,SSId) values (%s,%s)''', (pkt.addr2, pkt.info))
                    rows_dumped.append(pkt.addr2)
                    connection.commit()
                    # print rows_dumped
                '''
                print MAC address and SSID info of AP
                '''
                # print type(pkt.addr2)
                if pkt.addr2 in rows_auth:
                    print " %s\t%10s\t\tAuthorised" % (pkt.addr2, pkt.info)
                else:
                    print " %s\t%10s\t\tUnauthorised" % (pkt.addr2, pkt.info)
                    #print "Need help, press ctr+c and choose option 2"


def Check_connected_ap():
    '''
    check-connected_ap() function check connected AP is authorised or not
    if its Unauthorised it will disconnected from device automatically
    :return:
    '''
    '''
    this command is to extract connected AP to device
    '''
    cmd = ["nmcli -f BSSID,ACTIVE dev wifi list | awk '$2 ~ /yes/ {print $1}'"]
    # subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    sleep(2)
    address = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = address.communicate()
    convetedOut = out.lower()
    # print convetedOut
    if not convetedOut:
        print "\033[01;31m Wireless Card is not connected\033[1;m"
        print "\033[01;34m Press 1 to Main menu\033[1;m"
        while (input() != 1):
            pass
        return

    else:
        authFlag = False
        for i in range(0, len(rows_auth), 1):

            #     # print rows_auth[i]
            #     # print out.lower()
            #     # print type(out.lower())
            #     # print type(rows_auth[i].lower())
            #     # print type(str(rows_auth[1]))
            #     # print "arun"
            #     # print type(out)
            #     # print rows_auth[1]
            if convetedOut.rstrip() == str(rows_auth[i]):
                # print "in auth"
                # print rows_auth[i]
                # print out.lower()
                authFlag = True
                break
        '''
        check Flag for conclusion
        '''
        if authFlag == True:
            # print convetedOut
            # print rows_auth
            # print type(rows_auth)
            # if convetedOut.rstrip() in rows_auth:
            print "\033[1;36m Connected Access point is Authorised\033[1;m"
            print "\033[01;34m Press 1 to Main menu\033[1;m"
            while (input() != 1):
                pass
        else:
            '''
                checking connected AP is Authorised or not with white listed database
                and set authFlag True if connectected AP is Authorised
            '''
            print "\033[01;31m Connectected Access Point is Unauthorised \033[1;m"
            print "\033[01;32m To disconnect Access point Enter 1 Otherwise 0 \033[1;m"
            disconnect = input()
            if disconnect == 1:
                subprocess.call('service network-manager stop', shell=True)
                print "\033[1;36m Access Point is Disconnected now its SAFE \033[1;m"
                print "\033[01;34m Press 1 to Main menu\033[1;m"
                while (input() != 1):
                    pass
            else:
                print "\033[01;31m ENDANGER\033[1;m"
                print "\033[01;34m Press 1 to Main menu\033[1;m"
                while (input() != 1):
                    pass




if __name__ == "__main__":

    '''
    continuous loop for option choice
    '''
    while 1:
        print '''\033[01;32m



                   #---------------------------------------------------------------------------------------#
                   |                                                                                       |
                   |  #############    ##############       #############                                  |
                   |  #############    ###############     #############                                   |
                   |       ###           ###        ##     ####                                            |
                   |       ###           ###        ###      #####                                         |
                   |       ###           ###        ###        #####        ###     ###     #############  |
         **********|       ###           ###        ###          #####      ###     ###    ############    |**********
      *************|       ###           ###        ###            ####     ###     ###     ######         |*************
         **********|       ###           ###        ##              ####    ###     ###        #####       |**********
                   |  #############    ###############      #############    #########      ##########     |
                   |  #############    ##############      #############      #######    ############      |
                   |                                                             ####                      |
                   |                                                             ###                       |
                   |                                                             ###                       |
                   |                                                            ###                        |
                   |                                                                                       |
                   #---------------------------------------------------------------------------------------#

             \033[1;m'''
    # subprocess.call('service network-manager restart', shell=True)
        print "\033[01;31m Enter choice \033[1;m\n\033[01;34m 1-Check nearby Access Points information\n 2-Check connected Access Point status\033[1;m"
        choice = input()
        if choice == 1:
            ap_list[:] = []
            print "\033[01;32m Waiting for network-manager restart \033[1;m"
            subprocess.call('service network-manager restart', shell=True)
            print "\033[01;31m MAC address\t\t    SSID\t\tType \033[1;m"
            for i in range(0, 3, 1):
                sleep(1)
            '''
            this is scapy function fro monitoring wireless card by monX(airmon-ng tool given interface)
            sniff each packet and send it to Access_points() function
            '''
            sniff(iface="mon0", prn=Access_points)
        elif choice == 2:
            Check_connected_ap()
        else:
            print " WRONG SELECTION"