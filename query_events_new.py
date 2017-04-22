#!/usr/bin/env python2
# encoding=utf-8

import MySQLdb
import time
import sys
import os
import socket
import struct
import csv
import zipfile
import binascii
import datetime
import traceback
import MySQLdb.cursors
import pandas as pd
import netaddr
from calendar import monthrange
from sqlalchemy import create_engine

reload(sys)
sys.setdefaultencoding('utf-8')

csv.register_dialect(
    'mydialect',
    delimiter = ';',
    quotechar = '"',
    doublequote = True,
    skipinitialspace = True,
    lineterminator = '\r\n',
    quoting = csv.QUOTE_MINIMAL)

CHUNK_SIZE = 200000
BUFFER_SIZE = 500

COLS = [
    'DATE',
    'SIGNATURE',
    'SOURCEIP',
    'SOURCEIPFQDN',
    'DESTIP',
    'DESTIPFQDN',
    'SOURCEPORT',
    'DESTPORT',
    'PRIORITY',
    'RELIABILITY',
    'RISK',
    'DATASOURCEID',
    'DATASOURCENAME',
    'USERNAME',
    'PASSWORD',
    'USERDATA1',
    'USERDATA2',
    'USERDATA3',
    'USERDATA4',
    'USERDATA5',
    'USERDATA6',
    'USERDATA7',
    'USERDATA8',
    'USERDATA9'
]

def get_previous_month():
        today = datetime.date.today()
        first = today.replace(day=1)
        lastMonth = first - datetime.timedelta(days=1)
        num_days = monthrange(lastMonth.year, lastMonth.month)
        return lastMonth.year, lastMonth.month, num_days[1]

def extract_ip(hex):
    #print hex 
    addr_long = int(hex,16)
    #return socket.inet_ntoa(struct.pack(">L", addr_long))
    return str(netaddr.IPAddress(addr_long))

def printProgress (iteration, total, prefix = '', suffix = '', decimals = 2, barLength = 100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : number of decimals in percent complete (Int)
        barLength   - Optional  : character length of bar (Int)
    """
    filledLength    = int(round(barLength * iteration / float(total)))
    percents        = round(100.00 * (iteration / float(total)), decimals)
    bar             = '=' * filledLength + '-' * (barLength - filledLength)
    sys.stdout.write('\r%s [%s] %s%s %s' % (prefix, bar, percents, '%', suffix)),
    sys.stdout.flush()
    if iteration == total:
        #sys.stdout.write('\n')
        sys.stdout.flush()


def query(user, pwd, dbname):
    year, month, num_days = get_previous_month()
    filename = "../tmp/siem_%s_%s.db"%(year, month)
    disk_engine = create_engine('sqlite:///%s'%(filename))
#    disk_engine.raw_connection().connection.text_factory = str
#    year = 2016
#    month = 6
#    num_days = 30
    first_date = 1
    today = datetime.datetime(year,month,first_date) -  datetime.timedelta(hours=7)
    next_day = today +  datetime.timedelta(days=num_days)
    sql = "select count(*) from alienvault_siem.acid_event where "\
        "timestamp >= '%s-%02d-%02d %02d:00:00' AND "\
        "timestamp < '%s-%02d-%02d %02d:00:00'" %(today.year, today.month, today.day, today.hour, next_day.year, next_day.month, next_day.day, next_day.hour)
    print sql
    #sys.exit(1)
    sys.stdout.write("Calculating total data...")
    sys.stdout.flush()
    db = MySQLdb.connect("127.0.0.1", user, pwd, dbname, cursorclass = MySQLdb.cursors.SSCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    results = cursor.fetchone()
    cursor.close()
    db.close()
    size = results[0]
    print "%s rows found" %size
    print "Querying data: %s %s" %(month, year)
    #filename = "%s/Export-SIEM-%s-%02d.csv" %(path, year, month)
    found = False
    total_rows = 0
    START1 = datetime.datetime.now()
    #thedatawriter = csv.writer(mycsvfile, dialect='mydialect')
    #thedatawriter.writerow(COLS)
    for date in range(1, (num_days+1)):
        db = MySQLdb.connect("127.0.0.1", user, pwd, dbname, cursorclass = MySQLdb.cursors.SSCursor)
        today = datetime.datetime(year,month,date) -  datetime.timedelta(hours=7)
        next_day = today +  datetime.timedelta(days=1)
        #if date == num_days:
        #    next_day += datetime.timedelta(hours=7)
        sys.stdout.write('Calculating data %02d/%02d/%s... ' % (date, month, year))
        sys.stdout.flush()
        sql = "select count(*) from alienvault_siem.acid_event where "\
           "timestamp >= '%s-%02d-%02d %02d:00:00' AND "\
           "timestamp < '%s-%02d-%02d %02d:00:00'" %(today.year, today.month, today.day, today.hour, next_day.year, next_day.month, next_day.day, next_day.hour)
        cursor = db.cursor()
        cursor.execute(sql)
        results = cursor.fetchone()
        cursor.close()
        size = results[0]
        print "%s rows found" %size
        if size == 0:
            continue
        start = 0
        #CHUNK_SIZE = size
        length = CHUNK_SIZE
        if size < CHUNK_SIZE:
            length = size
        counter = 1;
        while start < size:
            sys.stdout.write('\tCollecting data batch #%s with size %s rows... ' % (counter, length))
            sys.stdout.flush()
            #"DATE_FORMAT(CONVERT_TZ(A.timestamp,'+00:00','+07:00'), '%Y-%m-%d %h:%i:%s') as date, "\
            sql = ""\
                "select "\
                "DATE_FORMAT(CONVERT_TZ(A.timestamp,'+00:00','+07:00'), '%Y-%m-%d %H:%i:%s') as date, "\
                "C.name as signature, "\
                "A.ip_src as src_ip, "\
                "A.src_hostname as src_fqdn, "\
                "A.ip_dst as dst_ip, "\
                "A.dst_hostname as dst_fqdn, "\
                "A.layer4_sport as sport, "\
                "A.layer4_dport as dport, "\
                "A.ossim_priority as priority, "\
                "A.ossim_reliability as reliability, "\
                "GREATEST(A.ossim_risk_a,A.ossim_risk_c) as risk, "\
                "C.plugin_id as data_source_id, "\
                "D.name as data_source_name, "\
                "B.username as username, "\
                "B.password as password, "\
                "B.userdata1 as userdata1, "\
                "B.userdata2 as userdata2, "\
                "B.userdata3 as userdata3, "\
                "B.userdata4 as userdata4, "\
                "B.userdata5 as userdata5, "\
                "B.userdata6 as userdata6, "\
                "B.userdata7 as userdata7, "\
                "B.userdata8 as userdata8, "\
                "B.userdata9 as userdata9 "\
            "from "\
                "alienvault_siem.acid_event A "\
            "join "\
                "alienvault_siem.extra_data B "\
                "on A.id=B.event_id "\
            "join "\
                "alienvault.plugin_sid C "\
                "on (A.plugin_sid=C.sid and A.plugin_id=C.plugin_id) "\
           "join "\
                "alienvault.plugin D "\
                "on (C.plugin_id=D.id) "
            sql += "WHERE "\
                "timestamp >= '%s-%02d-%02d %02d:00:00' AND "\
                "timestamp < '%s-%02d-%02d %02d:00:00'" %(today.year, today.month, today.day, today.hour, next_day.year, next_day.month, next_day.day, next_day.hour)
            sql += "ORDER BY "\
                "timestamp ASC "\
            "LIMIT "+'%s' %start+","+'%s' %length
            #print "LIMIT "+'%s' %start+","+'%s' %length
            #print sql
            #continue
            #sys.exit(1)
            DEBUG = []
            try:
                db = MySQLdb.connect("127.0.0.1", user, pwd, dbname, cursorclass = MySQLdb.cursors.SSCursor)
                START2 = datetime.datetime.now()
                cursor = db.cursor()
                cursor.execute(sql)
                results = cursor.fetchall()
                END2 = datetime.datetime.now()
                DIFF2 = END2 - START2
                len_r = len(results)
                #print len_r
                print "%s rows in %s seconds" %(len_r, DIFF2.seconds)
                datas = []
                i = 0
                found = True
                printProgress(i, len_r, prefix = '\tExporting:', suffix = 'Complete', barLength = 100)
                START3 = datetime.datetime.now()
                for row in results:
                    tmp = list(row)
                    tmp[0] = pd.to_datetime(row[0])
                    tmp[2] = extract_ip(binascii.b2a_hex(row[2]))
                    tmp[4] = extract_ip(binascii.b2a_hex(row[4]))
                    temp = []
                    for s in tmp:
                        if isinstance(s, str):
                            temp.append(s.encode('ascii', 'xmlcharrefreplace'))
                        else:
                            temp.append(s)
                    DEBUG = temp
                    datas.append(temp)
                    #print tmp
                    if i%BUFFER_SIZE == 0:
                    #    thedatawriter.writerows(datas)
                        df = pd.DataFrame(datas)
                        df.columns = COLS
                        df.to_sql('data', disk_engine, if_exists='append', index=False, flavor='sqlite')
                        datas = []
                        printProgress(i, len_r, prefix = '\tExporting:', suffix = 'Complete', barLength = 100)
                    i += 1
                if datas:
                    #thedatawriter.writerows(datas)
                    #print datas[0:3]
                    #sys.exit(1)
                    df = pd.DataFrame(datas)
                    df.columns = COLS
                    df.to_sql('data', disk_engine, if_exists='append', index=False, flavor='sqlite')
                printProgress(i, len_r, prefix = '\tExporting:', suffix = 'Complete', barLength = 100)
                #total_rows += i
                #print 'total this: %s' %i
                END3 = datetime.datetime.now()
                DIFF3 = END3 - START3
                D3 = DIFF3.seconds + (DIFF3.microseconds/1e+6)
                #if D3 == 0:
                #    D3 = DIFF3.microseconds/1e+6
                print " in %0.2f seconds (%d r/s)" %(D3, int(len_r/D3))
                cursor.close();
                total_rows += len_r
            except Exception, e:
                #cursor.close()
                print "Error: unable to fecth data: %s" %(str(e))
                print "Trying to reconnecting..."
                time.sleep(10)
                #traceback.print_exc()
                #print DEBUG
                #sys.exit(1)
                continue
		
            counter +=1
            start += CHUNK_SIZE
            db.close()
            if (size - start) < CHUNK_SIZE:
                length = size - start
#        cursor.close()

#        db.close()
    print "\n"
    if found:
        print "Export Complete: %s rows has been saved to %s" %(total_rows, filename)
        print "Trying to buold index on %s" %filename
        connection = disk_engine.connect()
        connection.execute("create index index_name on data (datasourceid, datasourcename, username)")
       
#        print "Compacting file to %s.zip..." %filename
#        try:
#            zf = zipfile.ZipFile("%s.zip" % (filename), "w", zipfile.ZIP_DEFLATED, allowZip64=True)
#            zf.write(filename)
#        except Exception, e:
#            cursor.close()
#            print "Error: unable to compact: %s" %(str(e))
#            traceback.print_exc()
#        finally:
#            zf.close()
#            os.remove(filename)
    else:
        print "Export Complete: No Data Found"
#        os.remove(filename)
    END1 = datetime.datetime.now()
    DIFF1 = END1 - START1
    print "Time running: %s seconds" %DIFF1.seconds

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print "Usage: %s <user> <password> <database>"  %sys.argv[0]
        sys.exit(1)
    query(sys.argv[1], sys.argv[2], sys.argv[3])

