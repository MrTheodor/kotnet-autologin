#!/usr/bin/python
#
# Simple autologin program for network on Katholike Universitet Leuven
# Author: Jakub Krajniak <jkrajniak at gmail dot com>
# Licence: GPLv2
#

import argparse
import mechanize
import os
import re
import time
import syslog
import random


class AutoLogin:
    """Class for login into the KU KotNet."""
    br = mechanize.Browser()
    loggedIn = False

    def __init__(self, login, password, logfile=None):
        self.username = login
        self.password = password
        self.downloadLimit = 0
        self.uploadLimit = 0

    def login(self):
        self.br = mechanize.Browser()
        self.br.open('http://netlogin.kuleuven.be')
        self.br.select_form(nr=1)
        self.br.submit()
        self.br.select_form(nr=1)
        self.br['uid'] = self.username
        self.br.form.set_value(self.password, type='password')
        ret = self.br.submit()
        lines = ret.readlines()
        weblogin = [ l for l in lines if 'rc=100' in l]
        if len(weblogin) != 0:
            self.loggedIn = True
            print 'logged in', len(weblogin)
            self._getTransfer(lines)
            syslog.syslog(syslog.LOG_INFO, 'Logged with user %s, dl: %s, ul: %s' % (self.username, self.downloadLimit, self.uploadLimit))
        else:
            print 'max loggin excessed'
            self.loggedIn = False

    def _get_transfer(self, lines):
        avaDownload = [ re.findall('.* = (\d+) of (\d+).*', l) for l in lines if re.match ('.*weblogin.*available.*', l) ]
        self.downloadLimit = int(avaDownload[0][0][0]) / 1024 / 1024
        self.uploadLimit = int(avaDownload[1][0][0]) / 1024 / 1024


def main():
    config_files = [
        os.path.join(os.environ.get('HOME', ''), '.autologin.conf'),
        '/etc/autologin.conf'
        ]
    config_file = [x for x in config_files if os.path.exists(x)]
    userlogins = []
    if config_file:
        with open(config_file[0]) as conf_f:
            for conf_l in conf_f:
                userlogins.append(conf_l.split())
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('login', help='Login')
        parser.add_argument('password', help='password')

        args = parser.parse_args()
        user, password = args.login, args.password
        userlogins = [(user, password)]

    random.shuffle(userlogins)
    for user, password in userlogins:
        print 'Login with user', user
        c = Login(user, password)
        c.login()
        if c.downloadLimit > 1024 and c.uploadLimit > 1024:
            syslog.syslog(syslog.LOG_NOTICE, '%s;keep %s' % (time.strftime('%Y-%m-%d %H:%M:%S'), user))
            break

if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        syslog.syslog(syslog.LOG_ERR, str(ex))
